"""PolicyEnforcer + the engine protocol seam.

The enforcer depends only on the
:class:`~hexgate.security.decision.PolicyEngine` protocol, so a hand-rolled
fake engine is enough to pin its behavior: forward role/tool/args, lift the
returned :class:`Verdict` into a :class:`Decision` with host context.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from hexgate.security import (
    AgentPolicy,
    DecisionOutcome,
    Verdict,
    evaluate_tool_call,
)
from hexgate.security.decision import Decision
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import PolicySet


class _RecordingEngine:
    """Minimal PolicyEngine: records the call, returns a canned verdict."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        self.calls: list[dict[str, Any]] = []

    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict:
        self.calls.append(
            {
                "role": role,
                "tool": tool,
                "args": dict(args),
                "attributes": dict(attributes) if attributes is not None else None,
            }
        )
        return self.verdict


def test_enforcer_forwards_role_tool_and_args_to_engine() -> None:
    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.ALLOW))
    enforcer = PolicyEnforcer(engine, agent_name="support")

    decision = enforcer.decide("read_file", {"file_path": "docs/a.md"})

    assert engine.calls == [
        {
            "role": None,
            "tool": "read_file",
            "args": {"file_path": "docs/a.md"},
            "attributes": None,  # no active context → no attributes bag
        }
    ]
    assert decision.allowed
    assert decision.agent_name == "support"


def test_enforcer_forwards_context_attributes_to_engine() -> None:
    """An active HexgateContext's attributes reach the engine's evaluate()."""
    from hexgate.runtime.context import HexgateContext

    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.ALLOW))
    enforcer = PolicyEnforcer(engine, agent_name="support")

    with HexgateContext(
        user_id="u",
        user_roles=["billing"],
        attributes={"department": "finance", "clearance_level": 3},
    ).sync_scope():
        enforcer.decide("refund", {"amount": 10})

    assert engine.calls == [
        {
            "role": "billing",  # primary_role
            "tool": "refund",
            "args": {"amount": 10},
            "attributes": {"department": "finance", "clearance_level": 3},
        }
    ]


def test_enforcer_lifts_deny_verdict_with_structured_detail() -> None:
    engine = _RecordingEngine(
        Verdict(
            outcome=DecisionOutcome.DENY,
            reason="nope",
            hint={"allowed_paths": ["docs/**"]},
        )
    )
    decision = PolicyEnforcer(engine, agent_name="support").decide("read_file", {})

    assert decision.outcome is DecisionOutcome.DENY
    assert decision.error_type == "policy_denied"
    assert decision.reason == "nope"
    assert decision.hint == {"allowed_paths": ["docs/**"]}
    assert decision.tool_name == "read_file"


def test_enforcer_carries_wasm_violations_through_to_decision() -> None:
    """The structured violations list survives the verdict → decision lift."""
    engine = _RecordingEngine(
        Verdict(
            outcome=DecisionOutcome.DENY,
            reason="denied",
            violations=("args.amount <= 100", "args.currency == 'USD'"),
        )
    )
    decision = PolicyEnforcer(engine, agent_name="billing").decide("refund", {})

    assert decision.violations == ("args.amount <= 100", "args.currency == 'USD'")
    assert decision.as_error_payload()["violations"] == [
        "args.amount <= 100",
        "args.currency == 'USD'",
    ]


def test_from_verdict_maps_outcome_to_error_type() -> None:
    base = {"agent_name": "a", "tool_name": "t"}
    assert (
        Decision.from_verdict(Verdict(outcome=DecisionOutcome.ALLOW), **base).error_type
        is None
    )
    assert (
        Decision.from_verdict(Verdict(outcome=DecisionOutcome.DENY), **base).error_type
        == "policy_denied"
    )
    assert (
        Decision.from_verdict(
            Verdict(outcome=DecisionOutcome.NEEDS_APPROVAL), **base
        ).error_type
        == "approval_required"
    )


def test_policy_set_evaluate_matches_evaluate_tool_call() -> None:
    """PolicySet.evaluate is just role resolution + the pydantic engine."""
    policy = AgentPolicy.model_validate(
        {"default_policy": {"mode": "deny"}, "tools": {"web_search": {"mode": "allow"}}}
    )
    policy_set = PolicySet({"default": policy})

    assert policy_set.evaluate(
        role=None, tool="web_search", args={}
    ) == evaluate_tool_call(policy, "web_search", {})
    assert policy_set.evaluate(
        role="anything", tool="fetch", args={}
    ) == evaluate_tool_call(policy, "fetch", {})


def test_enforcer_attributes_gate_real_pydantic_engine() -> None:
    """End-to-end: a ctx.* constraint decides off the context's attributes."""
    from hexgate.runtime.context import HexgateContext

    policy = AgentPolicy.model_validate(
        {
            "default_policy": {"mode": "deny"},
            "tools": {
                "refund": {
                    "mode": "allow",
                    "constraints": ['ctx.department == "finance"'],
                }
            },
        }
    )
    enforcer = PolicyEnforcer(PolicySet({"default": policy}), agent_name="a")

    with HexgateContext(user_id="u", attributes={"department": "finance"}).sync_scope():
        assert enforcer.decide("refund", {}).allowed

    with HexgateContext(user_id="u", attributes={"department": "sales"}).sync_scope():
        assert not enforcer.decide("refund", {}).allowed

    # No active context → ctx.* ref misses → fail closed.
    assert not enforcer.decide("refund", {}).allowed


# ---------------------------------------------------------------------------
# build_enforcer — the composition root
# ---------------------------------------------------------------------------


def test_build_enforcer_pairs_engine_with_agent_name_and_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """build_enforcer wires the engine, agent name, and an audit sender
    resolved from the api_key into one PolicyEnforcer."""
    from hexgate.security.enforcer import build_enforcer
    from hexgate.security.policy_set import DEFAULT_ROLE_NAME

    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    engine = PolicySet({DEFAULT_ROLE_NAME: AgentPolicy()})
    enforcer = build_enforcer(engine, agent_name="support-bot")

    assert enforcer.policy is engine
    assert enforcer.agent_name == "support-bot"
    # No api_key + no HEXGATE_API_KEY → audit inert (configure returns None).
    assert enforcer._audit_sender is None
