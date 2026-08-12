"""PolicyEnforcer + the engine protocol seam.

The enforcer depends only on the
:class:`~hexgate.security.decision.PolicyEngine` protocol, so a hand-rolled
fake engine is enough to pin its behavior: forward role/tool/args once per
role in the caller's set, fold the verdicts, and lift the winner into a
:class:`Decision` with host context.

``_RecordingEngine.calls`` is a *list* on purpose — with multi-role callers the
number and order of engine invocations is part of the contract (role-set
resolution, dedup, the cap, and the short-circuit are all observable there).
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
from hexgate.security.enforcer import MAX_EVALUATED_ROLES, PolicyEnforcer
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
        decision = enforcer.decide("refund", {"amount": 10})

    assert engine.calls == [
        {
            "role": "billing",
            "tool": "refund",
            "args": {"amount": 10},
            "attributes": {"department": "finance", "clearance_level": 3},
        }
    ]
    # The bag is also stamped onto the Decision for in-process observers.
    assert decision.attributes == {"department": "finance", "clearance_level": 3}


# ---------------------------------------------------------------------------
# Multi-role: role-set resolution + the permissive union
# ---------------------------------------------------------------------------


def _allows_only(tool: str) -> AgentPolicy:
    """A deny-by-default policy that permits exactly one tool."""
    return AgentPolicy.model_validate(
        {"default_policy": {"mode": "deny"}, "tools": {tool: {"mode": "allow"}}}
    )


def test_enforcer_evaluates_every_role_in_caller_order() -> None:
    """All roles are asked, in the caller's order, when none of them allows."""
    from hexgate.runtime.context import HexgateContext

    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.DENY, reason="no"))
    enforcer = PolicyEnforcer(engine, agent_name="a")

    with HexgateContext(user_id="u", user_roles=["billing", "support"]).sync_scope():
        decision = enforcer.decide("refund", {})

    assert [call["role"] for call in engine.calls] == ["billing", "support"]
    assert decision.user_roles == ("billing", "support")
    assert decision.deciding_role is None
    assert decision.outcome is DecisionOutcome.DENY


def test_enforcer_stops_at_the_first_allowing_role() -> None:
    """The union short-circuits, so a later role is never even asked."""
    from hexgate.runtime.context import HexgateContext

    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.ALLOW))
    enforcer = PolicyEnforcer(engine, agent_name="a")

    with HexgateContext(user_id="u", user_roles=["billing", "support"]).sync_scope():
        decision = enforcer.decide("refund", {})

    assert [call["role"] for call in engine.calls] == ["billing"]
    assert decision.deciding_role == "billing"
    # The full set is still recorded — the audit trail must show who was calling,
    # not just who granted it.
    assert decision.user_roles == ("billing", "support")


def test_enforcer_grants_access_when_only_a_later_role_allows() -> None:
    """The point of the feature, end to end on the real pydantic engine."""
    from hexgate.runtime.context import HexgateContext

    policy_set = PolicySet(
        {
            "default": AgentPolicy.model_validate({"default_policy": {"mode": "deny"}}),
            "support": AgentPolicy.model_validate({"default_policy": {"mode": "deny"}}),
            "billing": _allows_only("refund"),
        }
    )
    enforcer = PolicyEnforcer(policy_set, agent_name="a")

    with HexgateContext(user_id="u", user_roles=["support"]).sync_scope():
        assert not enforcer.decide("refund", {}).allowed

    with HexgateContext(user_id="u", user_roles=["support", "billing"]).sync_scope():
        decision = enforcer.decide("refund", {})

    assert decision.allowed
    assert decision.deciding_role == "billing"


def test_enforcer_binds_the_role_fact_per_role() -> None:
    """A ``role ==`` constraint sees the role being evaluated, not the whole set.

    Without per-role binding a constraint like ``role == "billing"`` could never
    pass for a multi-role caller.
    """
    from hexgate.runtime.context import HexgateContext

    policy_set = PolicySet(
        {
            "default": AgentPolicy.model_validate({"default_policy": {"mode": "deny"}}),
            "support": AgentPolicy.model_validate({"default_policy": {"mode": "deny"}}),
            "billing": AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {
                        "refund": {
                            "mode": "allow",
                            "constraints": ['role == "billing"'],
                        }
                    },
                }
            ),
        }
    )
    enforcer = PolicyEnforcer(policy_set, agent_name="a")

    with HexgateContext(user_id="u", user_roles=["support", "billing"]).sync_scope():
        assert enforcer.decide("refund", {}).allowed

    with HexgateContext(user_id="u", user_roles=["support"]).sync_scope():
        assert not enforcer.decide("refund", {}).allowed


def test_enforcer_evaluates_no_roles_as_the_default_policy() -> None:
    """Empty ``user_roles`` and no context both evaluate once with role=None."""
    from hexgate.runtime.context import HexgateContext

    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.ALLOW))
    enforcer = PolicyEnforcer(engine, agent_name="a")

    with HexgateContext(user_id="u", user_roles=[]).sync_scope():
        decision = enforcer.decide("refund", {})

    assert [call["role"] for call in engine.calls] == [None]
    assert decision.user_roles == ()
    assert decision.role is None  # legacy single-role view


def test_enforcer_dedups_repeated_role_names() -> None:
    from hexgate.runtime.context import HexgateContext

    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.DENY, reason="no"))
    enforcer = PolicyEnforcer(engine, agent_name="a")

    with HexgateContext(
        user_id="u", user_roles=["billing", "support", "billing"]
    ).sync_scope():
        decision = enforcer.decide("refund", {})

    assert [call["role"] for call in engine.calls] == ["billing", "support"]
    assert decision.user_roles == ("billing", "support")


def test_enforcer_caps_the_number_of_roles_evaluated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A caller-supplied list can't force unbounded engine invocations.

    Dropping the tail only narrows a permissive union, so the cap is
    fail-closed — but it is logged, not silent.
    """
    import logging

    from hexgate.runtime.context import HexgateContext
    from hexgate.security import enforcer as enforcer_module

    monkey_roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES + 5)]
    engine = _RecordingEngine(Verdict(outcome=DecisionOutcome.DENY, reason="no"))
    enforcer = PolicyEnforcer(engine, agent_name="a")

    enforcer_module._warned_role_cap = False
    with caplog.at_level(logging.WARNING, logger="hexgate.security.enforcer"):
        with HexgateContext(user_id="u", user_roles=monkey_roles).sync_scope():
            decision = enforcer.decide("refund", {})

    assert len(engine.calls) == MAX_EVALUATED_ROLES
    assert len(decision.user_roles) == MAX_EVALUATED_ROLES
    assert decision.user_roles[0] == "role_0"
    assert "MAX_EVALUATED_ROLES" in caplog.text


def test_enforcer_warns_once_per_process_about_the_role_cap(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    from hexgate.runtime.context import HexgateContext
    from hexgate.security import enforcer as enforcer_module

    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES + 1)]
    enforcer = PolicyEnforcer(
        _RecordingEngine(Verdict(outcome=DecisionOutcome.DENY)), agent_name="a"
    )

    enforcer_module._warned_role_cap = False
    with caplog.at_level(logging.WARNING, logger="hexgate.security.enforcer"):
        with HexgateContext(user_id="u", user_roles=roles).sync_scope():
            enforcer.decide("refund", {})
            enforcer.decide("refund", {})

    assert caplog.text.count("MAX_EVALUATED_ROLES") == 1


def test_enforcer_single_role_matches_the_pre_multi_role_verdict() -> None:
    """D12: one role in ``user_roles`` produces exactly the verdict that role
    produces on its own, structured detail included."""
    from hexgate.runtime.context import HexgateContext

    policy = AgentPolicy.model_validate(
        {
            "default_policy": {"mode": "deny"},
            "tools": {
                "refund": {"mode": "allow", "constraints": ["args.amount <= 100"]}
            },
        }
    )
    policy_set = PolicySet({"default": policy, "billing": policy})
    enforcer = PolicyEnforcer(policy_set, agent_name="a")

    direct = policy_set.evaluate(role="billing", tool="refund", args={"amount": 500})
    with HexgateContext(user_id="u", user_roles=["billing"]).sync_scope():
        decision = enforcer.decide("refund", {"amount": 500})

    assert decision.outcome is direct.outcome
    assert decision.reason == direct.reason
    assert decision.violations == direct.violations
    assert decision.hint == direct.hint


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
