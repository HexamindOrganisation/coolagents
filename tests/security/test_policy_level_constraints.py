"""Policy-level ``constraints:`` — the list that applies to every tool.

Three properties are load-bearing, one section each: it reaches every tool key
including the synthetic ``agent.run``; it can only *narrow*; and it unions
across ``inherits`` rather than overriding.
"""

from __future__ import annotations

import pytest

from hexgate.security.models import AgentPolicy
from hexgate.security.policy import evaluate_tool_call
from hexgate.security.policy_set import PolicySetError, load_policy_map


def _policy(**overrides) -> AgentPolicy:
    base = {
        "constraints": ["run.tool_calls < 3"],
        "default_policy": {"mode": "allow"},
        "tools": {
            "read_file": {"mode": "allow"},
            "delete_all": {"mode": "deny"},
        },
    }
    return AgentPolicy.model_validate({**base, **overrides})


def _outcome(policy: AgentPolicy, tool: str, tool_calls: int) -> str:
    return evaluate_tool_call(
        policy, tool, {}, run={"tool_calls": tool_calls}
    ).outcome.value


# --- reach ------------------------------------------------------------------


@pytest.mark.parametrize("tool", ["read_file", "not_listed_anywhere", "agent.run"])
def test_applies_to_every_reachable_tool(tool: str) -> None:
    """``agent.run`` matters because its policy comes from a fallback constant,
    not the document — easy to miss in a per-tool loop on one engine only."""
    policy = _policy()

    assert _outcome(policy, tool, tool_calls=1) == "allow"
    assert _outcome(policy, tool, tool_calls=5) == "deny"


def test_deny_reason_names_the_policy_level_constraint() -> None:
    verdict = evaluate_tool_call(_policy(), "read_file", {}, run={"tool_calls": 5})

    assert "run.tool_calls < 3" in verdict.reason


def test_evaluated_before_the_tools_own_constraints() -> None:
    """Order decides only which violation is reported first."""
    policy = _policy(
        tools={"refund": {"mode": "allow", "constraints": ["args.amount <= 50"]}}
    )

    verdict = evaluate_tool_call(
        policy, "refund", {"amount": 999}, run={"tool_calls": 5}
    )

    assert "run.tool_calls < 3" in verdict.reason
    assert "args.amount" not in verdict.reason


def test_the_tools_own_constraints_still_apply() -> None:
    policy = _policy(
        tools={"refund": {"mode": "allow", "constraints": ["args.amount <= 50"]}}
    )

    verdict = evaluate_tool_call(
        policy, "refund", {"amount": 999}, run={"tool_calls": 1}
    )

    assert verdict.outcome.value == "deny"
    assert "args.amount <= 50" in verdict.reason


# --- can only narrow --------------------------------------------------------


def test_never_resurrects_a_denied_tool() -> None:
    """``mode: deny`` short-circuits before constraints."""
    assert _outcome(_policy(), "delete_all", tool_calls=0) == "deny"


def test_never_resurrects_an_unlisted_reach_key() -> None:
    """Reach keys are closed-world — nothing here may grant an unlisted one."""
    assert _outcome(_policy(), "agent.handoff:billing", tool_calls=0) == "deny"


def test_an_empty_list_changes_nothing() -> None:
    policy = _policy(constraints=[])

    assert _outcome(policy, "read_file", tool_calls=999) == "allow"


# --- inheritance ------------------------------------------------------------


def _resolved(policy_map: dict[str, dict], role: str) -> AgentPolicy:
    return load_policy_map(
        {name: AgentPolicy.model_validate(spec) for name, spec in policy_map.items()}
    ).policy_for(role)


def test_unions_across_inherits_rather_than_overriding() -> None:
    """Override would let ``inherits: [read_only]`` silently remove the mixin's
    cap — fail-open on a security restriction."""
    resolved = _resolved(
        {
            "read_only": {"is_mixin": True, "constraints": ["run.tool_calls < 50"]},
            "default": {
                "inherits": ["read_only"],
                "constraints": ["run.elapsed_seconds < 120"],
                "default_policy": {"mode": "allow"},
            },
        },
        "default",
    )

    assert resolved.constraints == ["run.tool_calls < 50", "run.elapsed_seconds < 120"]


def test_an_inherited_constraint_actually_denies() -> None:
    """``_resolve_inheritance`` names its fields, so one left out is dropped for
    every role using ``inherits:`` — fail-open. Asserted by *evaluating*: a
    field check alone would pass a merge that built the list but never used it.
    """
    resolved = _resolved(
        {
            "read_only": {"is_mixin": True, "constraints": ["run.tool_calls < 3"]},
            "default": {
                "inherits": ["read_only"],
                "default_policy": {"mode": "allow"},
            },
        },
        "default",
    )

    assert (
        evaluate_tool_call(
            resolved, "anything", {}, run={"tool_calls": 5}
        ).outcome.value
        == "deny"
    )


def test_deduplicated_on_a_diamond() -> None:
    """A predicate inherited by two paths is evaluated once."""
    resolved = _resolved(
        {
            "base": {"is_mixin": True, "constraints": ["run.tool_calls < 50"]},
            "audited": {"is_mixin": True, "inherits": ["base"]},
            "read_only": {"is_mixin": True, "inherits": ["base"]},
            "default": {
                "inherits": ["audited", "read_only"],
                "default_policy": {"mode": "allow"},
            },
        },
        "default",
    )

    assert resolved.constraints == ["run.tool_calls < 50"]


def test_a_role_without_inherits_is_untouched() -> None:
    """The no-inherits early return skips the merge — a separate path."""
    resolved = _resolved(
        {"default": {"constraints": ["run.tool_calls < 3"]}}, "default"
    )

    assert resolved.constraints == ["run.tool_calls < 3"]


# --- load-time validation ---------------------------------------------------


def test_grammar_error_surfaces_at_model_validate() -> None:
    with pytest.raises(Exception, match="constraint|parse"):
        AgentPolicy.model_validate({"constraints": ["args.amount <<< 3"]})


def test_undefined_const_reference_rejected_at_policy_set_construction() -> None:
    with pytest.raises(PolicySetError, match="undefined constant consts.cap"):
        load_policy_map(
            {
                "default": AgentPolicy.model_validate(
                    {"constraints": ["run.tool_calls < consts.cap"]}
                )
            }
        )


def test_const_reference_resolves_when_defined() -> None:
    policy = load_policy_map(
        {
            "default": AgentPolicy.model_validate(
                {
                    "consts": {"cap": 3},
                    "constraints": ["run.tool_calls < consts.cap"],
                    "default_policy": {"mode": "allow"},
                }
            )
        }
    ).policy_for("default")

    assert _outcome(policy, "anything", tool_calls=1) == "allow"
    assert _outcome(policy, "anything", tool_calls=5) == "deny"
