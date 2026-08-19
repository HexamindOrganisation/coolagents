"""Tests for agent-level policy: the ``admission`` / ``agents`` blocks and their
lowering into synthetic ``agent.*`` tool keys (``security/models.py``).

The lowering is the parity-critical piece: ``admission`` / ``agents`` expand into
ordinary tool entries in ``effective_tools`` so both policy engines gate an
agent-level rule through the identical decision path as a tool. These tests drive
the pydantic path via the ``assert_*`` helpers and check that the Rego compiler
emits the same lowered keys, with no engine change.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hexgate.security import (
    AGENT_RUN_TOOL,
    AgentPolicy,
    AgentTargetPolicy,
    BaseToolPolicy,
    PolicySetError,
    agent_target_key,
    assert_allows,
    assert_denies,
    assert_needs_approval,
    compile_to_rego,
    load_policy_set_from_dict,
)

# --- lowering --------------------------------------------------------------


def test_admission_lowers_to_agent_run() -> None:
    policy = AgentPolicy(admission=BaseToolPolicy(mode="allow"))
    lowered = policy.lowered_agent_tools()
    assert set(lowered) == {AGENT_RUN_TOOL}
    assert lowered[AGENT_RUN_TOOL].mode == "allow"


def test_agents_lower_per_via_mode() -> None:
    policy = AgentPolicy(
        agents={
            "billing-bot": AgentTargetPolicy(
                mode="approval_required",
                via=["tool", "handoff"],
                constraints=["args.depth <= 2"],
            ),
            "refund-bot": AgentTargetPolicy(mode="allow", via=["tool"]),
        }
    )
    lowered = policy.lowered_agent_tools()
    assert set(lowered) == {
        "agent.tool:billing-bot",
        "agent.handoff:billing-bot",
        "agent.tool:refund-bot",
    }
    # refund-bot is tool-only: no handoff key was minted.
    assert "agent.handoff:refund-bot" not in lowered
    # mode + constraints carry over to every via key.
    assert lowered["agent.handoff:billing-bot"].mode == "approval_required"
    assert lowered["agent.tool:billing-bot"].constraints == ["args.depth <= 2"]


def test_via_defaults_to_both_modes() -> None:
    policy = AgentPolicy(agents={"b": AgentTargetPolicy(mode="allow")})
    assert set(policy.lowered_agent_tools()) == {"agent.tool:b", "agent.handoff:b"}


def test_via_dedupes_order_preserving() -> None:
    target = AgentTargetPolicy(mode="allow", via=["handoff", "tool", "handoff"])
    assert target.via == ["handoff", "tool"]


def test_empty_via_rejected() -> None:
    with pytest.raises(ValidationError):
        AgentTargetPolicy(mode="allow", via=[])


def test_effective_tools_merges_authored_and_lowered() -> None:
    policy = AgentPolicy(
        tools={"refund": BaseToolPolicy(mode="allow")},
        admission=BaseToolPolicy(mode="allow"),
        agents={"b": AgentTargetPolicy(mode="deny", via=["handoff"])},
    )
    assert set(policy.effective_tools) == {
        "refund",
        AGENT_RUN_TOOL,
        "agent.handoff:b",
    }


def test_effective_tools_returns_tools_when_no_agent_blocks() -> None:
    tools = {"refund": BaseToolPolicy(mode="allow")}
    policy = AgentPolicy(tools=tools)
    # No agent blocks → the same authored map, untouched.
    assert policy.effective_tools == tools


# --- reserved namespace ----------------------------------------------------


@pytest.mark.parametrize(
    "reserved",
    ["agent.run", "agent.tool:x", "agent.handoff:x"],
)
def test_reserved_agent_tool_name_rejected(reserved: str) -> None:
    with pytest.raises(ValidationError):
        AgentPolicy(tools={reserved: BaseToolPolicy(mode="allow")})


def test_non_reserved_dotted_tool_name_allowed() -> None:
    # ``agent.foo`` is not a lowered key shape, and ``net.*`` egress tools must
    # keep working — only the exact ``agent.run`` / ``agent.tool:`` / ``agent.handoff:``
    # shapes are reserved.
    policy = AgentPolicy(
        tools={
            "agent.foo": BaseToolPolicy(mode="allow"),
            "net.http_request": BaseToolPolicy(mode="allow"),
        }
    )
    assert "agent.foo" in policy.tools


# --- enforcement through the real path -------------------------------------


def _policy() -> AgentPolicy:
    return AgentPolicy(
        default_policy=BaseToolPolicy(mode="deny"),
        admission=BaseToolPolicy(mode="allow"),
        agents={
            "billing-bot": AgentTargetPolicy(
                mode="approval_required",
                via=["tool", "handoff"],
                constraints=["args.depth <= 2"],
            ),
            "refund-bot": AgentTargetPolicy(mode="allow", via=["tool"]),
            "admin-bot": AgentTargetPolicy(mode="deny"),
        },
    )


def test_admission_allows() -> None:
    assert_allows(_policy(), AGENT_RUN_TOOL, {"agent": "self"})


def test_handoff_to_approval_target_needs_approval_within_depth() -> None:
    assert_needs_approval(
        _policy(), agent_target_key("handoff", "billing-bot"), {"depth": 1}
    )


def test_handoff_denied_when_constraint_fails() -> None:
    # depth 3 fails ``args.depth <= 2`` → deny even though the target is listed.
    assert_denies(_policy(), agent_target_key("handoff", "billing-bot"), {"depth": 3})


def test_tool_only_target_allows_as_tool_but_denies_handoff() -> None:
    policy = _policy()
    assert_allows(policy, agent_target_key("tool", "refund-bot"))
    # refund-bot minted no handoff key → falls to deny-by-default default_policy.
    assert_denies(policy, agent_target_key("handoff", "refund-bot"))


def test_denied_target_denies() -> None:
    assert_denies(_policy(), agent_target_key("handoff", "admin-bot"))


def test_unlisted_target_is_closed_world_under_deny_default() -> None:
    # No rule for evil-bot; deny-by-default default_policy makes a listed-agents
    # policy closed-world for free.
    assert_denies(_policy(), agent_target_key("handoff", "evil-bot"))


# --- parity: the Rego compiler emits the same lowered keys ------------------


def test_rego_compiler_emits_lowered_agent_keys() -> None:
    # ``compile_to_rego`` takes the parsed YAML document (flat single-policy here).
    payload = {"agents": {"billing-bot": {"mode": "allow", "via": ["handoff"]}}}
    rego = compile_to_rego(payload)
    # The synthetic key is a plain string literal in the guard, ``:`` and all.
    assert 'input.tool == "agent.handoff:billing-bot"' in rego


# --- inheritance -----------------------------------------------------------


def test_agent_blocks_survive_inheritance() -> None:
    payload = {
        "roles": {
            "base": {
                "is_mixin": True,
                "admission": {"mode": "allow"},
                "agents": {"shared-bot": {"mode": "allow", "via": ["tool"]}},
            },
            "support": {
                "inherits": ["base"],
                "agents": {"billing-bot": {"mode": "deny"}},
            },
        }
    }
    policy_set = load_policy_set_from_dict(payload)
    support = policy_set.policy_for("support")
    # Own agent target present, and inherited admission + inherited target both
    # survived the merge (dropping either would be fail-open).
    assert "agent.tool:shared-bot" in support.effective_tools
    assert AGENT_RUN_TOOL in support.effective_tools
    assert_denies(
        policy_set, agent_target_key("handoff", "billing-bot"), role="support"
    )
    assert_allows(policy_set, agent_target_key("tool", "shared-bot"), role="support")


def test_const_ref_in_agent_constraint_validated() -> None:
    # A ``consts.<name>`` in an agent-block constraint must be cross-checked at
    # PolicySet build, same as a tool constraint — an undefined const is an error.
    payload = {
        "roles": {
            "default": {
                "agents": {
                    "b": {"mode": "allow", "constraints": ["args.depth <= consts.max"]}
                },
            }
        }
    }
    with pytest.raises(PolicySetError):
        load_policy_set_from_dict(payload)


def test_child_narrowing_an_inherited_via_is_rejected() -> None:
    # A child dropping a via the parent listed would silently un-list that mode
    # (fail-open under a permissive default). Reject it loudly.
    payload = {
        "roles": {
            "base": {
                "is_mixin": True,
                "agents": {"admin-bot": {"mode": "deny", "via": ["tool", "handoff"]}},
            },
            "support": {
                "inherits": ["base"],
                "default_policy": {"mode": "allow"},
                "agents": {"admin-bot": {"mode": "allow", "via": ["tool"]}},
            },
        }
    }
    with pytest.raises(PolicySetError, match="narrows agent target"):
        load_policy_set_from_dict(payload)


def test_child_may_redeclare_target_with_the_full_via_set() -> None:
    # Re-declaring with the same (or wider) via set is a clean override; the
    # child's mode wins for every via.
    payload = {
        "roles": {
            "base": {
                "is_mixin": True,
                "agents": {"admin-bot": {"mode": "deny", "via": ["tool", "handoff"]}},
            },
            "support": {
                "inherits": ["base"],
                "agents": {
                    "admin-bot": {
                        "mode": "approval_required",
                        "via": ["tool", "handoff"],
                    }
                },
            },
        }
    }
    policy_set = load_policy_set_from_dict(payload)
    assert_needs_approval(
        policy_set, agent_target_key("handoff", "admin-bot"), role="support"
    )


def test_agent_policy_is_frozen() -> None:
    # Immutability is what makes memoizing effective_tools safe; enforce it so
    # the invariant the cache relies on is real, not just documented.
    policy = AgentPolicy(tools={"t": BaseToolPolicy(mode="allow")})
    with pytest.raises(ValidationError):
        policy.tools = {}
