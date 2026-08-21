"""Tests for agent-level policy: the ``admission`` / ``agents`` blocks and their
lowering into synthetic ``agent.*`` tool keys (``security/models.py``).

The lowering is the parity-critical piece: ``admission`` / ``agents`` expand into
ordinary tool entries in ``effective_tools`` so both policy engines gate an
agent-level rule through the identical decision path as a tool. These tests drive
the pydantic path via the ``assert_*`` helpers and check that the Rego compiler
emits the same lowered keys, with no engine change.
"""

from __future__ import annotations

import shutil

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

needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")

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


def test_admission_is_opt_in_when_unlisted_but_enforced_when_declared() -> None:
    # agent.run is opt-in: a policy that declares no admission admits (even under a
    # deny-default), so adding admission to one role never locks out roles without
    # it. A declared admission still enforces.
    no_admission = AgentPolicy(default_policy=BaseToolPolicy(mode="deny"))
    assert_allows(no_admission, AGENT_RUN_TOOL)  # absent → admit, not deny-default
    declared_deny = AgentPolicy(
        default_policy=BaseToolPolicy(mode="deny"),
        admission=BaseToolPolicy(mode="deny"),
    )
    assert_denies(declared_deny, AGENT_RUN_TOOL)


def test_authored_agent_prefixed_tool_follows_default_not_closed_world() -> None:
    # An authored tool whose name merely starts with "agent." (not a reserved key)
    # follows default_policy, it is not swept into the closed-world reach handling.
    policy = AgentPolicy(default_policy=BaseToolPolicy(mode="allow"))
    assert_allows(policy, "agent.foo")  # not a key → default allow
    assert_allows(policy, "agent.tool")  # no colon → not a reach key → default allow
    assert_allows(policy, AGENT_RUN_TOOL)  # admission opt-in → allow
    assert_denies(policy, agent_target_key("tool", "x"))  # real reach key → deny


# --- parity: the Rego compiler emits the same lowered keys ------------------


def test_rego_compiler_emits_lowered_agent_keys() -> None:
    # ``compile_to_rego`` takes the parsed YAML document (flat single-policy here).
    payload = {"agents": {"billing-bot": {"mode": "allow", "via": ["handoff"]}}}
    rego = compile_to_rego(payload)
    # The synthetic key is a plain string literal in the guard, ``:`` and all.
    assert 'input.tool == "agent.handoff:billing-bot"' in rego


def test_rego_permissive_default_excludes_reach_keys_and_opts_in_admission() -> None:
    # Reach keys are excluded from the permissive catch-all (so they deny), while
    # admission opts in via its own rule. The old broad ``agent.`` exclusion is gone
    # (it wrongly caught authored agent.* tool names).
    rego = compile_to_rego(
        {
            "default_policy": {"mode": "allow"},
            "agents": {"b": {"mode": "allow", "via": ["tool"]}},
        }
    )
    assert 'not startswith(input.tool, "agent.tool:")' in rego
    assert 'not startswith(input.tool, "agent.handoff:")' in rego
    assert 'input.tool == "agent.run"' in rego  # opt-in admit rule
    assert 'not startswith(input.tool, "agent.")' not in rego


@needs_opa
def test_closed_world_agent_parity_pydantic_vs_wasm() -> None:
    # The fallbacks must agree across engines under an allow-default: ordinary tools
    # and authored agent.*-named tools follow the default (allow), admission opts in
    # (allow), and unlisted reach keys deny — on both the pydantic and WASM paths.
    from hexgate.security import compile_to_wasm, verdict_from_rego
    from hexgate.security.wasm_engine import WasmPolicy

    payload = {
        "default_policy": {"mode": "allow"},
        "agents": {"billing-bot": {"mode": "allow", "via": ["tool"]}},
    }
    ps = load_policy_set_from_dict(payload)
    engine = WasmPolicy.from_bytes(compile_to_wasm(compile_to_rego(payload)).wasm)

    cases = [
        "some_unlisted_tool",  # ordinary tool → default allow
        "agent.foo",  # authored agent.*-named tool (not a key) → default allow
        AGENT_RUN_TOOL,  # admission opt-in → allow
        agent_target_key("tool", "billing-bot"),  # listed → allow
        agent_target_key("handoff", "billing-bot"),  # via not listed → deny
        agent_target_key("tool", "other-bot"),  # target not listed → deny
    ]
    for tool in cases:
        pyd = ps.evaluate(role="default", tool=tool, args={})
        wsm = verdict_from_rego(
            engine.decide(role="default", tool=tool, args={}),
            tool_name=tool,
            role="default",
        )
        assert pyd.outcome is wsm.outcome, tool


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


def test_agent_reach_is_closed_world_even_under_allow_default() -> None:
    # A permissive default_policy grants unlisted *tools*, but never an unlisted
    # *agent* reach: agent keys are closed-world regardless of the default.
    policy = AgentPolicy(
        default_policy=BaseToolPolicy(mode="allow"),
        agents={"billing-bot": AgentTargetPolicy(mode="allow", via=["tool"])},
    )
    assert_allows(policy, "some_unlisted_tool")  # ordinary tool → default allow
    assert_allows(policy, agent_target_key("tool", "billing-bot"))  # listed
    assert_denies(policy, agent_target_key("handoff", "billing-bot"))  # via not listed
    assert_denies(policy, agent_target_key("tool", "other-bot"))  # target not listed


def test_dropped_via_denies_regardless_of_default() -> None:
    # A child that narrows a target's vias: the dropped via denies whatever the
    # default is (closed-world), so a permissive default cannot resurrect it. No
    # error, no fail-open — the whole class the old guard chased is gone.
    payload = {
        "roles": {
            "base": {
                "is_mixin": True,
                "agents": {
                    "billing-bot": {
                        "mode": "allow",
                        "via": ["tool", "handoff"],
                        "constraints": ["args.amount <= 100"],
                    }
                },
            },
            "support": {
                "inherits": ["base"],
                "default_policy": {"mode": "allow"},
                "agents": {"billing-bot": {"mode": "allow", "via": ["tool"]}},
            },
        }
    }
    policy_set = load_policy_set_from_dict(payload)
    assert_allows(policy_set, agent_target_key("tool", "billing-bot"), role="support")
    # handoff dropped → closed-world deny even under an allow-default, cap and all.
    assert_denies(
        policy_set,
        agent_target_key("handoff", "billing-bot"),
        {"amount": 5000},
        role="support",
    )


def test_inherited_dropped_via_denies_under_later_permissive_default() -> None:
    # The inheritance hazard: a mid role narrows to tool-only, then a descendant
    # flips default_policy to allow without touching agents. The dropped handoff
    # still denies (closed-world), so the descendant cannot silently resurrect it.
    payload = {
        "roles": {
            "base": {
                "is_mixin": True,
                "agents": {
                    "billing-bot": {
                        "mode": "allow",
                        "via": ["tool", "handoff"],
                        "constraints": ["args.amount <= 100"],
                    }
                },
            },
            "mid": {
                "is_mixin": True,
                "inherits": ["base"],
                "agents": {
                    "billing-bot": {
                        "mode": "allow",
                        "via": ["tool"],
                        "constraints": ["args.amount <= 100"],
                    }
                },
            },
            "support": {
                "inherits": ["mid"],
                "default_policy": {"mode": "allow"},  # declares no agents
            },
        }
    }
    policy_set = load_policy_set_from_dict(payload)
    assert_denies(
        policy_set,
        agent_target_key("handoff", "billing-bot"),
        {"amount": 5000},
        role="support",
    )


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
