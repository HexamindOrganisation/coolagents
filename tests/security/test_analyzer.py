"""Tests for the policy analyzer — soft lints over a linked bundle, plus the
cross-role `permissive-default` check over a resolved role map."""

from __future__ import annotations

from types import SimpleNamespace

from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    ModuleContent,
    PolicySet,
    analyze,
    check,
    check_project,
    link_policy_set,
    load_policy_map,
)
from hexgate.security.analyzer import check_default_role_exposure


def _mod(name, kind, tools, *, default_mode="allow"):
    return ModuleContent(
        name=name,
        kind=kind,
        policy=AgentPolicy(
            default_policy=BaseToolPolicy(mode=default_mode), tools=tools
        ),
        source=f"{name}.yaml",
        content_hash=f"hash-{name}",
    )


def _allow(constraints=None):
    return BaseToolPolicy(mode="allow", constraints=constraints or [])


def _deny(constraints=None):
    return BaseToolPolicy(mode="deny", constraints=constraints or [])


def _manifest(*tools):
    """Duck-typed AgentManifest: tools=[(name, [arg, ...]), ...]."""
    return SimpleNamespace(
        tools=[
            SimpleNamespace(
                name=name,
                input_schema=SimpleNamespace(properties={a: None for a in args}),
            )
            for name, args in tools
        ]
    )


def _codes(lints):
    return {(lint.code, lint.tool) for lint in lints}


# --- clean ---


def test_clean_bundle_has_no_lints():
    boundary = _mod("b", "boundary", {"refund": _allow(["args.amount <= 100"])})
    cap = _mod("c", "capability", {"refund": _allow()})
    manifest = _manifest(("refund", ["amount"]))
    assert check([boundary], [cap], manifest=manifest) == []


# --- dead-grant (provenance only, no manifest) ---


def test_dead_grant_when_ceiling_excludes_a_capability_grant():
    ceiling = _mod("org", "boundary", {"refund": _allow()}, default_mode="deny")
    cap = _mod("c", "capability", {"refund": _allow(), "send_email": _allow()})

    lints = check([ceiling], [cap])

    dead = [lint for lint in lints if lint.code == "dead-grant"]
    assert len(dead) == 1
    assert dead[0].tool == "send_email"
    assert dead[0].severity == "warning"
    assert dead[0].source == "c.yaml"
    assert "org" in dead[0].message  # names the shadowing boundary


def test_dead_grant_when_a_boundary_hard_denies_the_tool():
    # The most clear-cut dead grant: an unconditional boundary deny beats the
    # grant. This never enters trace.shadowed, so keying off the effective
    # policy (not shadowed) is what catches it.
    boundary = _mod("org", "boundary", {"wire": _deny()})  # floor, unconditional deny
    cap = _mod("c", "capability", {"wire": _allow()})

    lints = check([boundary], [cap])

    dead = [lint for lint in lints if lint.code == "dead-grant"]
    assert len(dead) == 1
    assert dead[0].tool == "wire"
    assert "denies" in dead[0].message


# --- redundant-grant ---


def test_redundant_grant_across_two_capabilities():
    c1 = _mod("c1", "capability", {"refund": _allow(["args.amount <= 100"])})
    c2 = _mod("c2", "capability", {"refund": _allow(["args.amount <= 100"])})

    lints = check([], [c1, c2])

    red = [lint for lint in lints if lint.code == "redundant-grant"]
    assert len(red) == 1
    assert red[0].tool == "refund"
    assert red[0].severity == "info"
    assert red[0].source == "c2.yaml"  # the later one is flagged


# --- link errors surface as an error lint, not an exception ---


def test_link_error_becomes_an_error_lint():
    bad = _mod("bad", "capability", {"refund": _deny()})
    lints = check([], [bad])
    assert len(lints) == 1
    assert lints[0].code == "link-error"
    assert lints[0].severity == "error"


# --- drift (needs a manifest) ---


def test_unknown_tool_severity_follows_failure_direction():
    # boundary ceiling naming a missing tool = fail-open (real tool uncapped) = error;
    # boundary deny on a missing tool = harmless = info;
    # capability drift = dead grant = warning.
    boundary = _mod(
        "b",
        "boundary",
        {"ghost_cap": _allow(), "ghost_deny": _deny()},
    )
    cap = _mod("c", "capability", {"ghost_tool": _allow()})
    manifest = _manifest(("refund", ["amount"]))  # none of these tools declared

    lints = check([boundary], [cap], manifest=manifest)
    by = {lint.tool: lint for lint in lints if lint.code == "unknown-tool"}

    assert by["ghost_cap"].severity == "error"  # boundary ceiling allow
    assert by["ghost_deny"].severity == "info"  # boundary deny, harmless
    assert by["ghost_tool"].severity == "warning"  # capability grant
    assert by["ghost_tool"].tier == "capability"


def test_drift_skipped_without_a_manifest():
    boundary = _mod("b", "boundary", {"delete_db": _deny()})
    cap = _mod("c", "capability", {"ghost_tool": _allow()})
    lints = check([boundary], [cap])  # no manifest
    assert not any(lint.code == "unknown-tool" for lint in lints)


def test_unknown_arg_flags_a_constraint_on_a_missing_parameter():
    boundary = _mod("b", "boundary", {"refund": _allow(['args.currency == "USD"'])})
    cap = _mod("c", "capability", {"refund": _allow()})
    manifest = _manifest(("refund", ["amount"]))  # accepts amount, not currency

    lints = check([boundary], [cap], manifest=manifest)

    arg = [lint for lint in lints if lint.code == "unknown-arg"]
    assert len(arg) == 1
    assert arg[0].tool == "refund"
    assert arg[0].source == "b.yaml"
    assert "currency" in arg[0].message


# --- analyze() over an existing result, and severity ordering ---


def test_analyze_sorts_errors_first():
    boundary = _mod("b", "boundary", {"ghost": _allow()})  # ceiling drift = error
    c1 = _mod("c1", "capability", {"refund": _allow(["args.amount <= 1"])})
    c2 = _mod("c2", "capability", {"refund": _allow(["args.amount <= 1"])})
    manifest = _manifest(("refund", ["amount"]))

    result = link_policy_set([boundary], [c1, c2])
    lints = analyze(result, [boundary], [c1, c2], manifest=manifest)

    from hexgate.security.analyzer import SEVERITY_RANK

    severities = [lint.severity for lint in lints]
    assert severities == sorted(severities, key=SEVERITY_RANK.get)
    assert ("unknown-tool", "ghost") in _codes(lints)  # error present
    assert ("redundant-grant", "refund") in _codes(lints)  # info present


def test_undefined_const_becomes_link_error_lint_not_traceback():
    # link_policy_set raises PolicySetError (undefined const) — check() must fold
    # it into a lint, not let it escape as a traceback.
    cap = _mod(
        "c", "capability", {"refund": _allow(["args.amount <= consts.max_refund"])}
    )
    lints = check([], [cap])
    assert [lint.code for lint in lints] == ["link-error"]
    assert lints[0].severity == "error"


def test_boundary_deny_arg_typo_is_error():
    # A boundary conditional deny with a typo'd arg inverts to an allow
    # (fail-open), so its arg drift must be an error, not a warning.
    boundary = _mod("org", "boundary", {"refund": _deny(["args.amoun > 1000"])})
    cap = _mod("c", "capability", {"refund": _allow()})
    manifest = _manifest(("refund", ["amount"]))

    lints = check([boundary], [cap], manifest=manifest)
    arg = [lint for lint in lints if lint.code == "unknown-arg"]
    assert len(arg) == 1
    assert arg[0].severity == "error"
    assert arg[0].tier == "boundary"


def test_constraint_erased_when_a_sibling_grant_is_unconditional():
    tight = _mod("tight", "capability", {"refund": _allow(["args.amount <= 100"])})
    loose = _mod("loose", "capability", {"refund": _allow()})  # unconditional
    lints = check([], [tight, loose])
    erased = [lint for lint in lints if lint.code == "constraint-erased"]
    assert len(erased) == 1
    assert erased[0].tool == "refund"
    assert erased[0].source == "tight.yaml"  # the constrained one is flagged
    assert "loose" in erased[0].message


def test_default_policy_constraints_rejected_as_link_error():
    from hexgate.security import AgentPolicy, BaseToolPolicy

    module = ModuleContent(
        name="b",
        kind="boundary",
        policy=AgentPolicy(
            default_policy=BaseToolPolicy(mode="allow", constraints=["args.x <= 1"])
        ),
        source="b.yaml",
        content_hash="h",
    )
    lints = check([module], [])
    assert [lint.code for lint in lints] == ["link-error"]
    assert "default_policy constraints" in lints[0].message


# ---------------------------------------------------------------------------
# permissive-default — cross-role exposure of the `default` fallback
# ---------------------------------------------------------------------------


def _policy_set(roles: dict[str, dict]) -> PolicySet:
    return load_policy_map(
        {name: AgentPolicy.model_validate(spec) for name, spec in roles.items()}
    )


def test_permissive_default_flags_a_grant_no_named_role_has() -> None:
    """A tool only `default` grants is reachable by any undefined role name."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "default": {"tools": {"delete_everything": {"mode": "allow"}}},
                "support": {"tools": {"read_file": {"mode": "allow"}}},
            }
        )
    )

    assert [lint.code for lint in lints] == ["permissive-default"]
    assert lints[0].severity == "warning"
    assert lints[0].tool == "delete_everything"


def test_permissive_default_is_quiet_when_a_named_role_also_grants_it() -> None:
    """A shared grant is intentional (typically a mixin), not exposure."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "default": {"tools": {"read_file": {"mode": "allow"}}},
                "support": {"tools": {"read_file": {"mode": "allow"}}},
            }
        )
    )

    assert lints == []


def test_permissive_default_is_quiet_for_a_least_privilege_default() -> None:
    lints = check_default_role_exposure(
        _policy_set(
            {
                "default": {"default_policy": {"mode": "deny"}},
                "support": {"tools": {"read_file": {"mode": "allow"}}},
            }
        )
    )

    assert lints == []


def test_permissive_default_is_quiet_for_a_single_role_policy() -> None:
    """A legacy flat policy.yaml *is* the `default` role — nothing to report."""
    lints = check_default_role_exposure(
        _policy_set({"default": {"tools": {"read_file": {"mode": "allow"}}}})
    )

    assert lints == []


def test_permissive_default_flags_a_granting_catch_all() -> None:
    """`default_policy: allow` under `default` exposes every unlisted tool."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "default": {"default_policy": {"mode": "allow"}},
                "support": {
                    "default_policy": {"mode": "deny"},
                    "tools": {"read_file": {"mode": "allow"}},
                },
            }
        )
    )

    assert [lint.code for lint in lints] == ["permissive-default"]
    assert "default_policy" in lints[0].message
    assert lints[0].tool is None


def test_permissive_default_flags_approval_required_grants_too() -> None:
    """`approval_required` still reaches the tool, just with a gate."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "default": {"tools": {"deploy": {"mode": "approval_required"}}},
                "support": {"tools": {"read_file": {"mode": "allow"}}},
            }
        )
    )

    assert len(lints) == 1
    assert lints[0].tool == "deploy"


def test_permissive_default_sees_through_inheritance() -> None:
    """The check runs on resolved policies, so inherited grants count."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "base": {"is_mixin": True, "tools": {"read_file": {"mode": "allow"}}},
                "default": {"tools": {"read_file": {"mode": "allow"}}},
                "support": {"inherits": ["base"]},
            }
        )
    )

    assert lints == []


# ---------------------------------------------------------------------------
# implicit-default — a roles document that never declares `default`
#
# The loader aliases the first concrete role as the fallback, so `default` and
# that role resolve to the SAME policy object. Every test above declares an
# explicit `default`, which is how a silent check shipped: comparing the
# fallback against a list that still contained itself matched every grant.
# ---------------------------------------------------------------------------


def test_implicit_default_is_flagged() -> None:
    """No `default` role means one named role silently became the fallback."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "billing": {"tools": {"refund": {"mode": "allow"}}},
                "support": {"tools": {"lookup": {"mode": "allow"}}},
            }
        )
    )

    codes = [lint.code for lint in lints]
    assert "implicit-default" in codes
    assert all(lint.severity == "warning" for lint in lints)
    assert "billing" in next(
        lint.message for lint in lints if lint.code == "implicit-default"
    )


def test_implicit_default_still_reports_the_grants_it_exposes() -> None:
    """The aliased role's own grants ARE the exposure — they must be listed."""
    lints = check_default_role_exposure(
        _policy_set(
            {
                "billing": {"tools": {"refund": {"mode": "allow"}}},
                "support": {"tools": {"lookup": {"mode": "allow"}}},
            }
        )
    )

    assert "refund" in {lint.tool for lint in lints}


def test_explicit_default_argument_is_not_an_implicit_default() -> None:
    """`load_policy_map(default=...)` is a deliberate choice, not an accident."""
    lints = load_policy_map(
        {
            "billing": AgentPolicy.model_validate(
                {"tools": {"refund": {"mode": "allow"}}}
            ),
            "support": AgentPolicy.model_validate(
                {"tools": {"lookup": {"mode": "allow"}}}
            ),
        },
        default="billing",
    )

    assert [lint.code for lint in check_default_role_exposure(lints)] != [
        "implicit-default"
    ]
# --- check_project: per-role attribution + project-level lints -------------


def test_check_project_tags_a_dead_grant_with_its_role():
    ceiling = _mod("org", "boundary", {"refund": _allow()}, default_mode="deny")
    pay = _mod("pay", "capability", {"refund": _allow(), "send_email": _allow()})

    lints = check_project([ceiling], [pay], {"support": ["pay"]})

    dead = [lint for lint in lints if lint.code == "dead-grant"]
    assert len(dead) == 1
    assert dead[0].tool == "send_email"  # ceiling excludes it
    assert dead[0].role == "support"


def test_unused_capability_is_flagged():
    used = _mod("used", "capability", {"x": _allow()})
    unused = _mod("unused", "capability", {"y": _allow()})

    lints = check_project([], [used, unused], {"default": ["used"]})

    un = [lint for lint in lints if lint.code == "unused-capability"]
    assert len(un) == 1
    assert un[0].source == "unused.yaml"
    assert "unused" in un[0].message


def test_no_default_role_is_flagged():
    cap = _mod("c", "capability", {"x": _allow()})
    lints = check_project([], [cap], {"billing": ["c"]})
    nd = [lint for lint in lints if lint.code == "no-default-role"]
    assert len(nd) == 1
    # role stays None so a role-scoped `check --role X` still surfaces it.
    assert nd[0].role is None


def test_check_project_unknown_capability_is_a_link_error():
    # Same contract as resolve_for_project: an unknown capability name in a role
    # fails, it is not silently dropped.
    cap = _mod("c", "capability", {"x": _allow()})
    lints = check_project([], [cap], {"r": ["missing"]})
    assert [lint.code for lint in lints] == ["link-error"]


def test_no_roles_emit_no_project_lints():
    # None (no roles.yaml) -> one default importing everything. Nothing unused,
    # and the default is present, so neither project-level lint fires.
    cap = _mod("c", "capability", {"x": _allow()})
    lints = check_project([], [cap], None)
    codes = {lint.code for lint in lints}
    assert "unused-capability" not in codes
    assert "no-default-role" not in codes
