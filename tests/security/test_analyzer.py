"""Tests for the policy analyzer — soft lints over a linked bundle."""

from __future__ import annotations

from types import SimpleNamespace

from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    ModuleContent,
    analyze,
    check,
    link_policy_set,
)


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


def test_unknown_tool_boundary_is_error_capability_is_warning():
    boundary = _mod("b", "boundary", {"delete_db": _deny()})
    cap = _mod("c", "capability", {"ghost_tool": _allow()})
    manifest = _manifest(("refund", ["amount"]))  # neither tool is declared

    lints = check([boundary], [cap], manifest=manifest)
    by = {(lint.tool): lint for lint in lints if lint.code == "unknown-tool"}

    assert by["delete_db"].severity == "error"
    assert by["delete_db"].tier == "boundary"
    assert by["ghost_tool"].severity == "warning"
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
    boundary = _mod("b", "boundary", {"ghost": _deny()})
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
