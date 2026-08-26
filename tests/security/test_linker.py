"""Tests for the policy linker — composing a module bundle into one policy.

The fold is the crown jewel, so these are pure (no opa needed) except the final
parity test. Fixtures mirror ``policy-modules-plan.md``'s worked example, with
the two boundary postures kept internally consistent:

- **floor** boundary (``default_policy: allow``) — only subtracts what it names;
  unlisted tools pass through to capabilities.
- **ceiling** boundary (``default_policy: deny``) — a tool it doesn't list is
  ineligible, so a capability grant for it is inert (shadowed).
"""

from __future__ import annotations

import shutil

import pytest

from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    DecisionOutcome,
    LinkError,
    ModuleContent,
    evaluate_tool_call,
    link,
    link_policy_set,
    resolve_for_project,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


def _mod(name, kind, tools, *, default_mode="allow", consts=None):
    return ModuleContent(
        name=name,
        kind=kind,
        policy=AgentPolicy(
            default_policy=BaseToolPolicy(mode=default_mode),
            tools=tools,
            consts=consts or {},
        ),
        source=f"{name}.yaml",
        content_hash=f"hash-{name}",
    )


def _allow(constraints=None):
    return BaseToolPolicy(mode="allow", constraints=constraints or [])


def _deny(constraints=None):
    return BaseToolPolicy(mode="deny", constraints=constraints or [])


def _approval():
    return BaseToolPolicy(mode="approval_required")


# --- floor boundary: the worked-example table (unlisted tools pass through) ---


@pytest.fixture
def floor_bundle():
    boundary = _mod(
        "org.core",
        "boundary",
        {
            "delete_database": _deny(),
            "refund_order": _allow(["args.amount <= 1000"]),
        },
        default_mode="allow",  # floor
    )
    payments = _mod(
        "payments",
        "capability",
        {
            "refund_order": _allow(['args.currency in ["USD", "EUR"]']),
            "lookup_order": _allow(),
        },
    )
    leaf = _mod(
        "leaf",
        "capability",
        {"send_email": _allow(), "escalate": _approval()},
    )
    return [boundary], [payments, leaf]


@pytest.mark.parametrize(
    "tool,args,expected",
    [
        ("refund_order", {"amount": 800, "currency": "USD"}, DecisionOutcome.ALLOW),
        ("refund_order", {"amount": 1200, "currency": "USD"}, DecisionOutcome.DENY),
        ("refund_order", {"amount": 800, "currency": "GBP"}, DecisionOutcome.DENY),
        ("delete_database", {}, DecisionOutcome.DENY),
        ("lookup_order", {}, DecisionOutcome.ALLOW),
        ("send_email", {}, DecisionOutcome.ALLOW),
        ("escalate", {}, DecisionOutcome.NEEDS_APPROVAL),
    ],
)
def test_floor_worked_example(floor_bundle, tool, args, expected):
    effective, _ = link(*floor_bundle)
    assert evaluate_tool_call(effective, tool, args).outcome is expected


def test_floor_refund_intersects_ceiling_and_grant(floor_bundle):
    effective, _ = link(*floor_bundle)
    # ceiling constraint (amount<=1000) AND the capability grant (currency).
    cons = effective.tools["refund_order"].constraints
    assert any("amount <= 1000" in c for c in cons)
    assert any("currency" in c for c in cons)


# --- ceiling boundary: a tool it doesn't list is ineligible ---


def test_ceiling_gates_eligibility_and_records_shadow():
    ceiling = _mod(
        "org.ceiling",
        "boundary",
        {
            "delete_database": _deny(),
            "refund_order": _allow(["args.amount <= 1000"]),
        },
        default_mode="deny",  # ceiling
    )
    # payments grants refund_order (in the ceiling) + lookup_order (not in it).
    payments = _mod(
        "payments", "capability", {"refund_order": _allow(), "lookup_order": _allow()}
    )
    leaf = _mod("leaf", "capability", {"send_email": _allow()})

    effective, trace = link([ceiling], [payments, leaf])

    # refund_order is in the ceiling AND granted → allowed (capped).
    assert evaluate_tool_call(effective, "refund_order", {"amount": 500}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "lookup_order", {}).outcome is (
        DecisionOutcome.DENY
    )
    assert evaluate_tool_call(effective, "send_email", {}).outcome is (
        DecisionOutcome.DENY
    )
    # and the shadowing is attributed to the ceiling for the analyzer.
    assert "lookup_order" in trace.shadowed
    assert trace.shadowed["lookup_order"].module == "org.ceiling"


# --- combining rules ---


def test_two_capabilities_union():
    """Two grants for one tool union: allowed if EITHER condition holds."""
    usd = _mod("usd", "capability", {"refund": _allow(['args.currency == "USD"'])})
    eur = _mod("eur", "capability", {"refund": _allow(['args.currency == "EUR"'])})
    effective, _ = link([], [usd, eur])

    assert evaluate_tool_call(effective, "refund", {"currency": "USD"}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "refund", {"currency": "EUR"}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "refund", {"currency": "GBP"}).outcome is (
        DecisionOutcome.DENY
    )


def test_two_boundaries_intersect_stricter_cap():
    """Two ceilings on one tool intersect: the stricter bound wins."""
    g1 = _mod("g1", "boundary", {"refund": _allow(["args.amount <= 1000"])})
    g2 = _mod("g2", "boundary", {"refund": _allow(["args.amount <= 500"])})
    grant = _mod("cap", "capability", {"refund": _allow()})
    effective, _ = link([g1, g2], [grant])

    assert evaluate_tool_call(effective, "refund", {"amount": 400}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "refund", {"amount": 700}).outcome is (
        DecisionOutcome.DENY  # over the stricter 500 cap
    )


def test_unconditional_boundary_deny_is_absolute():
    """A boundary deny beats any capability grant."""
    guard = _mod("g", "boundary", {"wire": _deny()}, default_mode="allow")
    grant = _mod("c", "capability", {"wire": _allow()})
    effective, _ = link([guard], [grant])
    assert evaluate_tool_call(effective, "wire", {}).outcome is DecisionOutcome.DENY


def test_conditional_boundary_deny_subtracts_region():
    """A boundary deny WITH constraints subtracts that region from the grant."""
    guard = _mod(
        "g",
        "boundary",
        {"refund": _deny(["args.amount > 1000"])},
        default_mode="allow",
    )
    grant = _mod("c", "capability", {"refund": _allow()})
    effective, _ = link([guard], [grant])
    assert evaluate_tool_call(effective, "refund", {"amount": 500}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "refund", {"amount": 2000}).outcome is (
        DecisionOutcome.DENY
    )


def test_capability_deny_raises():
    """Capabilities may only grant — a deny is a config error, not a silent tighten."""
    bad = _mod("bad", "capability", {"refund": _deny()})
    with pytest.raises(LinkError, match="capabilities may only grant"):
        link([], [bad])


def test_capability_cannot_override_boundary_const():
    """A capability redefining a boundary const would loosen a cap — reject it."""
    guard = _mod(
        "g",
        "boundary",
        {"refund": _allow(["args.amount <= consts.cap"])},
        consts={"cap": 1000},
    )
    cap = _mod("c", "capability", {"refund": _allow()}, consts={"cap": 1_000_000})
    with pytest.raises(LinkError, match="may not override boundary constants"):
        link([guard], [cap])


def test_ceiling_conditional_deny_only_does_not_grant_eligibility():
    """A ceiling that mentions a tool ONLY via a conditional deny must not let a
    capability grant slip through — the tool isn't in the ceiling's allow set."""
    ceiling = _mod(
        "org",
        "boundary",
        {"refund": _deny(["args.amount > 10000"])},  # conditional deny, no allow
        default_mode="deny",  # ceiling
    )
    cap = _mod("c", "capability", {"refund": _allow()})
    effective, trace = link([ceiling], [cap])
    # ineligible: the ceiling never granted refund, so a $5000 refund is denied.
    assert evaluate_tool_call(effective, "refund", {"amount": 5000}).outcome is (
        DecisionOutcome.DENY
    )
    assert "refund" in trace.shadowed


def test_two_boundaries_conflicting_const_raises():
    """Two boundaries disagreeing on a const value must not silently last-win."""
    g1 = _mod(
        "org",
        "boundary",
        {"refund": _allow(["args.amount <= consts.cap"])},
        consts={"cap": 100},
    )
    g2 = _mod("team", "boundary", {"lookup": _allow()}, consts={"cap": 100000})
    with pytest.raises(LinkError, match="conflicting values"):
        link([g1, g2], [])


def test_matching_const_across_tiers_is_allowed():
    """Same const value in both tiers is harmless — only a differing value errors."""
    guard = _mod(
        "g",
        "boundary",
        {"refund": _allow(["args.amount <= consts.cap"])},
        consts={"cap": 1000},
    )
    cap = _mod("c", "capability", {"refund": _allow()}, consts={"cap": 1000})
    effective, _ = link([guard], [cap])
    assert effective.consts["cap"] == 1000


def test_file_scope_in_module_raises():
    """file_scope can't survive composition yet — fail loud, don't silently drop."""
    from hexgate.security import FileScope, FileToolPolicy

    guard = _mod(
        "g",
        "boundary",
        {
            "write_file": FileToolPolicy(
                mode="allow", file_scope=FileScope(allowed_paths=["/tmp/**"])
            )
        },
    )
    with pytest.raises(LinkError, match="file_scope"):
        link([guard], [])


def test_boundary_agents_deny_composes_as_authoritative_deny() -> None:
    # An ``agents`` block lowers to agent.* keys the fold composes like tools
    # (R-AGENT-002). A boundary agent-deny is authoritative — it folds to a hard
    # deny on the lowered reach key, exactly as a boundary tool deny would.
    boundary = ModuleContent(
        name="b",
        kind="boundary",
        policy=AgentPolicy(agents={"evil-bot": {"mode": "deny"}}),
        source="b.yaml",
        content_hash="hash-b",
    )
    effective, _ = link([boundary], [])
    denied = effective.effective_tools["agent.handoff:evil-bot"]
    assert denied.mode == "deny"


def test_capability_admission_grant_composes() -> None:
    # A capability may grant admission: an ``admission`` block lowers to agent.run,
    # which the fold unions like any other capability grant.
    cap = ModuleContent(
        name="c",
        kind="capability",
        policy=AgentPolicy(admission={"mode": "allow"}),
        source="c.yaml",
        content_hash="hash-c",
    )
    effective, _ = link([], [cap])
    assert effective.effective_tools["agent.run"].mode == "allow"


def test_capability_agents_deny_is_a_link_error() -> None:
    # Capabilities grant only, agent keys included: a capability that denies a
    # lowered agent key is a config error, same as a capability tool deny.
    cap = ModuleContent(
        name="c",
        kind="capability",
        policy=AgentPolicy(agents={"evil-bot": {"mode": "deny"}}),
        source="c.yaml",
        content_hash="hash-c",
    )
    with pytest.raises(LinkError, match=r"agent\.handoff:evil-bot"):
        link([], [cap])


# --- provenance + policy-set wiring ---


def test_provenance_records_contributing_layers(floor_bundle):
    _, trace = link(*floor_bundle)
    contributors = {p.module for p in trace.contributors["refund_order"]}
    assert contributors == {"org.core", "payments"}


def test_link_policy_set_merges_consts_and_builds_default_role():
    guard = _mod(
        "g",
        "boundary",
        {"refund": _allow(["args.amount <= consts.cap"])},
        consts={"cap": 1000},
    )
    grant = _mod("c", "capability", {"refund": _allow()})
    result = link_policy_set([guard], [grant])
    assert "default" in result.policy_set.roles
    assert result.effective["default"].consts == {"cap": 1000}
    # const-ref validation (PolicySet construction) didn't reject it.
    assert (
        result.policy_set.evaluate(
            role="default", tool="refund", args={"amount": 500}
        ).outcome
        is DecisionOutcome.ALLOW
    )


# --- parity: the resolved policy evaluates identically on both engines ---


@needs_opa
def test_resolved_policy_parity_pydantic_vs_wasm(floor_bundle):
    """Resolve → compile → wasm must agree with the pydantic engine, so the
    linker's assembled constraints (nested parens, top-level OR, `not(...)`)
    survive the Rego/WASM round-trip."""
    from hexgate.security import (
        compile_to_rego,
        compile_to_wasm,
        verdict_from_rego,
    )
    from hexgate.security.wasm_engine import WasmPolicy

    result = link_policy_set(*floor_bundle)
    payload = result.effective["default"].model_dump(mode="json")
    wasm = compile_to_wasm(compile_to_rego(payload)).wasm
    engine = WasmPolicy.from_bytes(wasm)

    cases = [
        ("refund_order", {"amount": 800, "currency": "USD"}),
        ("refund_order", {"amount": 1200, "currency": "USD"}),
        ("refund_order", {"amount": 800, "currency": "GBP"}),
        ("delete_database", {}),
        ("lookup_order", {}),
        ("send_email", {}),
    ]
    for tool, args in cases:
        pyd = result.policy_set.evaluate(role="default", tool=tool, args=args)
        wsm = verdict_from_rego(
            engine.decide(role="default", tool=tool, args=args),
            tool_name=tool,
            role="default",
        )
        assert pyd.outcome is wsm.outcome, (tool, args)


# --- resolve_for_project: roles as capability bindings ---------------------


def test_resolve_folds_each_role_independently():
    # Floor boundary caps refund at <= 100 for every role.
    org = _mod("org", "boundary", {"refund": _allow(["args.amount <= 100"])})
    read_only = _mod("read_only", "capability", {"view": _allow()})
    payments = _mod("payments", "capability", {"refund": _allow()})

    result = resolve_for_project(
        [org],
        [read_only, payments],
        {"default": ["read_only"], "billing": ["read_only", "payments"]},
    )

    assert set(result.by_role) == {"default", "billing"}
    default_pol = result.policy_set.policy_for("default")
    billing_pol = result.policy_set.policy_for("billing")
    # default imports read_only only -> no refund grant.
    assert "view" in default_pol.tools
    assert "refund" not in default_pol.tools
    # billing imports payments too -> refund granted, capped by the boundary.
    assert billing_pol.tools["refund"].mode == "allow"
    assert "args.amount <= 100" in billing_pol.tools["refund"].constraints


def test_boundary_applies_to_every_role():
    # An unconditional boundary deny wins in every role, regardless of imports.
    org = _mod("org", "boundary", {"delete": _deny()})
    cap = _mod("c", "capability", {"delete": _allow(), "x": _allow()})

    result = resolve_for_project([org], [cap], {"r1": ["c"], "r2": ["c"]})

    for role in ("r1", "r2"):
        assert result.policy_set.policy_for(role).tools["delete"].mode == "deny"


def test_unknown_capability_in_a_role_raises_link_error():
    cap = _mod("c", "capability", {"x": _allow()})
    with pytest.raises(LinkError, match="unknown capability"):
        resolve_for_project([], [cap], {"r": ["missing"]})


def test_none_roles_means_one_default_importing_everything():
    # None == "no roles.yaml" -> all-compose back-compat.
    caps = [
        _mod("a", "capability", {"x": _allow()}),
        _mod("b", "capability", {"y": _allow()}),
    ]
    result = resolve_for_project([], caps, None)

    assert result.policy_set.roles == ["default"]
    tools = result.policy_set.policy_for("default").tools
    assert {"x", "y"} <= set(tools)


def test_empty_roles_is_fail_closed_not_all_compose():
    # {} == "roles.yaml present but binds nothing" -> fail-closed empty default,
    # NOT all-compose. This is the fix for a typo'd roles: key widening access.
    caps = [_mod("a", "capability", {"x": _allow()})]
    result = resolve_for_project([], caps, {})

    assert result.policy_set.roles == ["default"]
    assert result.policy_set.policy_for("default").tools == {}


def test_unbound_capability_deny_is_rejected():
    # A capability that denies must fail even when no role imports it — validated
    # over the whole library, not just the folded-in modules.
    good = _mod("good", "capability", {"x": _allow()})
    bad = _mod("bad", "capability", {"refund": _deny()})
    with pytest.raises(LinkError, match="capabilities may only grant"):
        resolve_for_project([], [good, bad], {"r": ["good"]})


def test_default_role_synthesised_when_absent_is_deny_all():
    # roles.yaml with no `default` -> an empty default so unroled callers get
    # fail-closed deny, not a missing bucket.
    cap = _mod("c", "capability", {"x": _allow()})
    result = resolve_for_project([], [cap], {"billing": ["c"]})

    assert "default" in result.by_role
    assert result.policy_set.policy_for("default").tools == {}
    assert "x" in result.policy_set.policy_for("billing").tools
