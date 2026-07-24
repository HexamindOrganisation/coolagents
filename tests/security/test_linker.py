"""Tests for the policy linker — composing a module bundle into one policy.

The fold is the crown jewel, so these are pure (no opa needed) except the final
parity test. Fixtures mirror ``policy-modules-plan.md``'s worked example, with
the two guardrail postures kept internally consistent:

- **floor** guardrail (``default_policy: allow``) — only subtracts what it names;
  unlisted tools pass through to capabilities.
- **ceiling** guardrail (``default_policy: deny``) — a tool it doesn't list is
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


# --- floor guardrail: the worked-example table (unlisted tools pass through) ---


@pytest.fixture
def floor_bundle():
    guardrail = _mod(
        "org.core",
        "guardrail",
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
    return [guardrail], [payments, leaf]


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


# --- ceiling guardrail: a tool it doesn't list is ineligible ---


def test_ceiling_gates_eligibility_and_records_shadow():
    ceiling = _mod(
        "org.ceiling",
        "guardrail",
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


def test_two_guardrails_intersect_stricter_cap():
    """Two ceilings on one tool intersect: the stricter bound wins."""
    g1 = _mod("g1", "guardrail", {"refund": _allow(["args.amount <= 1000"])})
    g2 = _mod("g2", "guardrail", {"refund": _allow(["args.amount <= 500"])})
    grant = _mod("cap", "capability", {"refund": _allow()})
    effective, _ = link([g1, g2], [grant])

    assert evaluate_tool_call(effective, "refund", {"amount": 400}).outcome is (
        DecisionOutcome.ALLOW
    )
    assert evaluate_tool_call(effective, "refund", {"amount": 700}).outcome is (
        DecisionOutcome.DENY  # over the stricter 500 cap
    )


def test_unconditional_guardrail_deny_is_absolute():
    """A guardrail deny beats any capability grant."""
    guard = _mod("g", "guardrail", {"wire": _deny()}, default_mode="allow")
    grant = _mod("c", "capability", {"wire": _allow()})
    effective, _ = link([guard], [grant])
    assert evaluate_tool_call(effective, "wire", {}).outcome is DecisionOutcome.DENY


def test_conditional_guardrail_deny_subtracts_region():
    """A guardrail deny WITH constraints subtracts that region from the grant."""
    guard = _mod(
        "g",
        "guardrail",
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


# --- provenance + policy-set wiring ---


def test_provenance_records_contributing_layers(floor_bundle):
    _, trace = link(*floor_bundle)
    contributors = {p.module for p in trace.contributors["refund_order"]}
    assert contributors == {"org.core", "payments"}


def test_link_policy_set_merges_consts_and_builds_default_role():
    guard = _mod(
        "g",
        "guardrail",
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
