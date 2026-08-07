"""Signed trusted-attribute (ABAC) tier — the enforcer prefers token-verified
attribute values over the spoofable ``HexgateContext.attributes`` bag for keys a
policy declares ``trusted_attributes``, and fails closed when a trusted key the
policy references is absent from the verified token.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from hexgate.runtime.context import (
    HexgateContext,
    ToolUseContext,
    reset_current_tool_use_context,
    set_current_tool_use_context,
)
from hexgate.security.bundle import PolicyBundle, build_signed_bundle
from hexgate.security.decision import DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.models import AgentPolicy, BaseToolPolicy
from hexgate.security.policy_set import load_policy_map, load_policy_set


# ---------------------------------------------------------------------------
# Declaration + inheritance (model / PolicySet)
# ---------------------------------------------------------------------------


def test_agent_policy_trusted_attributes_defaults_empty() -> None:
    assert AgentPolicy().trusted_attributes == []


def test_policy_set_trusted_attributes_is_union_across_roles() -> None:
    ps = load_policy_map(
        {
            "default": AgentPolicy(trusted_attributes=["department"]),
            "billing": AgentPolicy(trusted_attributes=["clearance_level"]),
        }
    )
    assert ps.trusted_attributes == frozenset({"department", "clearance_level"})


def test_trusted_attributes_merge_through_inheritance() -> None:
    ps = load_policy_map(
        {
            "base": AgentPolicy(is_mixin=True, trusted_attributes=["clearance_level"]),
            "billing": AgentPolicy(inherits=["base"], trusted_attributes=["region"]),
            "default": AgentPolicy(),
        }
    )
    resolved = ps.policy_for("billing")
    assert set(resolved.trusted_attributes) == {"clearance_level", "region"}


# ---------------------------------------------------------------------------
# Enforcer resolution — the trust core
# ---------------------------------------------------------------------------


def _enforcer_with_ctx_rule() -> PolicyEnforcer:
    """Enforcer whose ``refund`` tool allows only when ctx.clearance_level >= 3,
    with ``clearance_level`` declared trusted."""
    policy = AgentPolicy(
        trusted_attributes=["clearance_level"],
        tools={
            "refund": BaseToolPolicy(
                mode="allow", constraints=["ctx.clearance_level >= 3"]
            )
        },
    )
    return PolicyEnforcer(load_policy_set(policy), agent_name="t")


@contextmanager
def _scope(
    *, attributes: dict, verified: dict | None, self_asserted: bool = False
) -> Iterator[None]:
    """Enter a HexgateContext scope + install a verified-attribute tool context."""
    with HexgateContext(
        user_id="u", user_roles=["default"], attributes=attributes
    ).sync_scope():
        token = set_current_tool_use_context(
            ToolUseContext(
                verified_attributes=verified, attributes_self_asserted=self_asserted
            )
        )
        try:
            yield
        finally:
            reset_current_tool_use_context(token)


def test_spoofed_advisory_value_is_dropped_without_a_token() -> None:
    """A trusted key set only on the (spoofable) contextvar fails closed."""
    enf = _enforcer_with_ctx_rule()
    with _scope(attributes={"clearance_level": 99}, verified=None):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.DENY


def test_verified_value_authorizes() -> None:
    """A trusted key carried in the verified token drives the allow."""
    enf = _enforcer_with_ctx_rule()
    with _scope(attributes={}, verified={"clearance_level": 5}):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.ALLOW


def test_verified_value_wins_over_spoofed_advisory() -> None:
    """When both are present for a trusted key, only the verified value counts."""
    enf = _enforcer_with_ctx_rule()
    with _scope(attributes={"clearance_level": 99}, verified={"clearance_level": 1}):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.DENY


def test_trusted_key_absent_from_token_fails_closed() -> None:
    """A constraint on a trusted key not in the token denies (missing → deny)."""
    enf = _enforcer_with_ctx_rule()
    with _scope(attributes={}, verified={"unrelated": "x"}):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.DENY


def test_advisory_attribute_still_read_from_contextvar() -> None:
    """A non-trusted ctx key keeps its advisory (contextvar) value — unchanged
    from the pre-signed behavior."""
    policy = AgentPolicy(
        tools={
            "refund": BaseToolPolicy(
                mode="allow", constraints=['ctx.department == "finance"']
            )
        },
    )
    enf = PolicyEnforcer(load_policy_set(policy), agent_name="t")
    with _scope(attributes={"department": "finance"}, verified=None):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.ALLOW
    with _scope(attributes={"department": "sales"}, verified=None):
        assert enf.decide("refund", {}).outcome is DecisionOutcome.DENY


def test_decision_snapshot_carries_resolved_attributes() -> None:
    """Decision.attributes reflects the resolved (verified) bag, not the spoof."""
    enf = _enforcer_with_ctx_rule()
    with _scope(attributes={"clearance_level": 99}, verified={"clearance_level": 5}):
        decision = enf.decide("refund", {})
    assert decision.attributes == {"clearance_level": 5}


# ---------------------------------------------------------------------------
# Audit provenance — self-minted values are not audited as verified
# ---------------------------------------------------------------------------


class _CapturingSender:
    def __init__(self) -> None:
        self.events: list = []

    def emit(self, event) -> None:  # noqa: ANN001
        self.events.append(event)


def test_audit_marks_self_minted_trusted_attribute_as_self_asserted() -> None:
    """A trusted value the SDK signed in-process (self_asserted tool context) is
    audited as ``self_asserted``, never ``verified`` — the overclaim fix."""
    sender = _CapturingSender()
    enf = PolicyEnforcer(
        load_policy_set(
            AgentPolicy(
                trusted_attributes=["clearance_level"],
                tools={"refund": BaseToolPolicy(mode="allow")},
            )
        ),
        agent_name="t",
        audit_sender=sender,
    )
    with _scope(
        attributes={"clearance_level": 5},
        verified={"clearance_level": 5},
        self_asserted=True,
    ):
        enf.decide("refund", {})
    snapshot = sender.events[0].as_payload()["attributes"]
    assert snapshot["clearance_level"]["provenance"] == "self_asserted"


def test_audit_marks_externally_verified_trusted_attribute_as_verified() -> None:
    """The same value from an externally-supplied token (self_asserted=False) is
    audited as ``verified``."""
    sender = _CapturingSender()
    enf = PolicyEnforcer(
        load_policy_set(
            AgentPolicy(
                trusted_attributes=["clearance_level"],
                tools={"refund": BaseToolPolicy(mode="allow")},
            )
        ),
        agent_name="t",
        audit_sender=sender,
    )
    with _scope(
        attributes={},
        verified={"clearance_level": 5},
        self_asserted=False,
    ):
        enf.decide("refund", {})
    snapshot = sender.events[0].as_payload()["attributes"]
    assert snapshot["clearance_level"]["provenance"] == "verified"


# ---------------------------------------------------------------------------
# WASM bundle manifest carries the declaration (metadata only)
# ---------------------------------------------------------------------------


def test_build_signed_bundle_records_trusted_attributes_in_manifest() -> None:
    """The declaration travels in the manifest so the WASM path can resolve it.

    Uses --no-wasm so the test doesn't require opa; the manifest is built
    regardless of the wasm step."""
    yaml = (
        "tools:\n"
        "  refund:\n"
        "    mode: allow\n"
        "    constraints:\n"
        '      - "ctx.clearance_level >= 3"\n'
        "trusted_attributes:\n"
        "  - clearance_level\n"
    )
    bundle = build_signed_bundle(yaml, compile_wasm=False)
    assert bundle.manifest["trusted_attributes"] == ["clearance_level"]


def test_policy_bundle_exposes_trusted_attributes_from_manifest() -> None:
    import json

    manifest = {"version": 1, "wasm_hash": "x", "trusted_attributes": ["region"]}
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    bundle = PolicyBundle.from_parts(wasm_bytes=b"\x00", manifest_bytes=manifest_bytes)
    assert bundle.trusted_attributes == frozenset({"region"})


def test_policy_bundle_without_field_is_all_advisory() -> None:
    import json

    manifest_bytes = json.dumps({"version": 1, "wasm_hash": "x"}).encode("utf-8")
    bundle = PolicyBundle.from_parts(wasm_bytes=b"\x00", manifest_bytes=manifest_bytes)
    assert bundle.trusted_attributes == frozenset()
