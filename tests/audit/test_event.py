"""AuditEvent.as_payload() field mapping for the platform's audit endpoint."""

from __future__ import annotations

import json

from hexgate.audit import MAX_ARGS_BYTES, AuditEvent
from hexgate.security.decision import Decision, DecisionOutcome


def _decision(**overrides) -> Decision:
    base = dict(
        outcome=DecisionOutcome.DENY, agent_name="example_agent", tool_name="read_file"
    )
    return Decision(**{**base, **overrides})


def test_as_payload_full_payload() -> None:
    d = _decision(
        role="analyst",
        reason="denied for path",
        error_type="policy_denied",
        hint={"glob": "/x/**"},
        violations=("v1", "v2"),
        arguments={"path": "/etc/passwd"},
    )
    ev = AuditEvent(decision=d, user_id="alice", session_id="sess_1")
    wire = ev.as_payload()

    assert wire["event_id"] == str(ev.event_id)
    assert wire["occurred_at"] == ev.occurred_at.isoformat()
    assert wire["agent_name"] == "example_agent"
    assert wire["tool_name"] == "read_file"
    assert wire["outcome"] == "deny"
    assert wire["role"] == "analyst"
    assert wire["error_type"] == "policy_denied"
    assert wire["reason"] == "denied for path"
    assert wire["violations"] == ["v1", "v2"]
    assert wire["hint"] == {"glob": "/x/**"}
    assert wire["arguments"] == {"path": "/etc/passwd"}
    assert wire["user_id"] == "alice"
    assert wire["session_id"] == "sess_1"


def test_as_payload_server_resolved_fields_absent() -> None:
    """project_id, agent_version_id, received_at are server-resolved or server-stamped."""
    wire = AuditEvent(decision=_decision()).as_payload()
    assert "project_id" not in wire
    assert "agent_version_id" not in wire
    assert "received_at" not in wire


def test_as_payload_none_normalizes_to_empty_string() -> None:
    d = _decision(role=None, error_type=None)
    wire = AuditEvent(decision=d).as_payload()  # user_id/session_id default to ""
    assert wire["role"] == ""
    assert wire["error_type"] == ""
    assert wire["user_id"] == ""
    assert wire["session_id"] == ""


def test_as_payload_violations_tuple_serializes_as_list() -> None:
    """Decision.violations is tuple[str, ...] but the wire payload is a list."""
    wire = AuditEvent(decision=_decision(violations=("a", "b", "c"))).as_payload()
    assert wire["violations"] == ["a", "b", "c"]
    assert isinstance(wire["violations"], list)


def test_as_payload_redacts_sensitive_keys_recursively() -> None:
    args = {
        "path": "/x",
        "Password": "hunter2",
        "config": {"api_key": "sk-123", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "Bearer abc"}, {"trace": "t1"}],
    }
    wire = AuditEvent(decision=_decision(arguments=args)).as_payload()
    assert wire["arguments"] == {
        "path": "/x",
        "Password": "[REDACTED]",
        "config": {"api_key": "[REDACTED]", "mode": "safe"},
        "headers": [{"AUTHORIZATION": "[REDACTED]"}, {"trace": "t1"}],
    }


def test_as_payload_redaction_does_not_mutate_decision_arguments() -> None:
    d = _decision(arguments={"secret": "s3cr3t", "nested": {"token": "t"}})
    AuditEvent(decision=d).as_payload()
    assert d.arguments == {"secret": "s3cr3t", "nested": {"token": "t"}}


def test_as_payload_truncates_oversize_arguments_under_platform_cap() -> None:
    big = {"data": "x" * (MAX_ARGS_BYTES * 2)}
    wire = AuditEvent(decision=_decision(arguments=big)).as_payload()
    args = wire["arguments"]
    assert args["_truncated"] is True
    assert args["original_bytes"] > MAX_ARGS_BYTES
    assert args["preview"].startswith('{"data": "xxx')
    # The wire form must fit the platform cap, measured as the platform does.
    assert len(json.dumps(args, default=str).encode("utf-8")) <= MAX_ARGS_BYTES


def test_as_payload_small_arguments_pass_through_untruncated() -> None:
    wire = AuditEvent(decision=_decision(arguments={"path": "/x"})).as_payload()
    assert wire["arguments"] == {"path": "/x"}


def test_event_id_and_occurred_at_unique_per_event() -> None:
    w1 = AuditEvent(decision=_decision()).as_payload()
    w2 = AuditEvent(decision=_decision()).as_payload()
    assert w1["event_id"] != w2["event_id"]
    assert "+00:00" in w1["occurred_at"]


# ---------------------------------------------------------------------------
# Attribute snapshot (signed trusted-attribute tier)
# ---------------------------------------------------------------------------


def test_as_payload_omits_attributes_when_none() -> None:
    ev = AuditEvent(decision=_decision())
    assert ev.as_payload()["attributes"] is None


def test_as_payload_marks_verified_trusted_attribute() -> None:
    """A trusted key from an externally-verified token → provenance verified;
    a non-trusted key → advisory."""
    d = _decision(attributes={"clearance_level": 5, "department": "finance"})
    ev = AuditEvent(
        decision=d,
        trusted_attributes=frozenset({"clearance_level"}),
        attributes_self_asserted=False,
    )
    assert ev.as_payload()["attributes"] == {
        "clearance_level": {"value": 5, "provenance": "verified"},
        "department": {"value": "finance", "provenance": "advisory"},
    }


def test_as_payload_marks_self_minted_trusted_attribute_as_self_asserted() -> None:
    """A trusted key whose value was signed in-process from the contextvar is
    NOT audited as verified — it's self_asserted (the reviewer's overclaim fix)."""
    d = _decision(attributes={"clearance_level": 5})
    ev = AuditEvent(
        decision=d,
        trusted_attributes=frozenset({"clearance_level"}),
        attributes_self_asserted=True,
    )
    assert ev.as_payload()["attributes"] == {
        "clearance_level": {"value": 5, "provenance": "self_asserted"}
    }


def test_as_payload_redacts_sensitive_attribute_keys() -> None:
    d = _decision(attributes={"api_key": "sk-secret", "region": "EU"})
    ev = AuditEvent(decision=d)
    snapshot = ev.as_payload()["attributes"]
    assert snapshot["api_key"]["value"] == "[REDACTED]"
    assert snapshot["region"]["value"] == "EU"
