"""LlmUsageEvent.as_payload() field mapping for the platform's llm-invocations endpoint."""

from __future__ import annotations

from hexgate.tracing.usage import LlmUsageEvent


def _event(**overrides) -> LlmUsageEvent:
    base = dict(
        agent_name="example_agent",
        model="gpt-4o",
        input_tokens=100,
        output_tokens=50,
        latency_ms=250,
        status="success",
    )
    return LlmUsageEvent(**{**base, **overrides})


def test_as_payload_happy_path() -> None:
    ev = _event(session_id="sess_1", user_id="alice", error_code=None)
    wire = ev.as_payload()

    assert wire["event_id"] == str(ev.event_id)
    assert wire["occurred_at"] == ev.occurred_at.isoformat()
    assert wire["agent_name"] == "example_agent"
    assert wire["session_id"] == "sess_1"
    assert wire["user_id"] == "alice"
    assert wire["model"] == "gpt-4o"
    assert wire["input_tokens"] == 100
    assert wire["output_tokens"] == 50
    assert wire["latency_ms"] == 250
    assert wire["status"] == "success"
    assert wire["error_code"] == ""
    # project_id, agent_version_id, received_at are server-resolved and must
    # never be sent on the wire — see AuditEnvelope on the platform side.
    assert "project_id" not in wire
    assert "agent_version_id" not in wire
    assert "received_at" not in wire


def test_as_payload_when_optional_fields_omitted_then_defaults_are_used() -> None:
    wire = _event().as_payload()  # session_id/user_id/error_code left at defaults
    assert wire["session_id"] == ""
    assert wire["user_id"] == ""
    assert wire["error_code"] == ""


def test_as_payload_when_error_code_is_none_then_it_is_stringified_to_empty() -> None:
    """The platform's error_code column is a plain str (default ""), not
    Optional — None must never reach the wire or ingest 422s."""
    wire = _event(error_code=None).as_payload()
    assert wire["error_code"] == ""


def test_as_payload_when_status_is_error_then_error_code_is_included() -> None:
    wire = _event(status="error", error_code="rate_limited").as_payload()
    assert wire["status"] == "error"
    assert wire["error_code"] == "rate_limited"


def test_event_id_defaults_to_a_stringified_uuid_and_is_unique_per_event() -> None:
    """event_id defaults via uuid4 (mirrors AuditEvent) rather than requiring
    the caller to generate one; as_payload() stringifies it for the wire."""
    ev1, ev2 = _event(), _event()

    assert ev1.event_id != ev2.event_id
    assert ev1.as_payload()["event_id"] == str(ev1.event_id)


def test_as_payload_when_occurred_at_defaults_then_occurred_at_has_utc_offset() -> None:
    wire = _event().as_payload()
    assert "+00:00" in wire["occurred_at"]


def test_as_payload_sends_null_run_id_never_empty_string() -> None:
    """An empty string is not a UUID: the platform 422s and the sender drops
    it, losing the record for every model call made outside a run scope."""
    assert _event().as_payload()["run_id"] is None


def test_as_payload_carries_the_run_id_when_inside_a_run() -> None:
    wire = _event(run_id="9c2f1d3e-0000-4000-8000-000000000001").as_payload()

    assert wire["run_id"] == "9c2f1d3e-0000-4000-8000-000000000001"
