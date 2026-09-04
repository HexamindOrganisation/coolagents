"""LlmUsageEvent.span_attributes() — the usage span's attribute layout per
``hexgate.tracing.semconv``: official ``gen_ai.*`` names where they exist,
``sec_ai.*`` for the rest."""

from __future__ import annotations

from hexgate.tracing import semconv
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


def test_span_attributes_happy_path() -> None:
    ev = _event(session_id="sess_1", user_id="alice", error_code=None)
    wire = ev.span_attributes()

    assert LlmUsageEvent.SCOPE == semconv.SCOPE_USAGE
    assert wire[semconv.EVENT_ID] == str(ev.event_id)
    assert wire[semconv.AGENT_NAME] == "example_agent"
    assert wire[semconv.SESSION_ID] == "sess_1"
    assert wire[semconv.USER_ID] == "alice"
    assert wire[semconv.GEN_AI_REQUEST_MODEL] == "gpt-4o"
    assert wire[semconv.GEN_AI_USAGE_INPUT_TOKENS] == 100
    assert wire[semconv.GEN_AI_USAGE_OUTPUT_TOKENS] == 50
    assert wire[semconv.LATENCY_MS] == 250
    assert wire[semconv.STATUS] == "success"
    assert wire[semconv.ERROR_CODE] == ""
    # occurred_at is the span start time; project_id, agent_version_id,
    # received_at are server-resolved — none of them is an attribute.
    assert not any("occurred_at" in k for k in wire)
    assert not any("project_id" in k for k in wire)
    assert not any("agent_version" in k for k in wire)
    assert not any("received_at" in k for k in wire)


def test_span_attributes_token_counts_stay_integers() -> None:
    """The enricher reads ``AnyValue.int_value``; a stringified count would
    only be accepted with a coercion warning."""
    wire = _event().span_attributes()
    assert type(wire[semconv.GEN_AI_USAGE_INPUT_TOKENS]) is int
    assert type(wire[semconv.GEN_AI_USAGE_OUTPUT_TOKENS]) is int
    assert type(wire[semconv.LATENCY_MS]) is int


def test_span_attributes_when_optional_fields_omitted_then_defaults_are_used() -> None:
    wire = _event().span_attributes()  # session_id/user_id/error_code left at defaults
    assert wire[semconv.SESSION_ID] == ""
    assert wire[semconv.USER_ID] == ""
    assert wire[semconv.ERROR_CODE] == ""


def test_span_attributes_when_error_code_is_none_then_it_is_stringified_to_empty() -> (
    None
):
    """The platform's error_code column is a plain str (default ""), not
    Optional — and OTel attributes can't carry None anyway."""
    wire = _event(error_code=None).span_attributes()
    assert wire[semconv.ERROR_CODE] == ""


def test_span_attributes_when_status_is_error_then_error_code_is_included() -> None:
    wire = _event(status="error", error_code="rate_limited").span_attributes()
    assert wire[semconv.STATUS] == "error"
    assert wire[semconv.ERROR_CODE] == "rate_limited"


def test_event_id_defaults_to_a_stringified_uuid_and_is_unique_per_event() -> None:
    """event_id defaults via uuid4 (mirrors AuditEvent) rather than requiring
    the caller to generate one; span_attributes() stringifies it."""
    ev1, ev2 = _event(), _event()

    assert ev1.event_id != ev2.event_id
    assert ev1.span_attributes()[semconv.EVENT_ID] == str(ev1.event_id)


def test_occurred_at_defaults_to_an_aware_utc_datetime() -> None:
    ev = _event()
    assert ev.occurred_at.utcoffset() is not None
    assert ev.occurred_at.utcoffset().total_seconds() == 0


def test_span_attributes_omit_run_id_never_send_it_empty() -> None:
    """An empty string is not a UUID: the enricher's validation fails and the
    span is DLQ'd, losing the record for every model call outside a run scope."""
    assert semconv.RUN_ID not in _event().span_attributes()


def test_span_attributes_carry_the_run_id_when_inside_a_run() -> None:
    wire = _event(run_id="9c2f1d3e-0000-4000-8000-000000000001").span_attributes()

    assert wire[semconv.RUN_ID] == "9c2f1d3e-0000-4000-8000-000000000001"
