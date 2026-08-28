"""AuditSender behavior: one event in → one finished OTel span out, laid
out per ``hexgate.tracing.semconv``. Captures spans with an in-memory
exporter injected through the constructor's test seam, so nothing touches
the network.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

from hexgate.audit import AuditEvent
from hexgate.security.bans import BanEnforcementEvent
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing import semconv
from hexgate.tracing._senders import AuditSender, _unix_nanos
from hexgate.tracing.usage import LlmUsageEvent


def _event(**overrides) -> AuditEvent:
    d = Decision(outcome=DecisionOutcome.DENY, agent_name="r", tool_name="t")
    return AuditEvent(decision=d, user_id="u", session_id="s", **overrides)


def _sender() -> tuple[AuditSender, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    sender = AuditSender(
        endpoint="https://example.invalid/v1/traces", api_key="k", exporter=exporter
    )
    return sender, exporter


def _flush(sender: AuditSender) -> None:
    assert sender._provider.force_flush(timeout_millis=2_000)


# ---------------------------------------------------------------------------
# emit(): span shape
# ---------------------------------------------------------------------------


def test_emit_happy_path() -> None:
    sender, exporter = _sender()
    ev = _event()

    sender.emit(ev)
    _flush(sender)

    (span,) = exporter.get_finished_spans()
    assert span.instrumentation_scope.name == semconv.SCOPE_AUDIT
    assert span.attributes[semconv.EVENT_ID] == str(ev.event_id)
    assert span.attributes[semconv.TOOL_NAME] == "t"
    assert span.attributes[semconv.OUTCOME] == "deny"


def test_emit_uses_occurred_at_as_start_and_end_time() -> None:
    """The enricher reads ``occurred_at`` from ``start_time_unix_nano``;
    these are point-in-time events, so start == end."""
    at = datetime(2026, 8, 28, 12, 0, 0, 123456, tzinfo=timezone.utc)
    sender, exporter = _sender()

    sender.emit(_event(occurred_at=at))
    _flush(sender)

    (span,) = exporter.get_finished_spans()
    assert span.start_time == _unix_nanos(at)
    assert span.end_time == span.start_time
    assert span.start_time == 1_787_918_400_123_456_000


def test_emit_selects_the_tracer_by_event_scope() -> None:
    sender, exporter = _sender()

    sender.emit(_event())
    sender.emit(
        LlmUsageEvent(
            agent_name="a",
            model="m",
            input_tokens=1,
            output_tokens=2,
            latency_ms=3,
            status="success",
        )
    )
    sender.emit(BanEnforcementEvent(ban_type="agent", ban_id="b", agent_name="a"))
    _flush(sender)

    scopes = [s.instrumentation_scope.name for s in exporter.get_finished_spans()]
    assert scopes == [semconv.SCOPE_AUDIT, semconv.SCOPE_USAGE, semconv.SCOPE_BANS]


def test_emit_span_is_a_root_span_even_inside_a_callers_active_span() -> None:
    """A customer's own OTel tracing must not become our span's parent —
    otherwise their sampling decision would apply to our audit events."""
    sender, exporter = _sender()
    # An active span in the current context is what start_span() would pick
    # up as the parent by default — regardless of which provider made it.
    caller_exporter = InMemorySpanExporter()
    caller_provider = TracerProvider()
    caller_provider.add_span_processor(SimpleSpanProcessor(caller_exporter))
    with caller_provider.get_tracer("customer").start_as_current_span("outer") as outer:
        sender.emit(_event())
    _flush(sender)

    (span,) = exporter.get_finished_spans()
    assert span.parent is None
    assert span.context.trace_id != outer.get_span_context().trace_id


def test_emit_is_always_sampled() -> None:
    sender, exporter = _sender()
    sender.emit(_event())
    _flush(sender)
    (span,) = exporter.get_finished_spans()
    assert span.context.trace_flags.sampled


def test_emit_from_a_plain_thread_with_no_event_loop_is_exported() -> None:
    """No event-loop affinity: a purely synchronous caller (pydantic_ai's
    ``run_sync()``, a background worker thread) enqueues like any other."""
    sender, exporter = _sender()

    t = threading.Thread(target=sender.emit, args=(_event(),))
    t.start()
    t.join()
    _flush(sender)

    assert len(exporter.get_finished_spans()) == 1


def test_emit_when_the_dict_fields_are_set_then_they_travel_as_json_strings() -> None:
    d = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="r",
        tool_name="t",
        arguments={"path": "/x"},
        hint={"glob": "/x/**"},
    )
    sender, exporter = _sender()
    sender.emit(AuditEvent(decision=d))
    _flush(sender)

    (span,) = exporter.get_finished_spans()
    assert span.attributes[semconv.ARGUMENTS] == '{"path": "/x"}'
    assert span.attributes[semconv.HINT] == '{"glob": "/x/**"}'
    assert semconv.ATTRIBUTES not in span.attributes  # unset → absent, not null


def test_emit_list_fields_travel_as_native_string_arrays() -> None:
    d = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="r",
        tool_name="t",
        user_roles=("a", "b"),
        violations=("v1",),
    )
    sender, exporter = _sender()
    sender.emit(AuditEvent(decision=d))
    _flush(sender)

    (span,) = exporter.get_finished_spans()
    assert span.attributes[semconv.USER_ROLES] == ("a", "b")
    assert span.attributes[semconv.VIOLATIONS] == ("v1",)


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


async def test_close_flushes_queued_spans_then_stops_the_provider() -> None:
    sender, exporter = _sender()
    sender.emit(_event())

    await sender.close()

    assert len(exporter.get_finished_spans()) == 1
    assert exporter._stopped  # provider.shutdown() reached the exporter


async def test_post_close_emit_is_noop() -> None:
    sender, exporter = _sender()
    await sender.close()

    sender.emit(_event())

    assert exporter.get_finished_spans() == ()


async def test_close_is_idempotent() -> None:
    sender, _ = _sender()
    await sender.close()
    await sender.close()  # OTel's own guard makes this a logged no-op


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


@pytest.mark.real_span_exporter
def test_constructor_builds_an_otlp_http_exporter_bearing_the_key() -> None:
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

    sender = AuditSender(endpoint="https://collector.example/v1/traces", api_key="k1")
    try:
        exporter = sender._processor.span_exporter
        assert isinstance(exporter, OTLPSpanExporter)
        assert exporter._endpoint == "https://collector.example/v1/traces"
        assert exporter._headers["Authorization"] == "Bearer k1"
        assert exporter._timeout == 5.0
    finally:
        sender._provider.shutdown()


def test_unix_nanos_keeps_microsecond_precision() -> None:
    at = datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=timezone.utc)
    assert _unix_nanos(at) % 1_000_000_000 == 999_999_000
