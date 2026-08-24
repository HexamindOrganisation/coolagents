"""mapping.py — span → validated event, per the semconv wire contract."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.coerce import SpanRejected
from hexgate_api.jobs.enricher.mapping import map_span
from hexgate_api.schemas import BanEnforcementEvent, DecisionEvent, LlmInvocationEvent
from tests.jobs.enricher.conftest import (
    ban_attrs,
    decision_attrs,
    make_span,
    usage_attrs,
)


def test_map_span_decision_happy_path() -> None:
    # 1.5ms past the second — must survive into DateTime64(3) precision.
    start_ns = (int(time.time()) - 60) * 10**9 + 1_500_000
    attrs = decision_attrs(
        **{
            semconv.USER_ROLES: ["admin", "dev"],
            semconv.DECIDING_ROLE: "admin",
            semconv.REASON: "matched allow rule",
            semconv.VIOLATIONS: ["v1"],
            semconv.ARGUMENTS: json.dumps({"query": "hello"}),
            semconv.SESSION_ID: "sess_1",
            semconv.USER_ID: "user_1",
        }
    )
    event = map_span(semconv.SCOPE_AUDIT, make_span(attrs, start_ns=start_ns), {})

    assert isinstance(event, DecisionEvent)
    assert str(event.event_id) == attrs[semconv.EVENT_ID]
    assert event.occurred_at == datetime.fromtimestamp(start_ns / 1e9, tz=timezone.utc)
    assert event.occurred_at.microsecond == 1_500  # ms precision preserved
    assert event.tool_name == "web_search"
    assert event.outcome == "allow"
    assert event.user_roles == ["admin", "dev"]
    assert event.arguments == {"query": "hello"}
    assert event.hint is None


def test_map_span_llm_happy_path() -> None:
    event = map_span(semconv.SCOPE_USAGE, make_span(usage_attrs()), {})
    assert isinstance(event, LlmInvocationEvent)
    assert event.model == "gpt-4o"
    assert event.input_tokens == 100
    assert event.output_tokens == 50
    assert event.latency_ms == 250
    assert event.status == "success"  # absent on the wire → model default


def test_map_span_ban_happy_path() -> None:
    event = map_span(semconv.SCOPE_BANS, make_span(ban_attrs()), {})
    assert isinstance(event, BanEnforcementEvent)
    assert event.ban_type == "agent"
    assert event.ban_id == "ban_123"


def test_when_scope_is_unknown_then_span_rejected() -> None:
    with pytest.raises(SpanRejected) as exc:
        map_span("some.other.scope", make_span(decision_attrs()), {})
    assert exc.value.error_class == "unknown_scope"


def test_when_event_id_is_not_a_uuid_then_span_rejected() -> None:
    attrs = decision_attrs(**{semconv.EVENT_ID: "not-a-uuid"})
    with pytest.raises(SpanRejected) as exc:
        map_span(semconv.SCOPE_AUDIT, make_span(attrs), {})
    assert exc.value.error_class == "validation"


def test_when_outcome_is_invalid_then_span_rejected() -> None:
    attrs = decision_attrs(**{semconv.OUTCOME: "maybe"})
    with pytest.raises(SpanRejected):
        map_span(semconv.SCOPE_AUDIT, make_span(attrs), {})


def test_when_arguments_json_is_invalid_then_span_rejected() -> None:
    attrs = decision_attrs(**{semconv.ARGUMENTS: "{broken"})
    with pytest.raises(SpanRejected):
        map_span(semconv.SCOPE_AUDIT, make_span(attrs), {})


def test_when_start_time_is_zero_then_span_rejected() -> None:
    with pytest.raises(SpanRejected) as exc:
        map_span(semconv.SCOPE_AUDIT, make_span(decision_attrs(), start_ns=0), {})
    assert "start_time" in exc.value.error


def test_when_occurred_at_is_in_the_future_then_span_rejected() -> None:
    future_ns = time.time_ns() + 10 * 60 * 10**9
    with pytest.raises(SpanRejected) as exc:
        map_span(
            semconv.SCOPE_AUDIT, make_span(decision_attrs(), start_ns=future_ns), {}
        )
    assert exc.value.error_class == "out_of_window"


def test_when_tokens_arrive_as_strings_then_coerced_to_int() -> None:
    attrs = usage_attrs(**{semconv.GEN_AI_USAGE_INPUT_TOKENS: "100"})
    event = map_span(semconv.SCOPE_USAGE, make_span(attrs), {})
    assert event.input_tokens == 100


def test_when_user_roles_arrive_as_json_string_then_coerced_to_list() -> None:
    attrs = decision_attrs(**{semconv.USER_ROLES: '["admin"]'})
    event = map_span(semconv.SCOPE_AUDIT, make_span(attrs), {})
    assert event.user_roles == ["admin"]


def test_when_latency_is_absent_then_derived_from_span_duration() -> None:
    attrs = usage_attrs()
    del attrs[semconv.LATENCY_MS]
    start_ns = time.time_ns() - 10**9
    span = make_span(attrs, start_ns=start_ns, end_ns=start_ns + 42_000_000)
    event = map_span(semconv.SCOPE_USAGE, span, {})
    assert event.latency_ms == 42


def test_when_agent_name_is_absent_then_resource_service_name_is_used() -> None:
    attrs = decision_attrs()
    del attrs[semconv.AGENT_NAME]
    event = map_span(
        semconv.SCOPE_AUDIT, make_span(attrs), {"service.name": "svc-agent"}
    )
    assert event.agent_name == "svc-agent"
