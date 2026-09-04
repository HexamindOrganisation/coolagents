"""Decoded OTLP span → validated platform event.

The wire contract lives in hexgate.tracing.semconv (shared with the future
SDK emitter). Dispatch is by instrumentation scope name; the platform's
Pydantic models (schemas.py) are the validation layer, so the enricher
accepts exactly what the HTTP ingest accepts. Type coercion lives in
coerce.py; redaction/byte caps in enforcement.py — this module is only the
attribute→field contract for each scope.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span
from pydantic import ValidationError

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.coerce import (
    SpanRejected,
    as_int,
    as_json_dict,
    as_str,
    as_str_list,
    required,
)
from hexgate_api.jobs.enricher.decode import attrs_dict
from hexgate_api.jobs.enricher.enforcement import (
    capped_arguments,
    capped_attributes,
    capped_hint,
    capped_violations,
)
from hexgate_api.query_scope import EventOutOfWindow, validate_event_window
from hexgate_api.schemas import BanEnforcementEvent, DecisionEvent, LlmInvocationEvent

_log = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

KNOWN_SCOPES = (semconv.SCOPE_AUDIT, semconv.SCOPE_USAGE, semconv.SCOPE_BANS)

Event = DecisionEvent | LlmInvocationEvent | BanEnforcementEvent


def _envelope(
    span: Span, attrs: dict[str, Any], resource_attrs: dict[str, Any], scope: str
) -> dict[str, Any]:
    """The AuditEnvelope fields shared by all three event types."""
    if span.start_time_unix_nano <= 0:
        raise SpanRejected(
            "span start_time_unix_nano is unset", error_class="validation", scope=scope
        )
    # Integer arithmetic, not fromtimestamp(ns / 1e9): the float loses
    # precision past ~µs and the storage column is DateTime64(3).
    occurred_at = _EPOCH + timedelta(microseconds=span.start_time_unix_nano // 1_000)
    agent_name = as_str(
        attrs.get(semconv.AGENT_NAME)
        or resource_attrs.get(semconv.AGENT_NAME)
        or resource_attrs.get("service.name")
    )
    if not agent_name:
        raise SpanRejected(
            f"missing required attribute {semconv.AGENT_NAME}",
            error_class="validation",
            scope=scope,
        )
    return {
        "event_id": as_str(required(attrs, semconv.EVENT_ID, scope=scope)),
        "occurred_at": occurred_at,
        "agent_name": agent_name,
        "session_id": as_str(attrs.get(semconv.SESSION_ID)),
        "user_id": as_str(attrs.get(semconv.USER_ID)),
    }


def _run_counter(attrs: dict[str, Any], key: str, scope: str) -> int:
    """A run counter, defaulting to 0 when the emitter sends no attribution.

    Absent is not an error: spans predating run attribution, and decisions made
    outside a run scope, both legitimately carry no counters.
    """
    value = attrs.get(key)
    return 0 if value is None else as_int(value, key=key, scope=scope)


def _run_fields(attrs: dict[str, Any], scope: str) -> dict[str, Any]:
    return {
        # ``None``, never ``""``: the field is ``UUID | None`` and an empty
        # string fails validation, DLQ-ing the whole event over an advisory
        # column. Emitters omit the attribute outside a run scope.
        "run_id": as_str(attrs.get(semconv.RUN_ID)) or None,
        "run_tool_calls": _run_counter(attrs, semconv.RUN_TOOL_CALLS, scope),
        "run_llm_calls": _run_counter(attrs, semconv.RUN_LLM_CALLS, scope),
        "run_denials": _run_counter(attrs, semconv.RUN_DENIALS, scope),
        "run_total_tokens": _run_counter(attrs, semconv.RUN_TOTAL_TOKENS, scope),
        "run_elapsed_ms": _run_counter(attrs, semconv.RUN_ELAPSED_MS, scope),
    }


def _decision_fields(attrs: dict[str, Any], scope: str) -> dict[str, Any]:
    return {
        **_run_fields(attrs, scope),
        "tool_name": as_str(required(attrs, semconv.TOOL_NAME, scope=scope)),
        "outcome": as_str(required(attrs, semconv.OUTCOME, scope=scope)),
        "user_roles": as_str_list(
            attrs.get(semconv.USER_ROLES), key=semconv.USER_ROLES, scope=scope
        ),
        "deciding_role": as_str(attrs.get(semconv.DECIDING_ROLE)),
        "error_type": as_str(attrs.get(semconv.ERROR_TYPE)),
        "reason": as_str(attrs.get(semconv.REASON)),
        # Redaction/caps happen here, before validation, so an over-long
        # violations list is bounded rather than rejected, and the batch
        # inserts downstream can trust every event as final.
        "violations": capped_violations(
            as_str_list(
                attrs.get(semconv.VIOLATIONS), key=semconv.VIOLATIONS, scope=scope
            )
        ),
        "hint": capped_hint(
            as_json_dict(attrs.get(semconv.HINT), key=semconv.HINT, scope=scope)
        ),
        "arguments": capped_arguments(
            as_json_dict(
                attrs.get(semconv.ARGUMENTS), key=semconv.ARGUMENTS, scope=scope
            )
        ),
        "attributes": capped_attributes(
            as_json_dict(
                attrs.get(semconv.ATTRIBUTES), key=semconv.ATTRIBUTES, scope=scope
            )
        ),
    }


def _usage_fields(attrs: dict[str, Any], span: Span, scope: str) -> dict[str, Any]:
    latency = attrs.get(semconv.LATENCY_MS)
    if latency is None:
        # Point-in-time emitters set start == end; a real duration is a usable
        # fallback for foreign emitters that only timed the span.
        elapsed_ns = span.end_time_unix_nano - span.start_time_unix_nano
        latency = elapsed_ns // 1_000_000 if elapsed_ns > 0 else 0
    fields = {
        "model": as_str(required(attrs, semconv.GEN_AI_REQUEST_MODEL, scope=scope)),
        "input_tokens": as_int(
            required(attrs, semconv.GEN_AI_USAGE_INPUT_TOKENS, scope=scope),
            key=semconv.GEN_AI_USAGE_INPUT_TOKENS,
            scope=scope,
        ),
        "output_tokens": as_int(
            required(attrs, semconv.GEN_AI_USAGE_OUTPUT_TOKENS, scope=scope),
            key=semconv.GEN_AI_USAGE_OUTPUT_TOKENS,
            scope=scope,
        ),
        "latency_ms": as_int(latency, key=semconv.LATENCY_MS, scope=scope),
        "error_code": as_str(attrs.get(semconv.ERROR_CODE)),
        # Joins this model call to the decisions of the same run; the usage
        # event carries the id alone, no counters.
        "run_id": as_str(attrs.get(semconv.RUN_ID)) or None,
    }
    status = attrs.get(semconv.STATUS)
    if status is not None:  # absent → the model's "success" default
        fields["status"] = as_str(status)
    return fields


def _ban_fields(attrs: dict[str, Any], scope: str) -> dict[str, Any]:
    return {
        "ban_type": as_str(required(attrs, semconv.BAN_TYPE, scope=scope)),
        "ban_id": as_str(required(attrs, semconv.BAN_ID, scope=scope)),
        "reason": as_str(attrs.get(semconv.REASON)),
    }


def map_span(scope_name: str, span: Span, resource_attrs: dict[str, Any]) -> Event:
    """Build the validated event for one span, or raise :class:`SpanRejected`."""
    if scope_name not in KNOWN_SCOPES:
        raise SpanRejected(
            f"unknown instrumentation scope {scope_name!r}",
            error_class="unknown_scope",
            scope=scope_name,
        )
    attrs = attrs_dict(span.attributes)
    payload = _envelope(span, attrs, resource_attrs, scope_name)
    if scope_name == semconv.SCOPE_AUDIT:
        model: type[Event] = DecisionEvent
        payload |= _decision_fields(attrs, scope_name)
    elif scope_name == semconv.SCOPE_USAGE:
        model = LlmInvocationEvent
        payload |= _usage_fields(attrs, span, scope_name)
    else:
        model = BanEnforcementEvent
        payload |= _ban_fields(attrs, scope_name)
    try:
        event = model(**payload)
    except ValidationError as exc:
        first = exc.errors()[0]
        raise SpanRejected(
            f"validation failed on {first.get('loc')}: {first.get('msg')}",
            error_class="validation",
            scope=scope_name,
        ) from None
    try:
        validate_event_window(event.occurred_at)
    except EventOutOfWindow as exc:
        raise SpanRejected(
            str(exc), error_class="out_of_window", scope=scope_name
        ) from None
    return event
