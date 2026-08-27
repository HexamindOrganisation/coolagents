"""dlq.py — dead-letter envelope shapes."""

from __future__ import annotations

import base64
import json

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.dlq import record_envelope, span_envelope
from tests.jobs.enricher.conftest import decision_attrs, make_span


def test_span_envelope_happy_path() -> None:
    span = make_span(decision_attrs(), name="decision")
    raw = span_envelope(
        error="missing required attribute sec_ai.tool_name",
        error_class="validation",
        scope=semconv.SCOPE_AUDIT,
        project_id="proj_1",
        topic="hexgate.otlp.raw",
        partition=1,
        offset=4711,
        span=span,
    )
    payload = json.loads(raw)
    assert payload["error_class"] == "validation"
    assert payload["scope"] == semconv.SCOPE_AUDIT
    assert payload["project_id"] == "proj_1"
    assert payload["source"] == {
        "topic": "hexgate.otlp.raw",
        "partition": 1,
        "offset": 4711,
    }
    assert payload["span"]["name"] == "decision"
    assert payload["span"]["span_id_hex"] == span.span_id.hex()


def test_when_a_decision_span_is_rejected_then_dlq_attributes_are_redacted() -> None:
    # The DLQ has 30-day retention and no ACLs — a secret-bearing argument
    # key must be blanked even in the rejection record.
    attrs = decision_attrs(**{"sec_ai.api_token": "s3cr3t"})
    raw = span_envelope(
        error="whatever",
        error_class="validation",
        scope=semconv.SCOPE_AUDIT,
        project_id="proj_1",
        topic="t",
        partition=0,
        offset=0,
        span=make_span(attrs),
    )
    payload = json.loads(raw)
    assert payload["span"]["attributes"]["sec_ai.api_token"] == "[REDACTED]"


def _envelope_attributes(attrs: dict) -> dict:
    raw = span_envelope(
        error="whatever",
        error_class="validation",
        scope=semconv.SCOPE_AUDIT,
        project_id="proj_1",
        topic="t",
        partition=0,
        offset=0,
        span=make_span(attrs),
    )
    return json.loads(raw)["span"]["attributes"]


def test_when_arguments_hold_a_secret_key_then_dlq_redacts_inside_the_json() -> None:
    # Arguments arrive as a JSON string; the secret key is inside it, not a
    # span attribute key, so redaction has to parse before matching.
    attrs = decision_attrs(
        **{semconv.ARGUMENTS: json.dumps({"password": "hunter2", "query": "q"})}
    )
    attributes = _envelope_attributes(attrs)
    assert attributes[semconv.ARGUMENTS] == {"password": "[REDACTED]", "query": "q"}


def test_when_a_dict_field_is_not_json_then_dlq_drops_it() -> None:
    attrs = decision_attrs(**{semconv.HINT: "{not json"})
    attributes = _envelope_attributes(attrs)
    assert attributes[semconv.HINT] == "[UNPARSEABLE]"


def test_when_a_record_is_undecodable_then_envelope_carries_base64() -> None:
    raw_value = b"\xff\xff garbage"
    raw = record_envelope(
        error="undecodable OTLP payload",
        error_class="decode",
        project_id="proj_1",
        topic="hexgate.otlp.raw",
        partition=2,
        offset=99,
        raw_value=raw_value,
    )
    payload = json.loads(raw)
    assert payload["scope"] is None
    assert base64.b64decode(payload["record_value_base64"]) == raw_value
