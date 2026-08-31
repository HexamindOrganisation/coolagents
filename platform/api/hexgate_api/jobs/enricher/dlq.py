"""Dead-letter envelopes for permanently-rejected records and spans.

JSON, not protobuf: the DLQ's consumers are humans (``rpk topic consume``)
and a future replay script, volume is low, and a single span can't be
re-serialized standalone anyway. One message per rejected unit — a span
normally (including every span of a keyless record), the whole record only
when its bytes are undecodable. Keyed by project_id so DLQ partitioning
mirrors the source.

DLQ messages can duplicate whenever a poll replays — a rebalance, a crash, or
a stop during the DLQ retry loop — because offsets commit only after every
send has landed. Envelopes carry no dedup key, so nothing collapses them the
way ReplacingMergeTree does for the tables; consumers must tolerate that.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

from hexgate.audit import SENSITIVE_ARG_KEY_RE, redact, truncate_json
from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.decode import attrs_dict

# The dict fields travel as JSON strings (semconv wire contract). ``redact``
# matches dict keys, so a still-serialized payload would pass through whole
# with its secret-bearing keys unread.
_JSON_DICT_KEYS = (semconv.ARGUMENTS, semconv.HINT, semconv.ATTRIBUTES)
_UNPARSEABLE = "[UNPARSEABLE]"

# Both variable-size fields are capped well below the producer's 1 MiB
# default max_request_size: an envelope the producer itself cannot send
# fails client-side on every attempt and would wedge the very partition
# the DLQ exists to protect. The caps are diagnostic previews, not the
# record of truth — ``_source`` locates the original bytes while the raw
# topic's retention lasts.
_ATTRIBUTES_CAP_BYTES = 32 * 1024
_RAW_VALUE_CAP_BYTES = 64 * 1024


def _source(topic: str, partition: int, offset: int) -> dict[str, Any]:
    """Pointer back to the raw record, valid while the source retention lasts."""
    return {"topic": topic, "partition": partition, "offset": offset}


def _redacted_attributes(span: Span) -> dict[str, Any]:
    """Span attributes safe for the DLQ: JSON-string dicts parsed, then redacted.

    A dict field that doesn't parse *to a dict* can't be redacted (``redact``
    matches keys, so a bare string or list has nothing to match), so it is
    dropped rather than forwarded raw — the DLQ is for diagnosing the
    rejection, and the source record (see ``_source``) still holds the
    original bytes.
    """
    attributes = attrs_dict(span.attributes)
    for key in _JSON_DICT_KEYS:
        raw = attributes.get(key)
        if isinstance(raw, str):
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = None
            attributes[key] = parsed if isinstance(parsed, dict) else _UNPARSEABLE
    return truncate_json(
        redact(attributes, pattern=SENSITIVE_ARG_KEY_RE), cap=_ATTRIBUTES_CAP_BYTES
    )


def span_envelope(
    *,
    error: str,
    error_class: str,
    scope: str,
    project_id: str,
    topic: str,
    partition: int,
    offset: int,
    span: Span,
) -> bytes:
    """Envelope for one rejected span; its siblings are unaffected.

    Attributes are redacted (substring key match, the stricter of the two
    SDK patterns) before they land here: this topic has 30-day retention and
    no ACLs, so unredacted arguments must never reach it. The JSON-string
    dict fields are parsed first so the key match reaches inside them, and
    they stay dicts in the envelope.
    """
    attributes = _redacted_attributes(span)
    payload = {
        "error": error,
        "error_class": error_class,
        "scope": scope,
        "project_id": project_id,
        "source": _source(topic, partition, offset),
        "span": {
            "name": span.name,
            "trace_id_hex": span.trace_id.hex(),
            "span_id_hex": span.span_id.hex(),
            "start_time_unix_nano": span.start_time_unix_nano,
            "attributes": attributes,
        },
    }
    return json.dumps(payload, default=str).encode("utf-8")


def record_envelope(
    *,
    error: str,
    error_class: str,
    project_id: str | None,
    topic: str,
    partition: int,
    offset: int,
    raw_value: bytes,
) -> bytes:
    """Envelope for a whole record that never decoded into spans."""
    payload = {
        "error": error,
        "error_class": error_class,
        "scope": None,
        "project_id": project_id,
        "source": _source(topic, partition, offset),
        "record_value_base64": base64.b64encode(
            raw_value[:_RAW_VALUE_CAP_BYTES]
        ).decode("ascii"),
        "record_value_truncated": len(raw_value) > _RAW_VALUE_CAP_BYTES,
    }
    return json.dumps(payload).encode("utf-8")
