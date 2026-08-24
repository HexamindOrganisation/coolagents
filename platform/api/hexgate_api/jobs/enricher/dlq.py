"""Dead-letter envelopes for permanently-rejected records and spans.

JSON, not protobuf: the DLQ's consumers are humans (``rpk topic consume``)
and a future replay script, volume is low, and a single span can't be
re-serialized standalone anyway. One message per rejected unit — a span
normally, the whole record only when its bytes are undecodable or it
arrived keyless. Keyed by project_id so DLQ partitioning mirrors the source.

DLQ messages can duplicate when a poll is replayed after a rebalance
(offsets commit only after processing) — consumers must tolerate that.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from opentelemetry.proto.trace.v1.trace_pb2 import Span

from hexgate.audit import SENSITIVE_ARG_KEY_RE, redact
from hexgate_api.jobs.enricher.decode import attrs_dict


def _source(topic: str, partition: int, offset: int) -> dict[str, Any]:
    """Pointer back to the raw record, valid while the source retention lasts."""
    return {"topic": topic, "partition": partition, "offset": offset}


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
    no ACLs, so unredacted arguments must never reach it.
    """
    attributes = redact(attrs_dict(span.attributes), pattern=SENSITIVE_ARG_KEY_RE)
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
        "record_value_base64": base64.b64encode(raw_value).decode("ascii"),
    }
    return json.dumps(payload).encode("utf-8")
