"""Kafka record bytes → decoded OTLP spans.

One record value is one serialized ``ExportTraceServiceRequest`` (the
Collector's kafkaexporter, ``encoding: otlp_proto``), carrying up to a whole
Collector batch of spans across several resource/scope groups.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from opentelemetry.proto.trace.v1.trace_pb2 import Span


class RecordDecodeError(Exception):
    """The record value is not a parseable ExportTraceServiceRequest."""


class DecodedSpan(NamedTuple):
    scope_name: str
    span: Span
    resource_attrs: dict[str, Any]


def attr_value(value: AnyValue) -> Any:
    """Recursively convert an OTLP AnyValue to its Python equivalent.

    kvlists become dicts and arrays lists so the mapping layer can coerce
    uniformly; an unset AnyValue becomes None.
    """
    kind = value.WhichOneof("value")
    if kind is None:
        return None
    if kind == "array_value":
        return [attr_value(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return attrs_dict(value.kvlist_value.values)
    return getattr(value, kind)


def attrs_dict(attributes: Any) -> dict[str, Any]:
    """OTLP KeyValue list → plain dict (last occurrence of a key wins)."""
    out: dict[str, Any] = {}
    for kv in attributes:
        assert isinstance(kv, KeyValue)
        out[kv.key] = attr_value(kv.value)
    return out


def decode_record(value: bytes | None) -> list[DecodedSpan]:
    """Parse one record into per-span units, each tagged with its
    instrumentation scope name and the enclosing resource attributes.

    Raises :class:`RecordDecodeError` when the bytes are not a valid
    protobuf message; a valid request with zero spans returns [].
    """
    if value is None:
        # A tombstone or a foreign producer's null. ParseFromString(None)
        # raises TypeError, not DecodeError — unmapped here, it would escape
        # the caller's decode handling and crash-loop the process.
        raise RecordDecodeError("record value is None")
    request = ExportTraceServiceRequest()
    try:
        request.ParseFromString(value)
    except DecodeError as exc:
        raise RecordDecodeError(str(exc)) from exc
    decoded: list[DecodedSpan] = []
    for resource_spans in request.resource_spans:
        resource_attrs = attrs_dict(resource_spans.resource.attributes)
        for scope_spans in resource_spans.scope_spans:
            scope_name = scope_spans.scope.name
            for span in scope_spans.spans:
                decoded.append(DecodedSpan(scope_name, span, resource_attrs))
    return decoded
