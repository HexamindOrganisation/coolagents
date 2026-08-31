"""decode.py — record bytes → per-span units."""

from __future__ import annotations

import pytest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.decode import (
    RecordDecodeError,
    attr_value,
    decode_record,
)
from tests.jobs.enricher.conftest import (
    any_value,
    ban_attrs,
    decision_attrs,
    make_request_bytes,
    make_span,
)


def test_decode_record_happy_path() -> None:
    span = make_span(decision_attrs())
    decoded = decode_record(
        make_request_bytes(
            [(semconv.SCOPE_AUDIT, [span])], resource_attrs={"service.name": "svc"}
        )
    )
    assert len(decoded) == 1
    scope_name, decoded_span, resource_attrs = decoded[0]
    assert scope_name == semconv.SCOPE_AUDIT
    assert decoded_span.start_time_unix_nano == span.start_time_unix_nano
    assert resource_attrs == {"service.name": "svc"}


def test_when_value_is_not_protobuf_then_record_decode_error() -> None:
    with pytest.raises(RecordDecodeError):
        decode_record(b"\xff\xff\xff\xff not a protobuf")


def test_when_value_is_none_then_record_decode_error() -> None:
    # ParseFromString(None) raises TypeError, which nothing upstream catches;
    # it must surface as the decode error the consumer parks to the DLQ.
    with pytest.raises(RecordDecodeError):
        decode_record(None)


def test_when_request_has_multiple_scopes_then_spans_tagged_per_scope() -> None:
    decoded = decode_record(
        make_request_bytes(
            [
                (semconv.SCOPE_AUDIT, [make_span(decision_attrs())]),
                (semconv.SCOPE_BANS, [make_span(ban_attrs()), make_span(ban_attrs())]),
            ]
        )
    )
    assert [scope for scope, _, _ in decoded] == [
        semconv.SCOPE_AUDIT,
        semconv.SCOPE_BANS,
        semconv.SCOPE_BANS,
    ]


def test_when_request_is_empty_then_no_spans() -> None:
    assert decode_record(make_request_bytes([])) == []


def test_attr_value_converts_array_and_kvlist() -> None:
    assert attr_value(any_value(["a", "b"])) == ["a", "b"]
    assert attr_value(any_value({"k": 1, "nested": {"x": True}})) == {
        "k": 1,
        "nested": {"x": True},
    }
    assert attr_value(AnyValue()) is None
    # KeyValue with a plain scalar survives the round trip untouched.
    assert attr_value(KeyValue(key="s", value=any_value("v")).value) == "v"
