"""Shared builders for the enricher tests: hand-built OTLP payloads (the SDK
emitter doesn't exist yet — the wire contract in hexgate.tracing.semconv is
authoritative), fake Kafka clients that append to a shared call log so tests
can assert ordering, and a job factory wired with those fakes."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
)
from opentelemetry.proto.common.v1.common_pb2 import (
    AnyValue,
    InstrumentationScope,
    KeyValue,
)
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
from opentelemetry.proto.trace.v1.trace_pb2 import ResourceSpans, ScopeSpans, Span

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.consumer import EnricherJob
from hexgate_api.settings import Settings

# ---------------------------------------------------------------------------
# OTLP payload builders
# ---------------------------------------------------------------------------


def any_value(value: Any) -> AnyValue:
    """Python value → AnyValue, mirroring decode.attr_value in reverse."""
    if isinstance(value, bool):  # before int: bool is an int subclass
        return AnyValue(bool_value=value)
    if isinstance(value, int):
        return AnyValue(int_value=value)
    if isinstance(value, float):
        return AnyValue(double_value=value)
    if isinstance(value, str):
        return AnyValue(string_value=value)
    if isinstance(value, list):
        wrapped = AnyValue()
        wrapped.array_value.values.extend(any_value(v) for v in value)
        return wrapped
    if isinstance(value, dict):
        wrapped = AnyValue()
        wrapped.kvlist_value.values.extend(
            KeyValue(key=k, value=any_value(v)) for k, v in value.items()
        )
        return wrapped
    raise TypeError(f"unsupported attribute value {value!r}")


def make_span(
    attrs: dict[str, Any],
    *,
    start_ns: int | None = None,
    end_ns: int = 0,
    name: str = "event",
) -> Span:
    if start_ns is None:
        start_ns = time.time_ns()
    span = Span(
        name=name,
        trace_id=uuid.uuid4().bytes,
        span_id=uuid.uuid4().bytes[:8],
        start_time_unix_nano=start_ns,
        end_time_unix_nano=end_ns,
    )
    span.attributes.extend(
        KeyValue(key=k, value=any_value(v)) for k, v in attrs.items()
    )
    return span


def make_request_bytes(
    groups: list[tuple[str, list[Span]]],
    resource_attrs: dict[str, Any] | None = None,
) -> bytes:
    """Serialize (scope_name, spans) groups the way the Collector's
    kafkaexporter does: one ExportTraceServiceRequest per record."""
    resource = Resource()
    if resource_attrs:
        resource.attributes.extend(
            KeyValue(key=k, value=any_value(v)) for k, v in resource_attrs.items()
        )
    request = ExportTraceServiceRequest(
        resource_spans=[
            ResourceSpans(
                resource=resource,
                scope_spans=[
                    ScopeSpans(scope=InstrumentationScope(name=scope), spans=spans)
                    for scope, spans in groups
                ],
            )
        ]
    )
    return request.SerializeToString()


# ---------------------------------------------------------------------------
# Wire-contract attribute dicts (minimal-required, override per test)
# ---------------------------------------------------------------------------


def decision_attrs(**overrides: Any) -> dict[str, Any]:
    base = {
        semconv.EVENT_ID: str(uuid.uuid4()),
        semconv.AGENT_NAME: "researcher",
        semconv.TOOL_NAME: "web_search",
        semconv.OUTCOME: "allow",
    }
    return {**base, **overrides}


def usage_attrs(**overrides: Any) -> dict[str, Any]:
    base = {
        semconv.EVENT_ID: str(uuid.uuid4()),
        semconv.AGENT_NAME: "researcher",
        semconv.GEN_AI_REQUEST_MODEL: "gpt-4o",
        semconv.GEN_AI_USAGE_INPUT_TOKENS: 100,
        semconv.GEN_AI_USAGE_OUTPUT_TOKENS: 50,
        semconv.LATENCY_MS: 250,
    }
    return {**base, **overrides}


def ban_attrs(**overrides: Any) -> dict[str, Any]:
    base = {
        semconv.EVENT_ID: str(uuid.uuid4()),
        semconv.AGENT_NAME: "researcher",
        semconv.BAN_TYPE: "agent",
        semconv.BAN_ID: "ban_123",
    }
    return {**base, **overrides}


# ---------------------------------------------------------------------------
# Fake Kafka clients + job factory
# ---------------------------------------------------------------------------


@dataclass
class FakeRecord:
    key: bytes | None
    value: bytes
    topic: str = "hexgate.otlp.raw"
    partition: int = 0
    offset: int = 0


@dataclass
class FakeConsumer:
    calls: list[str]
    commits: int = 0

    async def commit(self) -> None:
        self.calls.append("commit")
        self.commits += 1


@dataclass
class FakeProducer:
    calls: list[str]
    sent: list[tuple[str, bytes | None, bytes]] = field(default_factory=list)

    async def send_and_wait(self, topic: str, value: bytes, key: bytes | None) -> None:
        self.calls.append("dlq")
        self.sent.append((topic, key, value))


@pytest.fixture
def make_job(monkeypatch: pytest.MonkeyPatch):
    """EnricherJob wired with fakes + a MagicMock ClickHouse whose inserts
    append to the shared call log; resolve_versions is stubbed to return
    per-pair fake ids ("" via the `unresolved` flag)."""

    def _make(*, unresolved: bool = False, insert_side_effect: Any = None):
        calls: list[str] = []
        clickhouse = MagicMock()

        def _log_insert(*args: Any, **kwargs: Any) -> None:
            calls.append("insert")
            if _make.insert_failures:  # consume one scheduled failure
                raise _make.insert_failures.pop(0)

        clickhouse.insert.side_effect = _log_insert
        _make.insert_failures = list(insert_side_effect or [])

        async def _stub_resolve(pairs: set[tuple[str, str]]):
            return {pair: "" if unresolved else f"ver_{pair[1]}" for pair in pairs}

        monkeypatch.setattr(
            "hexgate_api.jobs.enricher.consumer.resolve_versions", _stub_resolve
        )
        settings = Settings(enricher_insert_max_backoff_s=0.01)
        consumer = FakeConsumer(calls)
        producer = FakeProducer(calls)
        job = EnricherJob(
            settings,
            clickhouse_client=clickhouse,
            consumer=consumer,
            producer=producer,
        )
        return job, clickhouse, consumer, producer, calls

    return _make
