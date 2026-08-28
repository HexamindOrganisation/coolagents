"""Shared sender registry — generic get-or-create/shutdown machinery reused
by ``hexgate.audit`` (policy decisions), ``hexgate.tracing.usage`` (LLM
token usage) and ``hexgate.security.bans`` (ban enforcements). None of those
modules owns this one; all import from it.

Also owns the ``HEXGATE_LOCAL_MODE`` gate: a single kill switch that
suppresses every event type sharing this registry, not just decisions.

Transport: every event is one OpenTelemetry span, exported over OTLP/HTTP
(protobuf) to the Hexgate Collector. The wire contract — scope names,
attribute keys, how ``occurred_at``/``event_id`` travel — is
``hexgate.tracing.semconv``, shared verbatim with the platform's
span-enricher job.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, ClassVar, Protocol

from opentelemetry.context import Context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

from hexgate.config.env import resolve_api_key, resolve_otlp_endpoint
from hexgate.tracing import semconv

_log = logging.getLogger(__name__)

DEFAULT_EXPORT_TIMEOUT = 5.0
"""Bound, in seconds, on a single OTLP export request and on the final
flush at :meth:`AuditSender.close`. Replaces OTel's 30s defaults: a slow or
unreachable platform must not hold a host application's exit for that long."""

# Identifies the emitting library on every span's resource. Not read by the
# enricher (agent identity travels as a span attribute — one process hosts
# many agents), but it's what shows up next to our spans in any third-party
# OTel backend a customer points this exporter at.
_RESOURCE = Resource.create({"service.name": "hexgate-sdk"})


class SpanEvent(Protocol):
    """Structural type for anything ``AuditSender`` can emit — a frozen event
    dataclass that knows which instrumentation scope it belongs to and how
    to lay itself out as flat span attributes. ``AuditEvent``,
    ``LlmUsageEvent`` and ``BanEnforcementEvent`` all satisfy this without
    being imported here."""

    SCOPE: ClassVar[str]
    occurred_at: datetime

    def span_attributes(self) -> dict[str, Any]: ...


def _unix_nanos(moment: datetime) -> int:
    """``datetime`` → integer nanoseconds since the epoch, the unit OTLP
    types span timestamps in. Integer arithmetic on the microsecond field
    rather than ``timestamp() * 1e9``: the float loses precision past ~µs."""
    epoch_seconds = int(moment.timestamp())
    return epoch_seconds * 1_000_000_000 + moment.microsecond * 1_000


class AuditSender:
    """Span emitter for a single ``api_key``: one ``TracerProvider`` feeding
    one ``BatchSpanProcessor`` → ``OTLPSpanExporter`` pair, with one tracer
    per event stream (decisions / usage / bans) so the instrumentation-scope
    name tells the platform which event type each span is.

    ``emit()`` is sync, non-blocking and thread-agnostic: it only enqueues
    the finished span onto the processor's bounded in-memory queue, whose
    own worker thread batches and POSTs on a timer or size trigger. That
    holds equally on an asyncio loop thread, in a ``run_in_executor`` worker
    and in a purely synchronous caller with no loop anywhere — there is no
    event-loop affinity to manage. A saturated queue drops the newest spans
    (the processor logs a warning) rather than growing an unbounded backlog,
    same policy as before.

    ``exporter`` is an injection seam for tests; production callers leave
    it ``None`` and get an OTLP/HTTP exporter bearing the key.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        *,
        export_timeout: float = DEFAULT_EXPORT_TIMEOUT,
        exporter: SpanExporter | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._export_timeout = export_timeout
        self._closing = False
        if exporter is None:
            exporter = self._new_exporter()
        self._processor = BatchSpanProcessor(
            exporter, export_timeout_millis=export_timeout * 1000
        )
        # ALWAYS_ON, not the default parent-based sampler: a customer running
        # their own OTel tracing sets sampling decisions on *their* spans, and
        # a parent-based sampler here would inherit them — a 1% trace sample
        # would silently drop 99% of audit events. (emit() also starts every
        # span from an empty Context so it never picks up their parent.)
        #
        # shutdown_on_exit stays at its default (True): the provider registers
        # an atexit hook that flushes and stops the processor. The processor's
        # worker is a daemon thread, so without that hook a run_sync()-only
        # script that never calls hexgate.audit.shutdown() would lose its
        # final batch at interpreter exit. The hook is the safety net;
        # shutdown() is still the documented contract for host applications.
        self._provider = TracerProvider(sampler=ALWAYS_ON, resource=_RESOURCE)
        self._provider.add_span_processor(self._processor)
        self._tracers = {
            scope: self._provider.get_tracer(scope)
            for scope in (semconv.SCOPE_AUDIT, semconv.SCOPE_USAGE, semconv.SCOPE_BANS)
        }

    def _new_exporter(self) -> SpanExporter:
        # Imported lazily: the exporter pulls in `requests` and the protobuf
        # stubs, which tests injecting their own exporter never need.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )

        return OTLPSpanExporter(
            endpoint=self._endpoint,
            headers={"Authorization": f"Bearer {self._api_key}"},
            timeout=self._export_timeout,
        )

    def emit(self, event: SpanEvent) -> None:
        """Turn ``event`` into one finished span and hand it to the batch
        processor. Never blocks on the network; never raises for a transport
        problem (those surface as the exporter's own log lines)."""
        if self._closing:
            return
        tracer = self._tracers[event.SCOPE]
        at = _unix_nanos(event.occurred_at)
        # start == end: these are point-in-time events, and the enricher reads
        # occurred_at from start_time_unix_nano (see semconv). context=Context()
        # detaches the span from whatever the caller's own tracing has active,
        # so it is always a root span in a trace of its own.
        span = tracer.start_span(
            event.SCOPE,
            context=Context(),
            attributes=event.span_attributes(),
            start_time=at,
        )
        span.end(end_time=at)

    async def close(self) -> None:
        """Stop accepting new emits; flush what's queued; stop the worker.

        ``TracerProvider.shutdown()`` blocks for up to the export timeout, so
        it runs off the event loop. Idempotent — OTel's own shutdown guards
        make a second call a logged no-op."""
        self._closing = True
        await asyncio.to_thread(self._provider.shutdown)


# --- Shared per-api_key registry ---------------------------------------------

# Setting this env var to a truthy value (``1``/``true``/``yes``/``on``,
# case-insensitive) makes ``get_or_create_sender()`` a no-op for every event
# type sharing this registry, even when ``HEXGATE_API_KEY`` is present.
# ``bootstrap(local_only=True)`` sets it; ``hexgate chat`` passes
# ``local_only=True``. The check happens on every call (not cached) so an
# adapter wrapper that re-configures after bootstrap still respects the gate.
_LOCAL_MODE_ENV = "HEXGATE_LOCAL_MODE"

# One-shot log gate, so the "sender suppressed" message lands the first time
# it'd matter (a key WAS set but local mode preempted it) and stays quiet
# thereafter.
_logged_local_mode_suppressed = False

# One sender per api_key. A single process may wrap agents for several
# tenants/keys, and each must export with its own bearer token — so senders
# are keyed by key rather than kept as a first-wins singleton. All three
# event types share one sender per key; the span's instrumentation scope,
# not a separate endpoint, tells them apart.
# The registry is unbounded and assumes a small, fixed key set per process;
# a key-per-request pattern would leak one sender + export worker per unique
# key. Such callers must evict explicitly (await sender.close(), then drop
# the dict entry) or use shutdown().
_senders: dict[str, AuditSender] = {}


def _local_mode_active() -> bool:
    """True if ``HEXGATE_LOCAL_MODE`` is set to a truthy value.

    Accepts ``1``/``true``/``yes``/``on`` (case-insensitive). Everything
    else — including unset — evaluates false. Mirrors the truthy-value
    parser the platform's ``HEXGATE_COOKIE_SECURE`` knob uses, so the
    behavior is consistent across the codebase's env flags."""
    return os.environ.get(_LOCAL_MODE_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def get_or_create_sender(
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the sender for ``api_key``. Idempotent per key.

    ``api_key``/``base_url`` fall back to ``HEXGATE_API_KEY`` /
    ``HEXGATE_API_URL`` env vars; the export endpoint is
    ``HEXGATE_OTLP_ENDPOINT`` when set, else ``<api url>/v1/traces``.
    Reuses the existing sender when the same key was already configured;
    distinct keys get distinct senders. Returns ``None`` when no api_key is
    resolvable — the caller's event type stays inert.

    Also returns ``None`` when ``HEXGATE_LOCAL_MODE`` is set in env, even if
    a key was resolvable — that's the "I have a key in .env but I'm
    iterating locally and don't want cloud writes" path (``hexgate chat``
    opts in via ``bootstrap(local_only=True)``), shared by every event type
    that goes through this registry.
    """
    global _logged_local_mode_suppressed
    if _local_mode_active():
        # Only log when a key was actually present — otherwise the
        # message is just noise during a no-key local run.
        resolved = resolve_api_key(api_key)
        if resolved and not _logged_local_mode_suppressed:
            _log.info(
                "sender suppressed: %s=1 (a key is configured but local mode "
                "is on, so events stay on this machine)",
                _LOCAL_MODE_ENV,
            )
            _logged_local_mode_suppressed = True
        return None
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        return None
    existing = _senders.get(resolved_key)
    if existing is not None:
        return existing
    sender = AuditSender(
        endpoint=resolve_otlp_endpoint(base_url=base_url), api_key=resolved_key
    )
    _senders[resolved_key] = sender
    return sender


def get_sender(api_key: str | None = None) -> AuditSender | None:
    """Return the sender for ``api_key`` (falling back to ``HEXGATE_API_KEY``),
    if configured. Never creates one."""
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        return None
    return _senders.get(resolved_key)


async def shutdown() -> None:
    """Flush and stop every sender in the registry.

    Safe to call multiple times. Drains the whole shared registry — calling
    this from ``hexgate.audit``, ``hexgate.tracing.usage`` or the bans module
    closes every event type's sender in one shot. Host applications must
    call this before exit: normal traffic flushes itself on the processor's
    timer, but the final in-flight batch only leaves the process on an
    explicit flush (or the provider's best-effort atexit hook)."""
    senders = list(_senders.values())
    _senders.clear()
    for sender in senders:
        await sender.close()
