"""Shared sender registry — generic get-or-create/shutdown machinery reused
by ``hexgate.audit`` (policy decisions) and ``hexgate.tracing.usage`` (LLM
token usage). Neither of those modules owns this one; both import from it.

Also owns the ``HEXGATE_LOCAL_MODE`` gate: a single kill switch that
suppresses every event type sharing this registry, not just decisions.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
from typing import Any, Protocol

import httpx

from hexgate.config.env import resolve_api_key, resolve_api_url

_log = logging.getLogger(__name__)


class _PayloadEvent(Protocol):
    """Structural type for anything ``AuditSender`` can emit — a frozen
    event dataclass exposing a flat-dict wire payload. Both ``AuditEvent``
    and ``LlmUsageEvent`` satisfy this without either being imported here."""

    def as_payload(self) -> dict[str, Any]: ...


class AuditSender:
    """Fire-and-forget POST for a single ``(api_key, path)`` pair. Bounded
    by an asyncio.Semaphore.

    emit() is sync and non-blocking — schedules a background task. Drops with
    a periodic log when the semaphore is saturated (platform slow/unreachable).
    Named for its original use (policy decisions); reused unmodified for any
    event type whose payload is a flat JSON dict via ``as_payload()``.
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        *,
        max_in_flight: int = 32,
        http_timeout: float = 5.0,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._max_in_flight = max_in_flight
        self._http_timeout = http_timeout
        # The semaphore and httpx client are loop-bound: asyncio primitives
        # latch onto the first loop that drives them and reject any other
        # (e.g. a second asyncio.run()). Build them eagerly so configure()
        # stays sync, but track the loop and rebuild if it rotates.
        #
        # Capture the build-time loop so emit() can reach it from an executor
        # thread (a sync tool under run_in_executor has no loop of its own).
        try:
            self._loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self._semaphore = asyncio.Semaphore(max_in_flight)
        self._client: httpx.AsyncClient | None = self._new_client()
        self._tasks: set[asyncio.Task[None]] = set()
        self._closing = False
        self._dropped = 0
        self._warned_no_loop = False

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._http_timeout,
            headers={"Authorization": f"Bearer {self._api_key}"},
        )

    def _ensure_loop_state(self, loop: asyncio.AbstractEventLoop) -> None:
        """Adopt the running loop on first use; rebuild on loop rotation.

        The previous client/semaphore are bound to a now-defunct loop, so
        drop them (GC closes the old client) and rebuild on ``loop``."""
        if self._loop is loop:
            return
        if self._loop is not None:
            self._semaphore = asyncio.Semaphore(self._max_in_flight)
            self._client = self._new_client()
            self._dropped = 0
        self._loop = loop

    def emit(self, event: _PayloadEvent) -> None:
        if self._closing or self._client is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # Called off-loop (sync tool on a run_in_executor thread): route
            # to the build-time loop instead of dropping the event.
            loop = self._loop
            if loop is None or loop.is_closed():
                if not self._warned_no_loop:
                    _log.warning(
                        "audit emit called with no running loop and no live "
                        "bound loop; skipping"
                    )
                    self._warned_no_loop = True
                return
            try:
                loop.call_soon_threadsafe(self._spawn_send, event)
            except RuntimeError:
                pass  # loop torn down between the is_closed() check and the call
            return
        self._ensure_loop_state(loop)
        self._spawn_send(event)

    def _spawn_send(self, event: _PayloadEvent) -> None:
        """Create the send task. MUST run on the bound loop's thread —
        ``create_task`` and the loop-bound semaphore require the running loop.
        Reached on-loop from :meth:`emit`, or via ``call_soon_threadsafe``."""
        if self._closing or self._client is None:
            return
        if self._semaphore.locked():
            self._dropped += 1
            if self._dropped % 100 == 1:
                _log.warning(
                    "audit sender saturated; %d events dropped (platform slow?)",
                    self._dropped,
                )
            return
        task = asyncio.create_task(self._send(event), name="hexgate-audit-send")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send(self, event: _PayloadEvent) -> None:
        if self._client is None:
            # Invariant: _send is only reached after start() initialised
            # the client. Raise so `python -O` can't strip the check.
            raise RuntimeError("audit sender _send called before start()")
        async with self._semaphore:
            payload = event.as_payload()
            try:
                response = await self._client.post(self._endpoint, json=payload)
                if response.status_code == 503:
                    # Equal jitter: a fleet of SDKs hitting the same platform
                    # 503 must not retry in lockstep.
                    delay = min(self._http_timeout, 2.0)
                    await asyncio.sleep(random.uniform(delay / 2, delay))
                    response = await self._client.post(self._endpoint, json=payload)
                if response.status_code >= 400:
                    _log.error(
                        "audit ingest failed: %s %s",
                        response.status_code,
                        response.text[:200],
                    )
            except httpx.RequestError as exc:
                _log.warning("audit ingest network error: %s", exc)

    async def close(self, drain_timeout: float = 5.0) -> None:
        """Stop accepting new emits; drain in-flight tasks; close the HTTP client."""
        self._closing = True
        if self._tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self._tasks, return_exceptions=True),
                    timeout=drain_timeout,
                )
            except asyncio.TimeoutError:
                _log.warning(
                    "audit close: drain timed out with %d tasks pending",
                    len(self._tasks),
                )
        if self._client is not None:
            await self._client.aclose()


# --- Shared (api_key, path) registry ----------------------------------------

# Setting this env var to a truthy value (``1``/``true``/``yes``/``on``,
# case-insensitive) makes ``get_or_create_sender()`` a no-op for every event
# type sharing this registry, even when ``HEXGATE_API_KEY`` is present.
# ``bootstrap(local_only=True)`` sets it; ``hexgate chat`` passes
# ``local_only=True``. The check happens on every call (not cached) so an
# adapter wrapper that re-configures after bootstrap still respects the gate.
_LOCAL_MODE_ENV = "HEXGATE_LOCAL_MODE"

# One-shot log gate per path, so the "sender suppressed" message lands the
# first time it'd matter for that event type (a key WAS set but local mode
# preempted it) and stays quiet thereafter. Per-path rather than a single
# global flag, since decisions and usage each warrant their own
# first-suppression notice.
_logged_local_mode_suppressed: set[str] = set()

# One sender per (api_key, path) pair. A single process may wrap agents for
# several tenants/keys and emit more than one event type, and each pair must
# emit with its own bearer token to its own endpoint — so senders are keyed
# by the pair rather than kept as a first-wins singleton or keyed by api_key
# alone (which would make a usage sender for an already-configured decisions
# key silently reuse the decisions sender and POST to the wrong endpoint).
# The registry is unbounded and assumes a small, fixed key set per process;
# a key-per-request pattern would leak one sender + httpx pool per unique
# pair. Such callers must evict explicitly (await sender.close(), then drop
# the dict entry) or use shutdown().
_senders: dict[tuple[str, str], AuditSender] = {}


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
    path: str,
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the sender for ``(api_key, path)``. Idempotent per pair.

    Both ``api_key``/``base_url`` fall back to ``HEXGATE_API_KEY`` /
    ``HEXGATE_API_URL`` env vars. Reuses the existing sender when the same
    pair was already configured; distinct pairs get distinct senders.
    Returns ``None`` when no api_key is resolvable — the caller's event type
    stays inert.

    Also returns ``None`` when ``HEXGATE_LOCAL_MODE`` is set in env, even if
    a key was resolvable — that's the "I have a key in .env but I'm
    iterating locally and don't want cloud writes" path (``hexgate chat``
    opts in via ``bootstrap(local_only=True)``), shared by every event type
    that goes through this registry.
    """
    if _local_mode_active():
        # Only log when a key was actually present — otherwise the
        # message is just noise during a no-key local run.
        resolved = resolve_api_key(api_key)
        if resolved and path not in _logged_local_mode_suppressed:
            _log.info(
                "sender suppressed for %s: %s=1 (a key is configured but "
                "local mode is on, so events stay on this machine)",
                path,
                _LOCAL_MODE_ENV,
            )
            _logged_local_mode_suppressed.add(path)
        return None
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        return None
    cache_key = (resolved_key, path)
    existing = _senders.get(cache_key)
    if existing is not None:
        return existing
    resolved_url = resolve_api_url(base_url)
    sender = AuditSender(endpoint=f"{resolved_url}{path}", api_key=resolved_key)
    _senders[cache_key] = sender
    return sender


def get_sender(path: str, api_key: str | None = None) -> AuditSender | None:
    """Return the sender for ``(api_key, path)`` (api_key falling back to
    ``HEXGATE_API_KEY``), if configured. Never creates one."""
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        return None
    return _senders.get((resolved_key, path))


async def shutdown() -> None:
    """Drain in-flight emits and close every sender for every path.

    Safe to call multiple times. Drains the whole shared registry — calling
    this from either ``hexgate.audit`` or ``hexgate.tracing.usage`` closes
    both event types' senders in one shot."""
    senders = list(_senders.values())
    _senders.clear()
    await asyncio.gather(*(s.close() for s in senders), return_exceptions=True)
