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
import threading
import time
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
    """Fire-and-forget POST for a single ``(api_key, path)`` pair.

    emit() is sync and non-blocking. When a live event loop is available it
    schedules an asyncio task, bounded by ``self._semaphore``
    (``max_in_flight``). When none is available anywhere in the process
    (e.g. a purely-synchronous caller like pydantic_ai's ``run_sync()``,
    which drives its own loop internally and closes it before returning
    control here), it spawns a plain background thread instead, bounded the
    same way by ``self._sync_semaphore``. Both paths drop with a periodic
    log when saturated (platform slow/unreachable, or too many concurrent
    callers) rather than growing an unbounded backlog.
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
        # Fallback for when no asyncio loop exists anywhere in the process
        # (e.g. a caller built purely on pydantic_ai's run_sync()): a plain
        # background thread instead of an asyncio task. Bounded by the same
        # max_in_flight ceiling as self._semaphore, just applied to a
        # different resource (OS threads instead of asyncio tasks).
        # httpx.Client, unlike AsyncClient, has no event-loop affinity, so
        # it's safe to build eagerly here rather than lazily on first use.
        self._sync_semaphore = threading.Semaphore(max_in_flight)
        self._sync_client = self._new_sync_client()
        self._sync_dropped = 0
        # Tracked so close() can join outstanding sends before tearing down
        # self._sync_client out from under them. Needed for real: a script
        # built purely on run_sync() can still spin up its own
        # asyncio.run(hexgate.shutdown()) as its very last action (the
        # documented shutdown pattern, hexgate/audit.py:4) — a fresh loop
        # started just for that call reaches close() same as any other
        # caller, so this can and does overlap with an in-flight sync send.
        #
        # Also guards self._sync_dropped: unlike self._dropped (only ever
        # touched on the single event-loop thread), _spawn_sync_send can
        # run concurrently on real OS threads whenever several no-loop
        # callers hit saturation at once — a plain += there would be a
        # lost-update race.
        self._sync_threads: set[threading.Thread] = set()
        self._sync_lock = threading.Lock()

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=self._http_timeout,
            headers={"Authorization": f"Bearer {self._api_key}"},
        )

    def _new_sync_client(self) -> httpx.Client:
        return httpx.Client(
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
            # Called off-loop: either a sync tool dispatched to a
            # run_in_executor thread (a live loop is still bound, just not
            # running on *this* thread), or a purely synchronous caller with
            # no loop anywhere in the process (e.g. pydantic_ai's
            # run_sync()). Prefer handing back to the bound loop; only fall
            # to a plain background thread when no loop exists at all.
            loop = self._loop
            if loop is not None and not loop.is_closed():
                try:
                    loop.call_soon_threadsafe(self._spawn_send, event)
                    return
                except RuntimeError:
                    pass  # loop torn down between the is_closed() check and the call
            self._spawn_sync_send(event)
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

    def _spawn_sync_send(self, event: _PayloadEvent) -> None:
        """Fallback for when no asyncio loop exists anywhere to schedule
        ``_spawn_send`` on. Bounded by ``self._sync_semaphore`` the same way
        ``_spawn_send`` is bounded by ``self._semaphore`` — saturated
        callers are dropped immediately rather than piling up an unbounded
        number of OS threads. Threads are non-daemon: a short-lived
        run_sync()-only script is the common caller here, and a daemon
        thread would get killed the instant that script exits, before the
        send completes — silently reproducing the exact bug this fallback
        exists to fix. CPython's own interpreter-shutdown sequence joins
        non-daemon threads instead, bounded by ``self._http_timeout``.

        The ``self._closing`` check below is a fast path only, not the
        authoritative one — it's rechecked under ``self._sync_lock`` right
        before registering the thread, in the same critical section
        ``close()`` uses to flip ``self._closing`` and snapshot
        ``self._sync_threads`` together. Without that, a thread could read
        ``self._closing`` as ``False`` here, then still be constructing/
        registering itself when ``close()`` takes its snapshot moments
        later — landing after the snapshot, never joined, and racing
        ``self._sync_client.close()``."""
        if self._closing:
            return
        if not self._sync_semaphore.acquire(blocking=False):
            with self._sync_lock:
                self._sync_dropped += 1
                dropped = self._sync_dropped
            if dropped % 100 == 1:
                _log.warning(
                    "audit sender saturated (no event loop path); %d events "
                    "dropped (platform slow, or too many concurrent "
                    "synchronous callers?)",
                    dropped,
                )
            return
        thread = threading.Thread(
            target=self._send_sync,
            args=(event,),
            daemon=False,
            name="hexgate-audit-send-sync",
        )
        # Authoritative recheck + registration, one atomic step: if close()
        # already flipped _closing and took its snapshot, don't hand it a
        # thread it'll never wait for — give the semaphore slot back and
        # drop instead of starting a thread that'll race a closed client.
        with self._sync_lock:
            if self._closing:
                self._sync_semaphore.release()
                return
            self._sync_threads.add(thread)
        thread.start()

    def _send_sync(self, event: _PayloadEvent) -> None:
        """Synchronous mirror of ``_send`` for the no-event-loop fallback.
        Runs entirely on its own thread; always releases
        ``self._sync_semaphore`` so the next caller past the cap can
        proceed, and discards itself from ``self._sync_threads`` so close()
        isn't left waiting on threads that already finished."""
        try:
            payload = event.as_payload()
            try:
                response = self._sync_client.post(self._endpoint, json=payload)
                if response.status_code == 503:
                    delay = min(self._http_timeout, 2.0)
                    time.sleep(random.uniform(delay / 2, delay))
                    response = self._sync_client.post(self._endpoint, json=payload)
                if response.status_code >= 400:
                    _log.error(
                        "audit ingest failed: %s %s",
                        response.status_code,
                        response.text[:200],
                    )
            except httpx.RequestError as exc:
                _log.warning("audit ingest network error: %s", exc)
        finally:
            self._sync_semaphore.release()
            with self._sync_lock:
                self._sync_threads.discard(threading.current_thread())

    async def close(self, drain_timeout: float = 5.0) -> None:
        """Stop accepting new emits; drain in-flight tasks; close the HTTP clients."""
        # Flip _closing and snapshot _sync_threads as one atomic step, under
        # the same lock _spawn_sync_send uses for its own closing-recheck +
        # registration. Otherwise a thread could pass _spawn_sync_send's
        # check just before this line, and still be registering itself when
        # the snapshot below is taken — landing after it, never joined.
        with self._sync_lock:
            self._closing = True
            pending = list(self._sync_threads)
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
        # Join outstanding sync-fallback sends before closing the client
        # they share: a run_sync()-only script commonly wraps its final
        # cleanup in its own asyncio.run(hexgate.shutdown()), so close()
        # reaching here concurrently with an in-flight _send_sync() thread
        # is a real case, not a hypothetical one — closing self._sync_client
        # out from under it would abort the send (a bare RuntimeError if
        # the client closes before the request starts, since that's not an
        # httpx.RequestError and isn't caught by _send_sync's handler).
        #
        # Unlike the async drain above — where a asyncio.wait_for timeout
        # actually cancels the tasks, so nothing is still running by the
        # time aclose() fires — Thread.join(timeout=...) timing out leaves
        # the thread genuinely alive with no way to cancel it (no forced
        # thread termination in Python). So on a timed-out sync drain, skip
        # closing the client rather than racing whatever's still running:
        # leave it for the OS to reclaim at process exit, and let a later
        # close() call (safe to call multiple times) finish the job once
        # the thread has actually completed.
        if pending:
            timed_out = await asyncio.to_thread(
                self._join_sync_threads, pending, drain_timeout
            )
            if timed_out:
                _log.warning(
                    "audit close: sync drain timed out with %d thread(s) still "
                    "running; leaving the sync client open rather than closing "
                    "it out from under them",
                    timed_out,
                )
                return
        self._sync_client.close()

    @staticmethod
    def _join_sync_threads(threads: list[threading.Thread], timeout: float) -> int:
        """Join every thread within one shared ``timeout`` budget (not
        ``timeout`` each — mirrors ``asyncio.wait_for``'s total-time bound
        for the async drain above). Returns how many are still alive."""
        deadline = time.monotonic() + timeout
        for t in threads:
            t.join(timeout=max(0.0, deadline - time.monotonic()))
        return sum(1 for t in threads if t.is_alive())


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
