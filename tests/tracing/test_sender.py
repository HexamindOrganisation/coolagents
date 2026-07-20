"""AuditSender behavior. Mocks the httpx.AsyncClient on the sender instance.

Moved here from tests/audit/ under Design C: AuditSender is a fully generic
sender (it only depends on ``event.as_payload()``), now living in
hexgate.tracing._senders and shared by hexgate.audit and
hexgate.tracing.usage — its own tests belong next to it, not under
tests/audit/.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from hexgate.audit import AuditEvent
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing._senders import AuditSender

_LOGGER_NAME = "hexgate.tracing._senders"


def _event() -> AuditEvent:
    d = Decision(outcome=DecisionOutcome.DENY, agent_name="r", tool_name="t")
    return AuditEvent(decision=d, user_id="u", session_id="s")


def _stub_client(status: int = 202) -> MagicMock:
    client = MagicMock()
    client.post = AsyncMock(return_value=MagicMock(status_code=status, text=""))
    client.aclose = AsyncMock()
    return client


def _stub_sync_client(status: int = 202) -> MagicMock:
    client = MagicMock()
    client.post = MagicMock(return_value=MagicMock(status_code=status, text=""))
    client.close = MagicMock()
    return client


async def test_emit_schedules_task_and_returns_immediately() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    sender.emit(_event())
    assert len(sender._tasks) == 1
    await asyncio.gather(*sender._tasks)
    sender._client.post.assert_called_once()


async def test_emit_post_carries_endpoint_and_wire_body() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    sender.emit(_event())
    await asyncio.gather(*sender._tasks)
    args, kwargs = sender._client.post.call_args
    assert args[0] == "http://x/y"
    assert kwargs["json"]["outcome"] == "deny"
    assert kwargs["json"]["user_id"] == "u"
    assert kwargs["json"]["session_id"] == "s"


def test_constructor_sets_bearer_header() -> None:
    """Real httpx.AsyncClient constructed in __init__ carries the bearer header."""
    sender = AuditSender("http://x/y", "k")
    assert sender._client.headers["Authorization"] == "Bearer k"


async def test_semaphore_saturation_drops_events(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k", max_in_flight=1)
    await sender._semaphore.acquire()
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
            for _ in range(5):
                sender.emit(_event())
        assert sender._dropped == 5
        assert any("dropped" in r.message for r in caplog.records)
    finally:
        sender._semaphore.release()


async def test_503_triggers_one_retry() -> None:
    sender = AuditSender("http://x/y", "k", http_timeout=0.01)
    sender._client = MagicMock()
    sender._client.post = AsyncMock(
        side_effect=[
            MagicMock(status_code=503, text="busy"),
            MagicMock(status_code=202, text=""),
        ]
    )
    sender._client.aclose = AsyncMock()
    sender.emit(_event())
    await asyncio.gather(*sender._tasks)
    assert sender._client.post.await_count == 2


async def test_close_drains_in_flight_then_acloses_client() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    sender._sync_client = MagicMock()
    sender.emit(_event())
    sender.emit(_event())
    assert len(sender._tasks) == 2
    await sender.close()
    assert len(sender._tasks) == 0
    sender._client.aclose.assert_awaited_once()
    sender._sync_client.close.assert_called_once()


async def test_post_close_emit_is_noop() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    await sender.close()
    sender.emit(_event())
    assert len(sender._tasks) == 0


async def test_network_error_logged_not_raised(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = MagicMock()
    sender._client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
    sender._client.aclose = AsyncMock()
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        sender.emit(_event())
        await asyncio.gather(*sender._tasks)
    assert any("network error" in r.message for r in caplog.records)


def test_emit_when_no_running_loop_then_falls_back_to_spawn_sync_send() -> None:
    """No running loop and no bound loop (built outside any loop, e.g. a
    pydantic_ai run_sync()-only caller): emit dispatches to the bounded
    background-thread fallback instead of dropping the event."""
    sender = AuditSender("http://x/y", "k")
    assert sender._loop is None
    sender._spawn_sync_send = MagicMock()
    event = _event()

    sender.emit(event)

    sender._spawn_sync_send.assert_called_once_with(event)


def test_emit_when_call_soon_threadsafe_raises_then_falls_back_to_sync_send() -> None:
    """Loop torn down between the is_closed() check and call_soon_threadsafe:
    this race no longer drops the event — it falls back to the same path
    used when there's no loop at all, instead of being swallowed silently."""
    sender = AuditSender("http://x/y", "k")
    assert sender._loop is None  # built outside any running loop
    fake_loop = MagicMock()
    fake_loop.is_closed.return_value = False
    fake_loop.call_soon_threadsafe.side_effect = RuntimeError("loop closed mid-call")
    sender._loop = fake_loop
    sender._spawn_sync_send = MagicMock()
    event = _event()

    sender.emit(event)  # must not raise

    assert len(sender._tasks) == 0
    sender._spawn_sync_send.assert_called_once_with(event)


def test_spawn_sync_send_happy_path() -> None:
    """Spawns a non-daemon background thread that sends the event via
    _send_sync. Non-daemon is the invariant under test: a run_sync()-only
    script commonly exits moments after emit() returns, and a daemon thread
    would get killed before the send completes — silently reproducing the
    exact drop this fallback exists to fix."""
    sender = AuditSender("http://x/y", "k")
    release = threading.Event()
    client = MagicMock()

    def _post(endpoint: str, json: dict) -> MagicMock:
        release.wait(timeout=2)
        return MagicMock(status_code=202, text="")

    client.post = MagicMock(side_effect=_post)
    sender._sync_client = client

    sender._spawn_sync_send(_event())

    matching = [t for t in threading.enumerate() if t.name == "hexgate-audit-send-sync"]
    assert len(matching) == 1
    assert matching[0].daemon is False
    release.set()
    matching[0].join(timeout=2)
    client.post.assert_called_once()


def test_spawn_sync_send_when_closing_then_no_thread_is_created() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._closing = True
    before = {t.ident for t in threading.enumerate()}

    sender._spawn_sync_send(_event())

    assert {t.ident for t in threading.enumerate()} == before


def test_spawn_sync_send_when_closing_flips_mid_construction_then_not_registered() -> (
    None
):
    """Regression: the fast self._closing check at the top of
    _spawn_sync_send isn't authoritative — a thread can pass it, then still
    be constructing/registering when close() flips _closing and snapshots
    _sync_threads moments later. The authoritative recheck happens under
    self._sync_lock, in the same critical section close() uses, so it must
    catch this case: freeze a caller right after it constructs its Thread
    object (before the lock-protected recheck), flip _closing + snapshot
    exactly as close() does, then let it proceed and confirm it backs out
    cleanly instead of registering into a snapshot that's already been
    taken."""
    sender = AuditSender("http://x/y", "k")
    constructed = threading.Event()
    proceed = threading.Event()
    real_thread_cls = threading.Thread

    class _PausingThread(real_thread_cls):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            constructed.set()
            proceed.wait(timeout=2)

    with patch("hexgate.tracing._senders.threading.Thread", _PausingThread):
        spawner = real_thread_cls(target=sender._spawn_sync_send, args=(_event(),))
        spawner.start()
        assert constructed.wait(timeout=2), "thread construction never happened"

        # Simulate close()'s atomic flip+snapshot while the caller above is
        # paused between constructing its thread and registering it.
        with sender._sync_lock:
            sender._closing = True
            pending = list(sender._sync_threads)
        assert pending == [], "race window: nothing registered yet"

        proceed.set()
        spawner.join(timeout=2)

    assert sender._sync_threads == set()  # backed out, didn't register
    assert sender._sync_semaphore.acquire(blocking=False)  # slot given back, not leaked


def test_spawn_sync_send_when_saturated_then_event_is_dropped(
    caplog: "logging.LogCaptureFixture",
) -> None:
    """Mirrors test_semaphore_saturation_drops_events, but for the
    thread-based fallback path: bounded the same way, by the same
    max_in_flight value, applied to threading.Semaphore instead of
    asyncio.Semaphore."""
    sender = AuditSender("http://x/y", "k", max_in_flight=1)
    sender._sync_semaphore.acquire()  # simulate one send already in flight
    try:
        with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
            for _ in range(5):
                sender._spawn_sync_send(_event())
        assert sender._sync_dropped == 5
        assert any("dropped" in r.message for r in caplog.records)
    finally:
        sender._sync_semaphore.release()


def test_send_sync_happy_path() -> None:
    """_send_sync has no loop dependency, unlike _send, so it can be called
    directly from the test thread — no need to spawn or join anything."""
    sender = AuditSender("http://x/y", "k")
    sender._sync_client = _stub_sync_client()

    sender._send_sync(_event())

    sender._sync_client.post.assert_called_once()
    args, kwargs = sender._sync_client.post.call_args
    assert args[0] == "http://x/y"
    assert kwargs["json"]["outcome"] == "deny"


def test_send_sync_when_status_is_503_then_retries_once() -> None:
    sender = AuditSender("http://x/y", "k", http_timeout=0.01)
    client = MagicMock()
    client.post = MagicMock(
        side_effect=[
            MagicMock(status_code=503, text="busy"),
            MagicMock(status_code=202, text=""),
        ]
    )
    sender._sync_client = client

    sender._send_sync(_event())

    assert client.post.call_count == 2


def test_send_sync_when_request_error_then_logged_not_raised(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k")
    client = MagicMock()
    client.post = MagicMock(side_effect=httpx.ConnectError("refused"))
    sender._sync_client = client

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        sender._send_sync(_event())

    assert any("network error" in r.message for r in caplog.records)


async def test_emit_from_executor_thread_routes_to_bound_loop() -> None:
    """Off-loop emit (sync tool on a run_in_executor thread) routes to the
    build-time loop instead of being dropped."""
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    assert sender._loop is asyncio.get_running_loop()  # captured at construction

    loop = asyncio.get_running_loop()
    # Emit from a worker thread, exactly as BaseTool.ainvoke runs a sync tool.
    await loop.run_in_executor(None, sender.emit, _event())
    # Pump the loop until the send runs. The task self-discards on completion,
    # so the durable signal is the POST, not a transient _tasks count.
    for _ in range(100):
        if sender._client.post.await_count:
            break
        await asyncio.sleep(0)

    await asyncio.gather(*sender._tasks)
    sender._client.post.assert_called_once()


def test_spawn_send_when_closing_then_no_task_is_created() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._closing = True
    sender._spawn_send(_event())
    assert len(sender._tasks) == 0


async def test_send_when_client_is_none_then_runtimeerror_is_raised() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = None
    with pytest.raises(RuntimeError, match="before start"):
        await sender._send(_event())


async def test_send_when_response_status_is_4xx_then_failure_is_logged(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = MagicMock()
    sender._client.post = AsyncMock(
        return_value=MagicMock(status_code=404, text="not found")
    )
    sender._client.aclose = AsyncMock()
    with caplog.at_level(logging.ERROR, logger=_LOGGER_NAME):
        sender.emit(_event())
        await asyncio.gather(*sender._tasks)
    assert any("ingest failed" in r.message for r in caplog.records)


async def test_close_when_drain_times_out_then_warning_is_logged(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = _stub_client()
    task = asyncio.create_task(asyncio.sleep(10))
    sender._tasks.add(task)
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        await sender.close(drain_timeout=0.01)
    assert any("drain timed out" in r.message for r in caplog.records)
    assert task.cancelled()


async def test_close_joins_in_flight_sync_send_before_closing_the_client() -> None:
    """Regression: close() must not tear down self._sync_client while a
    fallback thread is still using it. A run_sync()-only script commonly
    wraps its final cleanup in a fresh asyncio.run(hexgate.shutdown()) —
    that reaches close() on a brand-new loop while a _send_sync() thread
    spawned moments earlier may still be in flight, so this race is real,
    not hypothetical."""
    sender = AuditSender("http://x/y", "k")
    started = threading.Event()
    release = threading.Event()
    client = MagicMock()

    def _post(endpoint: str, json: dict) -> MagicMock:
        started.set()
        release.wait(timeout=2)
        return MagicMock(status_code=202, text="")

    client.post = MagicMock(side_effect=_post)
    client.close = MagicMock()
    sender._sync_client = client

    sender._spawn_sync_send(_event())
    assert started.wait(timeout=2), "sync send never started"

    close_task = asyncio.create_task(sender.close())
    await asyncio.sleep(0.05)  # let close() reach the join
    assert not client.close.called, "client closed while a send was still in flight"

    release.set()
    await close_task

    client.close.assert_called_once()
    client.post.assert_called_once()


async def test_close_when_sync_drain_times_out_then_warning_is_logged(
    caplog: "logging.LogCaptureFixture",
) -> None:
    sender = AuditSender("http://x/y", "k")
    hang = threading.Event()
    client = MagicMock()

    def _post(endpoint: str, json: dict) -> MagicMock:
        hang.wait(timeout=5)
        return MagicMock(status_code=202, text="")

    client.post = MagicMock(side_effect=_post)
    client.close = MagicMock()
    sender._sync_client = client

    sender._spawn_sync_send(_event())
    await asyncio.sleep(0.05)  # let the thread actually start

    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        await sender.close(drain_timeout=0.01)

    assert any("sync drain timed out" in r.message for r in caplog.records)
    client.close.assert_called_once()  # still closes even after a timed-out drain

    hang.set()  # release the still-running thread so it doesn't outlive the test
    for t in threading.enumerate():
        if t.name == "hexgate-audit-send-sync":
            t.join(timeout=2)


async def test_close_when_client_is_none_then_no_error_is_raised() -> None:
    sender = AuditSender("http://x/y", "k")
    sender._client = None
    await sender.close()  # must not raise


def test_rebuilds_loop_bound_state_across_event_loops() -> None:
    """A sender reused across two asyncio.run() loops rebuilds its loop-bound
    client + semaphore instead of raising 'bound to a different event loop'."""
    sender = AuditSender("http://x/y", "k")
    sender._new_client = _stub_client  # rebuild uses a stub, not a real client
    sender._client = _stub_client()

    async def _emit_and_drain() -> None:
        sender.emit(_event())
        await asyncio.gather(*sender._tasks)

    asyncio.run(_emit_and_drain())
    first_loop, first_client, first_sem = (
        sender._loop,
        sender._client,
        sender._semaphore,
    )

    asyncio.run(_emit_and_drain())  # fresh loop — must not raise

    assert sender._loop is not first_loop
    assert sender._client is not first_client  # rebuilt on the new loop
    assert sender._semaphore is not first_sem
    sender._client.post.assert_called_once()
