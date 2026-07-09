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
from unittest.mock import AsyncMock, MagicMock

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
    sender.emit(_event())
    sender.emit(_event())
    assert len(sender._tasks) == 2
    await sender.close()
    assert len(sender._tasks) == 0
    sender._client.aclose.assert_awaited_once()


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


def test_no_running_loop_skips_silently(caplog: "logging.LogCaptureFixture") -> None:
    """No running loop and no bound loop (built outside any loop): emit
    no-ops with a one-time warning."""
    sender = AuditSender("http://x/y", "k")
    assert sender._loop is None
    with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
        sender.emit(_event())
        sender.emit(_event())  # second call: silent
    assert len(sender._tasks) == 0
    assert sender._warned_no_loop is True
    no_loop_warnings = [r for r in caplog.records if "no live bound loop" in r.message]
    assert len(no_loop_warnings) == 1


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

    assert sender._warned_no_loop is False  # routed, not dropped
    await asyncio.gather(*sender._tasks)
    sender._client.post.assert_called_once()


def test_emit_when_call_soon_threadsafe_raises_then_error_is_swallowed() -> None:
    """Loop torn down between the is_closed() check and call_soon_threadsafe:
    the race is swallowed, not raised."""
    sender = AuditSender("http://x/y", "k")
    assert sender._loop is None  # built outside any running loop
    fake_loop = MagicMock()
    fake_loop.is_closed.return_value = False
    fake_loop.call_soon_threadsafe.side_effect = RuntimeError("loop closed mid-call")
    sender._loop = fake_loop
    sender.emit(_event())  # must not raise
    assert len(sender._tasks) == 0


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
