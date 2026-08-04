"""Tests for hexgate.adapters._common's shared drain helper."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from hexgate.adapters._common import drain_pending_tasks
from hexgate.tracing import _senders as senders_mod
from hexgate.tracing._senders import AuditSender


@contextmanager
def _registered_sender(
    key: tuple[str, str] = ("test-key", "/test-path"),
) -> Iterator[AuditSender]:
    """Register a real AuditSender in the shared registry for the duration
    of the test, so pending_send_tasks() can find it — and always evict it
    afterward, since _senders is process-global state shared across the
    whole test session."""
    sender = AuditSender(endpoint="https://example.invalid/test-path", api_key="k")
    senders_mod._senders[key] = sender
    try:
        yield sender
    finally:
        del senders_mod._senders[key]


def _track(sender: AuditSender, loop: asyncio.AbstractEventLoop, coro) -> asyncio.Task:
    """Schedule coro on loop and register it in sender._tasks, mirroring
    what _spawn_send does for a real audit POST."""
    task = loop.create_task(coro)
    sender._tasks.add(task)
    task.add_done_callback(sender._tasks.discard)
    return task


def test_drain_pending_tasks_happy_path() -> None:
    """A sender-tracked task that finishes well within drain_timeout is
    awaited to completion."""
    loop = asyncio.new_event_loop()
    completed: list[bool] = []

    async def _quick() -> None:
        await asyncio.sleep(0.01)
        completed.append(True)

    try:
        with _registered_sender() as sender:
            task = _track(sender, loop, _quick())
            drain_pending_tasks(loop, drain_timeout=5.0)
            assert completed == [True]
            assert task.done()
    finally:
        loop.close()


def test_drain_pending_tasks_when_task_exceeds_timeout_then_it_gives_up() -> None:
    """An unreachable platform can hold a send open well past drain_timeout —
    drain_pending_tasks must return anyway rather than hang the caller's
    run_sync() for the full retry/backoff duration."""
    loop = asyncio.new_event_loop()
    completed: list[bool] = []

    async def _slow() -> None:
        await asyncio.sleep(5.0)
        completed.append(True)

    try:
        with _registered_sender() as sender:
            _track(sender, loop, _slow())
            drain_pending_tasks(loop, drain_timeout=0.05)
            assert completed == []
    finally:
        loop.close()


def test_drain_pending_tasks_when_nothing_pending_then_it_is_a_no_op() -> None:
    loop = asyncio.new_event_loop()
    try:
        with _registered_sender() as sender:
            assert not sender._tasks
            drain_pending_tasks(loop, drain_timeout=5.0)
    finally:
        loop.close()


def test_drain_pending_tasks_ignores_tasks_not_tracked_by_a_sender() -> None:
    """`loop` is a thread's shared default loop, not one hexgate owns
    exclusively — a caller's own unrelated task can be scheduled on it too.
    drain_pending_tasks must not await (or, on timeout, cancel) it."""
    loop = asyncio.new_event_loop()
    completed: list[bool] = []

    async def _unrelated() -> None:
        await asyncio.sleep(5.0)
        completed.append(True)

    try:
        unrelated_task = loop.create_task(_unrelated())
        drain_pending_tasks(loop, drain_timeout=0.05)
        assert not unrelated_task.done()
        assert not unrelated_task.cancelled()
    finally:
        unrelated_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            loop.run_until_complete(unrelated_task)
        loop.close()


def test_drain_pending_tasks_ignores_a_sender_tasks_bound_to_a_different_loop() -> None:
    """The sender registry is process-wide; a concurrently running adapter
    on another thread can own a sender with tasks on its own, different
    loop. Draining must not reach across into that other loop."""
    this_loop = asyncio.new_event_loop()
    other_loop = asyncio.new_event_loop()
    completed: list[bool] = []

    async def _slow() -> None:
        await asyncio.sleep(5.0)
        completed.append(True)

    try:
        with _registered_sender() as sender:
            _track(sender, other_loop, _slow())
            drain_pending_tasks(this_loop, drain_timeout=0.05)
            assert completed == []
            assert sender._tasks  # untouched: still pending on other_loop
    finally:
        this_loop.close()
        for task in list(sender._tasks):
            task.cancel()
        other_loop.run_until_complete(
            asyncio.gather(*sender._tasks, return_exceptions=True)
        )
        other_loop.close()
