"""Unit tests for the shared StreamAccumulator base + run_normalizer.

Exercises the framework-agnostic bookkeeping (blocks, tool correlation, state
inference, run bracketing) directly via a trivial subclass, plus the
``run_normalizer`` drive loop, so each adapter's tests only need to cover its
own ``consume`` mapping.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from hexgate.streaming import (
    BlockDeltaEvent,
    BlockStartEvent,
    BlockType,
    ErrorEvent,
    EventType,
    RunEndEvent,
    ToolCallState,
    ToolEndEvent,
    ToolStartEvent,
)
from hexgate.streaming._accumulator import (
    StreamAccumulator,
    _jsonable,
    run_normalizer,
)


class _Acc(StreamAccumulator):
    """Minimal subclass — tests drive the emit_* helpers directly."""

    def consume(self, event: Any) -> list:
        # Echo helper: a ("delta", text) tuple emits a text delta, so
        # run_normalizer can be driven end to end.
        if isinstance(event, tuple) and event[0] == "delta":
            return self.emit_delta("text", BlockType.TEXT, event[1])
        return []


def test_jsonable_passes_native_and_stringifies_unknown() -> None:
    assert _jsonable({"a": 1}) == {"a": 1}
    assert _jsonable("x") == "x"

    class _Weird:
        def __repr__(self) -> str:
            return "WEIRD"

    assert _jsonable(_Weird()) == "WEIRD"


def test_emit_delta_opens_block_once_then_appends() -> None:
    acc = _Acc("q")
    first = acc.emit_delta("text", BlockType.TEXT, "Hel")
    second = acc.emit_delta("text", BlockType.TEXT, "lo")

    assert [type(e) for e in first] == [BlockStartEvent, BlockDeltaEvent]
    # Same key → no second BlockStart, just a delta.
    assert [type(e) for e in second] == [BlockDeltaEvent]
    assert "".join(acc.message_parts) == "Hello"


def test_emit_delta_separates_text_and_reasoning() -> None:
    acc = _Acc("q")
    acc.emit_delta("text", BlockType.TEXT, "answer")
    acc.emit_delta("reasoning", BlockType.REASONING, "thinking")
    assert len(acc.blocks) == 2
    # Reasoning text does not leak into the assistant message.
    assert "".join(acc.message_parts) == "answer"


def test_empty_delta_is_noop() -> None:
    acc = _Acc("q")
    assert acc.emit_delta("text", BlockType.TEXT, "") == []
    assert acc.blocks == {}


def test_tool_start_closes_open_block_and_records_call() -> None:
    acc = _Acc("q")
    acc.emit_delta("text", BlockType.TEXT, "hi")
    events = acc.emit_tool_start("c1", "refund", {"amount": 5})
    kinds = [e.event_type for e in events]
    # Open text block is finalized before the tool starts.
    assert kinds == [EventType.BLOCK_END, EventType.TOOL_START]
    assert acc.tool_calls["c1"] == ("refund", {"amount": 5})


def test_tool_end_infers_failed_from_ok_false() -> None:
    acc = _Acc("q")
    acc.emit_tool_start("c1", "refund", {})
    [end] = acc.emit_tool_end("c1", {"ok": False, "error": {"message": "nope"}})
    assert isinstance(end, ToolEndEvent)
    assert end.state == ToolCallState.FAILED
    assert end.output_summary == "nope"
    assert end.tool_name == "refund"


def test_tool_end_state_override_wins() -> None:
    acc = _Acc("q")
    acc.emit_tool_start("c1", "t", {})
    [end] = acc.emit_tool_end("c1", "fine", state_override=ToolCallState.FAILED)
    assert end.state == ToolCallState.FAILED


def test_callless_tool_start_end_share_id() -> None:
    acc = _Acc("q")
    start = acc.emit_tool_start(None, "shell", {})
    [end] = acc.emit_tool_end(None, "ok")
    tool_start = next(e for e in start if isinstance(e, ToolStartEvent))
    assert tool_start.tool_id == end.tool_id


def test_tool_end_raw_output_is_jsonable() -> None:
    acc = _Acc("q")
    acc.emit_tool_start("c1", "t", {})

    class _Weird:
        pass

    acc.emit_tool_end("c1", _Weird())
    step = acc.steps[-1]
    # Stored form must be a string (json-safe), not the raw object.
    assert isinstance(step.raw_output, str)


def test_finish_brackets_empty_run() -> None:
    acc = _Acc("q")
    out = acc.finish()
    assert [e.event_type for e in out] == [EventType.RUN_START, EventType.RUN_END]


def test_error_emits_run_start_then_error_no_run_end() -> None:
    acc = _Acc("q")
    out = acc.error("boom")
    assert [e.event_type for e in out] == [EventType.RUN_START, EventType.ERROR]
    assert not any(isinstance(e, RunEndEvent) for e in out)


def test_finish_closes_an_open_tool_call() -> None:
    # A run that ends after a tool start with no matching end must not leave the
    # tool stuck at STARTED in ChatState.
    acc = _Acc("q")
    acc.emit_tool_start("c1", "refund", {"amount": 5})
    out = acc.finish()
    ends = [e for e in out if isinstance(e, ToolEndEvent)]
    assert len(ends) == 1
    assert ends[0].tool_id == "c1"
    assert ends[0].state == ToolCallState.FAILED


def test_error_closes_an_open_tool_call() -> None:
    acc = _Acc("q")
    acc.emit_tool_start("c1", "refund", {})
    out = acc.error("boom")
    ends = [e for e in out if isinstance(e, ToolEndEvent)]
    assert len(ends) == 1 and ends[0].state == ToolCallState.FAILED


def test_completed_tool_is_not_reclosed_on_finish() -> None:
    acc = _Acc("q")
    acc.emit_tool_start("c1", "t", {})
    acc.emit_tool_end("c1", "ok")
    out = acc.finish()
    # Only the run-end; the already-ended tool is not closed again.
    assert not any(isinstance(e, ToolEndEvent) for e in out)


async def _aiter(items: list[Any]) -> AsyncIterator[Any]:
    for item in items:
        yield item


async def test_run_normalizer_brackets_a_clean_stream() -> None:
    acc = _Acc("hello")
    out = [
        e async for e in run_normalizer(acc, _aiter([("delta", "hi"), ("delta", "!")]))
    ]
    kinds = [e.event_type for e in out]
    assert kinds[0] == EventType.RUN_START
    assert kinds[-1] == EventType.RUN_END
    run_end = out[-1]
    assert isinstance(run_end, RunEndEvent)
    assert run_end.result.message == "hi!"


async def test_run_normalizer_turns_a_raise_into_terminal_error() -> None:
    async def _boom() -> AsyncIterator[Any]:
        yield ("delta", "partial")
        raise RuntimeError("kaboom")

    acc = _Acc("q")
    out = [e async for e in run_normalizer(acc, _boom())]
    assert isinstance(out[-1], ErrorEvent)
    assert "kaboom" in out[-1].message
    assert not any(isinstance(e, RunEndEvent) for e in out)
