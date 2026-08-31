"""Unit tests for the Pydantic AI → hexgate StreamEvent normalizer.

Drives ``normalize_pydantic_events`` with hand-built fakes shaped like pydantic
``AgentStreamEvent``s (``event_kind`` + the part/delta/result fields the
normalizer reads via ``getattr``). No live model.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import SimpleNamespace
from typing import Any

from hexgate.adapters.pydantic_ai.streaming import normalize_pydantic_events
from hexgate.streaming import (
    BlockDeltaEvent,
    BlockType,
    ErrorEvent,
    EventType,
    RunEndEvent,
    ToolCallState,
    ToolEndEvent,
    ToolStartEvent,
)


def _part_start(index: int, part: Any) -> SimpleNamespace:
    return SimpleNamespace(event_kind="part_start", index=index, part=part)


def _part_delta(index: int, delta: Any) -> SimpleNamespace:
    return SimpleNamespace(event_kind="part_delta", index=index, delta=delta)


def _text_part(content: str) -> SimpleNamespace:
    return SimpleNamespace(part_kind="text", content=content)


def _thinking_part(content: str) -> SimpleNamespace:
    return SimpleNamespace(part_kind="thinking", content=content)


def _text_delta(content: str) -> SimpleNamespace:
    return SimpleNamespace(part_delta_kind="text", content_delta=content)


def _tool_call(index: int, call_id: str, name: str, args: dict) -> SimpleNamespace:
    part = SimpleNamespace(
        part_kind="tool-call",
        tool_call_id=call_id,
        tool_name=name,
        args_as_dict=lambda: args,
    )
    return SimpleNamespace(event_kind="function_tool_call", part=part)


def _tool_return(
    call_id: str, name: str, content: Any, outcome: str
) -> SimpleNamespace:
    result = SimpleNamespace(
        tool_call_id=call_id, tool_name=name, content=content, outcome=outcome
    )
    return SimpleNamespace(event_kind="function_tool_result", result=result)


def _retry_prompt(call_id: str, name: str, content: str) -> SimpleNamespace:
    # No ``outcome`` attribute → the normalizer treats it as a RetryPromptPart.
    result = SimpleNamespace(tool_call_id=call_id, tool_name=name, content=content)
    return SimpleNamespace(event_kind="function_tool_result", result=result)


async def _aiter(events: list[Any]) -> AsyncIterator[Any]:
    for event in events:
        yield event


async def _collect(events: list[Any], *, query: str = "hi") -> list[Any]:
    return [e async for e in normalize_pydantic_events(_aiter(events), query=query)]


async def test_text_part_and_deltas_stream() -> None:
    out = await _collect(
        [
            _part_start(0, _text_part("Hel")),
            _part_delta(0, _text_delta("lo")),
        ]
    )
    deltas = [e.text for e in out if isinstance(e, BlockDeltaEvent)]
    assert deltas == ["Hel", "lo"]
    run_end = next(e for e in out if isinstance(e, RunEndEvent))
    assert run_end.result.message == "Hello"


async def test_thinking_part_opens_reasoning_block() -> None:
    out = await _collect([_part_start(0, _thinking_part("hmm"))])
    delta = next(e for e in out if isinstance(e, BlockDeltaEvent))
    assert delta.block_type == BlockType.REASONING


async def test_text_blocks_separate_by_index() -> None:
    out = await _collect(
        [_part_start(0, _text_part("a")), _part_start(1, _text_part("b"))]
    )
    starts = [e for e in out if e.event_type == EventType.BLOCK_START]
    assert len(starts) == 2


async def test_function_tool_call_becomes_tool_start() -> None:
    out = await _collect([_tool_call(0, "c1", "refund_order", {"amount": 5})])
    start = next(e for e in out if isinstance(e, ToolStartEvent))
    assert start.tool_id == "c1"
    assert start.tool_name == "refund_order"
    assert start.arguments == {"amount": 5}


async def test_tool_call_part_in_model_stream_is_not_a_duplicate_start() -> None:
    # A ToolCallPart arriving via the model-request stream must be ignored;
    # only FunctionToolCallEvent starts a tool.
    out = await _collect(
        [_part_start(0, SimpleNamespace(part_kind="tool-call", tool_name="x"))]
    )
    assert not any(isinstance(e, ToolStartEvent) for e in out)


async def test_tool_return_success_is_completed() -> None:
    out = await _collect(
        [
            _tool_call(0, "c1", "refund", {}),
            _tool_return("c1", "refund", "Refunded $5", "success"),
        ]
    )
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert end.state == ToolCallState.COMPLETED
    assert end.tool_id == "c1"
    assert end.output_summary == "Refunded $5"


async def test_tool_return_denied_and_failed_are_failed() -> None:
    for outcome in ("denied", "failed"):
        out = await _collect(
            [
                _tool_call(0, "c1", "refund", {}),
                _tool_return("c1", "refund", "blocked", outcome),
            ]
        )
        end = next(e for e in out if isinstance(e, ToolEndEvent))
        assert end.state == ToolCallState.FAILED, outcome


async def test_retry_prompt_marks_tool_failed() -> None:
    out = await _collect(
        [
            _tool_call(0, "c1", "refund", {}),
            _retry_prompt("c1", "refund", "amount must be a number"),
        ]
    )
    end = next(e for e in out if isinstance(e, ToolEndEvent))
    assert end.state == ToolCallState.FAILED


async def test_fatal_error_emits_terminal_error() -> None:
    async def _boom() -> AsyncIterator[Any]:
        yield _part_start(0, _text_part("partial"))
        raise RuntimeError("model exploded")

    out = [e async for e in normalize_pydantic_events(_boom(), query="q")]
    assert isinstance(out[-1], ErrorEvent)
    assert "model exploded" in out[-1].message
    assert not any(isinstance(e, RunEndEvent) for e in out)


async def test_full_sequence_brackets_run() -> None:
    out = await _collect(
        [
            _part_start(0, _text_part("Let me check")),
            _tool_call(1, "c1", "get_order_status", {"order_id": "42"}),
            _tool_return("c1", "get_order_status", "shipped", "success"),
        ]
    )
    kinds = [e.event_type for e in out]
    assert kinds[0] == EventType.RUN_START
    assert kinds[-1] == EventType.RUN_END
    assert EventType.TOOL_START in kinds and EventType.TOOL_END in kinds
