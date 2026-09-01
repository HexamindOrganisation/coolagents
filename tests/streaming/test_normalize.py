"""Tests for LangChain stream normalization."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from langchain_core.messages import AIMessage, AIMessageChunk

from hexgate.streaming import (
    BlockDeltaEvent,
    BlockEndEvent,
    BlockStartEvent,
    RunEndEvent,
    RunStartEvent,
    StepType,
    TextStep,
    ToolCallState,
    ToolEndEvent,
    ToolStartEvent,
    normalize_langchain_events,
)


async def _aiter(items: list[dict]) -> AsyncIterator[dict]:
    """Yield a list of raw events as an async iterator."""
    for item in items:
        yield item


@pytest.mark.asyncio
async def test_normalize_langchain_events_handles_text_only_run() -> None:
    """Convert raw chat model stream events into text block events and final result."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_chat_model_stream",
            "run_id": "model-run",
            "parent_ids": ["root-run"],
            "data": {"chunk": AIMessageChunk(content="Hello ")},
        },
        {
            "event": "on_chat_model_stream",
            "run_id": "model-run",
            "parent_ids": ["root-run"],
            "data": {"chunk": AIMessageChunk(content="world")},
        },
        {
            "event": "on_chat_model_end",
            "run_id": "model-run",
            "parent_ids": ["root-run"],
            "data": {"output": AIMessage(content="Hello world")},
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]

    assert isinstance(events[0], RunStartEvent)
    assert isinstance(events[1], BlockStartEvent)
    assert isinstance(events[2], BlockDeltaEvent)
    assert isinstance(events[3], BlockDeltaEvent)
    assert isinstance(events[4], BlockEndEvent)
    assert isinstance(events[-1], RunEndEvent)
    assert events[-1].result.message == "Hello world"
    assert len(events[-1].result.steps) == 1
    assert isinstance(events[-1].result.steps[0], TextStep)


@pytest.mark.asyncio
async def test_normalize_langchain_events_preserves_tool_order() -> None:
    """Interleave text and tool steps in the order they executed."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_chat_model_stream",
            "run_id": "model-run-1",
            "parent_ids": ["root-run"],
            "data": {"chunk": AIMessageChunk(content="Need search.")},
        },
        {
            "event": "on_tool_start",
            "run_id": "tool-run",
            "name": "web_search",
            "parent_ids": ["root-run"],
            "data": {"input": {"query": "langchain"}},
        },
        {
            "event": "on_tool_end",
            "run_id": "tool-run",
            "name": "web_search",
            "parent_ids": ["root-run"],
            "data": {"input": {"query": "langchain"}, "output": {"results": [1, 2]}},
        },
        {
            "event": "on_chat_model_stream",
            "run_id": "model-run-2",
            "parent_ids": ["root-run"],
            "data": {"chunk": AIMessageChunk(content="Done.")},
        },
        {
            "event": "on_chat_model_end",
            "run_id": "model-run-2",
            "parent_ids": ["root-run"],
            "data": {"output": AIMessage(content="Done.")},
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]
    result = events[-1].result

    assert isinstance(events[0], RunStartEvent)
    assert any(isinstance(event, ToolStartEvent) for event in events)
    assert any(isinstance(event, ToolEndEvent) for event in events)
    assert isinstance(events[-1], RunEndEvent)
    assert result.message == "Need search.Done."
    assert [step.type for step in result.steps] == [
        StepType.TEXT,
        StepType.TOOL_CALL,
        StepType.TEXT,
    ]
    tool_step = result.steps[1]
    assert tool_step.state == ToolCallState.COMPLETED
    assert tool_step.output_summary == "2 results"


@pytest.mark.asyncio
async def test_normalize_langchain_events_tracks_nested_hierarchy() -> None:
    """Derive depth and parent run ids from LangChain parent ids."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_tool_start",
            "run_id": "tool-run",
            "name": "fetch",
            "parent_ids": ["root-run", "subagent-run"],
            "data": {"input": {"url": "https://example.com"}},
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]

    tool_start = next(event for event in events if isinstance(event, ToolStartEvent))
    assert tool_start.root_run_id == "root-run"
    assert tool_start.parent_run_id == "subagent-run"
    assert tool_start.depth == 2


@pytest.mark.asyncio
async def test_normalize_langchain_events_marks_graceful_tool_failure_as_failed() -> (
    None
):
    """Treat structured tool failures as failed tool steps in the normalized stream."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_tool_start",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {"input": {"file_path": "ai_news_report.md"}},
        },
        {
            "event": "on_tool_end",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {
                "input": {"file_path": "ai_news_report.md"},
                "output": {
                    "ok": False,
                    "error": {
                        "type": "policy_denied",
                        "message": 'Policy denied tool "write_file" for the requested path',
                    },
                },
            },
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]

    tool_end = next(event for event in events if isinstance(event, ToolEndEvent))
    result = events[-1].result
    tool_step = next(step for step in result.steps if step.type == StepType.TOOL_CALL)

    assert tool_end.state == ToolCallState.FAILED
    assert (
        tool_end.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )
    assert tool_step.state == ToolCallState.FAILED
    assert (
        tool_step.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )


@pytest.mark.asyncio
async def test_normalize_langchain_events_marks_json_string_tool_failure_as_failed() -> (
    None
):
    """Treat serialized JSON tool failures as failed tool steps too."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_tool_start",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {"input": {"file_path": "latest-ai-breakthroughs.md"}},
        },
        {
            "event": "on_tool_end",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {
                "input": {"file_path": "latest-ai-breakthroughs.md"},
                "output": '{"ok": false, "error": {"type": "policy_denied", "message": "Policy denied tool \\"write_file\\" for the requested path", "tool_name": "write_file", "retryable": false, "hint": {"allowed_paths": ["research_notes/*.md"]}}}',
            },
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]

    tool_end = next(event for event in events if isinstance(event, ToolEndEvent))
    result = events[-1].result
    tool_step = next(step for step in result.steps if step.type == StepType.TOOL_CALL)

    assert tool_end.state == ToolCallState.FAILED
    assert (
        tool_end.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )
    assert tool_step.state == ToolCallState.FAILED
    assert (
        tool_step.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )


@pytest.mark.asyncio
async def test_normalize_langchain_events_marks_wrapped_content_tool_failure_as_failed() -> (
    None
):
    """Treat content-wrapped JSON tool failures as failed tool steps too."""
    raw_events = [
        {
            "event": "on_chain_start",
            "run_id": "root-run",
            "parent_ids": [],
            "data": {"input": {"messages": [{"role": "user", "content": "hi"}]}},
        },
        {
            "event": "on_tool_start",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {"input": {"file_path": "latest-ai-breakthroughs.md"}},
        },
        {
            "event": "on_tool_end",
            "run_id": "tool-run",
            "name": "write_file",
            "parent_ids": ["root-run"],
            "data": {
                "input": {"file_path": "latest-ai-breakthroughs.md"},
                "output": {
                    "content": '{"ok": false, "error": {"type": "policy_denied", "message": "Policy denied tool \\"write_file\\" for the requested path"}}'
                },
            },
        },
    ]

    events = [
        event
        async for event in normalize_langchain_events(_aiter(raw_events), query="hi")
    ]

    tool_end = next(event for event in events if isinstance(event, ToolEndEvent))
    result = events[-1].result
    tool_step = next(step for step in result.steps if step.type == StepType.TOOL_CALL)

    assert tool_end.state == ToolCallState.FAILED
    assert (
        tool_end.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )
    assert tool_step.state == ToolCallState.FAILED
    assert (
        tool_step.output_summary
        == 'Policy denied tool "write_file" for the requested path'
    )
