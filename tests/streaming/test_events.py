"""Tests for stream and run result datatypes."""

from __future__ import annotations

from datetime import UTC

from pydantic import TypeAdapter

from hexgate.streaming import (
    AgentRunResult,
    BlockDeltaEvent,
    BlockEndEvent,
    BlockStartEvent,
    BlockType,
    ErrorEvent,
    EventType,
    ReasoningStep,
    RunEndEvent,
    RunStartEvent,
    Step,
    StepType,
    StreamEvent,
    TextStep,
    ToolCallState,
    ToolCallStep,
    ToolEndEvent,
    ToolStartEvent,
    ToolUpdateEvent,
)


def test_step_union_preserves_discriminated_types() -> None:
    """Parse mixed step payloads into the expected concrete models."""
    adapter = TypeAdapter(Step)

    text_step = adapter.validate_python(
        {
            "type": StepType.TEXT,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 1,
            "text": "Hello",
        }
    )
    reasoning_step = adapter.validate_python(
        {
            "type": StepType.REASONING,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 2,
            "text": "Need to search first.",
        }
    )
    tool_step = adapter.validate_python(
        {
            "type": StepType.TOOL_CALL,
            "run_id": "run-2",
            "root_run_id": "run-1",
            "parent_run_id": "run-1",
            "depth": 1,
            "sequence": 3,
            "tool_name": "web_search",
            "arguments": {"query": "langchain"},
            "state": ToolCallState.COMPLETED,
            "output_summary": "2 results",
        }
    )

    assert isinstance(text_step, TextStep)
    assert text_step.text == "Hello"
    assert isinstance(reasoning_step, ReasoningStep)
    assert reasoning_step.text == "Need to search first."
    assert isinstance(tool_step, ToolCallStep)
    assert tool_step.parent_run_id == "run-1"
    assert tool_step.depth == 1


def test_agent_run_result_keeps_step_order() -> None:
    """Store steps in the exact order they were executed."""
    result = AgentRunResult(
        run_id="run-1",
        root_run_id="run-1",
        message="Final answer",
        steps=[
            ReasoningStep(
                run_id="run-1",
                root_run_id="run-1",
                sequence=1,
                text="Think first.",
            ),
            ToolCallStep(
                run_id="run-1",
                root_run_id="run-1",
                sequence=2,
                tool_name="fetch",
                arguments={"url": "https://example.com"},
                state=ToolCallState.COMPLETED,
            ),
            TextStep(
                run_id="run-1",
                root_run_id="run-1",
                sequence=3,
                text="Here is the answer.",
            ),
        ],
    )

    assert [step.sequence for step in result.steps] == [1, 2, 3]
    assert [step.type for step in result.steps] == [
        StepType.REASONING,
        StepType.TOOL_CALL,
        StepType.TEXT,
    ]


def test_stream_event_union_parses_all_primary_event_types() -> None:
    """Parse representative event payloads into concrete event models."""
    adapter = TypeAdapter(StreamEvent)

    run_start = adapter.validate_python(
        {
            "event_type": EventType.RUN_START,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 1,
            "query": "What is LangChain?",
        }
    )
    block_start = adapter.validate_python(
        {
            "event_type": EventType.BLOCK_START,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 2,
            "block_id": "block-1",
            "block_type": BlockType.TEXT,
        }
    )
    block_delta = adapter.validate_python(
        {
            "event_type": EventType.BLOCK_DELTA,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 3,
            "block_id": "block-1",
            "block_type": BlockType.TEXT,
            "text": "Hello",
        }
    )
    tool_start = adapter.validate_python(
        {
            "event_type": EventType.TOOL_START,
            "run_id": "run-tool",
            "root_run_id": "run-1",
            "parent_run_id": "run-1",
            "depth": 1,
            "sequence": 4,
            "tool_id": "tool-1",
            "tool_name": "web_search",
            "arguments": {"query": "langchain"},
        }
    )
    tool_end = adapter.validate_python(
        {
            "event_type": EventType.TOOL_END,
            "run_id": "run-tool",
            "root_run_id": "run-1",
            "parent_run_id": "run-1",
            "depth": 1,
            "sequence": 5,
            "tool_id": "tool-1",
            "tool_name": "web_search",
            "state": ToolCallState.COMPLETED,
            "output_summary": "2 results",
        }
    )
    run_end = adapter.validate_python(
        {
            "event_type": EventType.RUN_END,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 6,
            "result": {
                "run_id": "run-1",
                "root_run_id": "run-1",
                "message": "Done",
                "steps": [],
            },
        }
    )
    error = adapter.validate_python(
        {
            "event_type": EventType.ERROR,
            "run_id": "run-1",
            "root_run_id": "run-1",
            "sequence": 7,
            "message": "boom",
        }
    )

    assert isinstance(run_start, RunStartEvent)
    assert isinstance(block_start, BlockStartEvent)
    assert isinstance(block_delta, BlockDeltaEvent)
    assert isinstance(tool_start, ToolStartEvent)
    assert isinstance(tool_end, ToolEndEvent)
    assert isinstance(run_end, RunEndEvent)
    assert isinstance(error, ErrorEvent)


def test_stream_events_preserve_hierarchy_fields() -> None:
    """Retain parent-child ancestry metadata for nested runs."""
    event = ToolUpdateEvent(
        run_id="run-child",
        root_run_id="run-root",
        parent_run_id="run-parent",
        depth=2,
        sequence=9,
        tool_id="tool-1",
        tool_name="fetch",
        text="Downloaded page",
    )

    assert event.run_id == "run-child"
    assert event.root_run_id == "run-root"
    assert event.parent_run_id == "run-parent"
    assert event.depth == 2


def test_default_event_metadata_is_populated() -> None:
    """Populate generated identifiers and UTC timestamps automatically."""
    event = BlockEndEvent(
        run_id="run-1",
        root_run_id="run-1",
        sequence=4,
        block_id="block-1",
        block_type=BlockType.REASONING,
    )

    assert event.event_id
    assert event.timestamp.tzinfo == UTC


def test_tool_call_step_defaults_are_sensible() -> None:
    """Use safe defaults for tool call persistence fields."""
    step = ToolCallStep(
        run_id="run-1",
        root_run_id="run-1",
        sequence=2,
        tool_name="fetch",
    )

    assert step.arguments == {}
    assert step.state == ToolCallState.STARTED
    assert step.output_summary is None
