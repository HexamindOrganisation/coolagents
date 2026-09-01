"""Helpers for normalizing LangChain event streams."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from langchain_core.messages import AIMessageChunk

from hexgate.streaming.events import (
    AgentRunResult,
    BlockDeltaEvent,
    BlockEndEvent,
    BlockStartEvent,
    BlockType,
    ErrorEvent,
    ReasoningStep,
    RunEndEvent,
    RunStartEvent,
    StreamEvent,
    TextStep,
    ToolCallState,
    ToolCallStep,
    ToolEndEvent,
    ToolStartEvent,
)


def new_root_run_id() -> str:
    """Return a fresh root run identifier."""
    return str(uuid4())


def _root_run_id(run_id: str, parent_ids: list[str]) -> str:
    """Resolve the root run id from a raw LangChain event."""
    return parent_ids[0] if parent_ids else run_id


def _parent_run_id(parent_ids: list[str]) -> str | None:
    """Resolve the direct parent run id from a raw LangChain event."""
    return parent_ids[-1] if parent_ids else None


def _extract_chunk_text(chunk: Any) -> str:
    """Extract visible text from a streamed LangChain chunk."""
    if isinstance(chunk, AIMessageChunk):
        content = chunk.content
        if isinstance(content, str):
            return content
        if not isinstance(content, list):
            return ""

        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
                continue
            if not isinstance(block, dict):
                continue
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
        return "".join(parts)

    if isinstance(chunk, str):
        return chunk

    return ""


def _summarize_output(output: Any) -> str | None:
    """Build a short summary string for a tool output."""
    if output is None:
        return None
    if isinstance(output, str):
        compact = " ".join(output.split())
        return compact[:200] + ("..." if len(compact) > 200 else "")
    if isinstance(output, dict):
        if "title" in output and "url" in output:
            return f"{output.get('title') or 'Untitled'} ({output.get('url')})"
        if "results" in output and isinstance(output["results"], list):
            return f"{len(output['results'])} results"
        return str({key: output[key] for key in list(output)[:3]})
    if isinstance(output, list):
        return f"{len(output)} items"
    return str(output)


def _coerce_tool_output(output: Any) -> Any:
    """Decode common wrapped or serialized tool outputs into structured data."""
    if isinstance(output, str):
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    if isinstance(output, dict):
        if "ok" in output:
            return output
        if "artifact" in output:
            return _coerce_tool_output(output.get("artifact"))
        if "content" in output:
            return _coerce_tool_output(output.get("content"))
        return output

    if isinstance(output, list) and len(output) == 1:
        return _coerce_tool_output(output[0])

    content = getattr(output, "content", None)
    if content is not None:
        return _coerce_tool_output(content)

    artifact = getattr(output, "artifact", None)
    if artifact is not None:
        return _coerce_tool_output(artifact)

    return output


def _tool_end_state(output: Any) -> tuple[ToolCallState, str | None]:
    """Infer the semantic tool state from its final output payload."""
    output = _coerce_tool_output(output)
    if isinstance(output, dict) and output.get("ok") is False:
        error = output.get("error")
        if isinstance(error, dict):
            message = error.get("message")
            if isinstance(message, str) and message:
                return ToolCallState.FAILED, message
        return ToolCallState.FAILED, _summarize_output(output)
    return ToolCallState.COMPLETED, _summarize_output(output)


@dataclass
class _OpenBlock:
    """Track a streamed text or reasoning block before finalization."""

    block_id: str
    block_type: BlockType
    run_id: str
    root_run_id: str
    parent_run_id: str | None
    depth: int
    parts: list[str]


class _RunAccumulator:
    """Accumulate normalized events and final run state from raw events."""

    def __init__(self, query: str) -> None:
        """Initialize a run accumulator for one user query."""
        self.query = query
        self.sequence = 0
        self.root_run_id: str | None = None
        self.open_blocks: dict[str, _OpenBlock] = {}
        self.steps: list[TextStep | ReasoningStep | ToolCallStep] = []
        self.message_parts: list[str] = []
        self.started = False

    def _next_sequence(self) -> int:
        """Return the next normalized event sequence number."""
        self.sequence += 1
        return self.sequence

    def _emit_run_start(
        self,
        *,
        run_id: str,
        root_run_id: str,
        parent_run_id: str | None,
        depth: int,
    ) -> RunStartEvent:
        """Create the run-start event for the root run."""
        return RunStartEvent(
            run_id=run_id,
            root_run_id=root_run_id,
            parent_run_id=parent_run_id,
            depth=depth,
            sequence=self._next_sequence(),
            query=self.query,
        )

    def _finalize_open_block(self, run_id: str) -> list[StreamEvent]:
        """Close an open block for a run and persist its final step."""
        block = self.open_blocks.pop(run_id, None)
        if block is None:
            return []

        text = "".join(block.parts)
        if block.block_type == BlockType.TEXT:
            self.steps.append(
                TextStep(
                    run_id=block.run_id,
                    root_run_id=block.root_run_id,
                    parent_run_id=block.parent_run_id,
                    depth=block.depth,
                    sequence=self._next_sequence(),
                    text=text,
                )
            )
            self.message_parts.append(text)
        elif block.block_type == BlockType.REASONING:
            self.steps.append(
                ReasoningStep(
                    run_id=block.run_id,
                    root_run_id=block.root_run_id,
                    parent_run_id=block.parent_run_id,
                    depth=block.depth,
                    sequence=self._next_sequence(),
                    text=text,
                )
            )

        return [
            BlockEndEvent(
                run_id=block.run_id,
                root_run_id=block.root_run_id,
                parent_run_id=block.parent_run_id,
                depth=block.depth,
                sequence=self._next_sequence(),
                block_id=block.block_id,
                block_type=block.block_type,
            )
        ]

    def _finalize_all_open_blocks(self) -> list[StreamEvent]:
        """Close all currently open blocks in insertion order."""
        emitted: list[StreamEvent] = []
        for run_id in list(self.open_blocks):
            emitted.extend(self._finalize_open_block(run_id))
        return emitted

    def consume(self, raw_event: dict[str, Any]) -> list[StreamEvent]:
        """Convert one raw LangChain event into zero or more normalized events."""
        event_name = raw_event["event"]
        run_id = raw_event["run_id"]
        parent_ids = list(raw_event.get("parent_ids", []))
        root_run_id = _root_run_id(run_id, parent_ids)
        parent_run_id = _parent_run_id(parent_ids)
        depth = len(parent_ids)
        emitted: list[StreamEvent] = []

        if self.root_run_id is None and not parent_ids:
            self.root_run_id = run_id
        if (
            not self.started
            and self.root_run_id == run_id
            and event_name.endswith("_start")
        ):
            emitted.append(
                self._emit_run_start(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                )
            )
            self.started = True

        if event_name == "on_chat_model_stream":
            chunk = raw_event.get("data", {}).get("chunk")
            text = _extract_chunk_text(chunk)
            if not text:
                return emitted

            block = self.open_blocks.get(run_id)
            if block is None:
                block = _OpenBlock(
                    block_id=str(uuid4()),
                    block_type=BlockType.TEXT,
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    parts=[],
                )
                self.open_blocks[run_id] = block
                emitted.append(
                    BlockStartEvent(
                        run_id=run_id,
                        root_run_id=root_run_id,
                        parent_run_id=parent_run_id,
                        depth=depth,
                        sequence=self._next_sequence(),
                        block_id=block.block_id,
                        block_type=block.block_type,
                    )
                )

            block.parts.append(text)
            emitted.append(
                BlockDeltaEvent(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    block_id=block.block_id,
                    block_type=block.block_type,
                    text=text,
                )
            )
            return emitted

        if event_name == "on_chat_model_end":
            emitted.extend(self._finalize_open_block(run_id))
            return emitted

        if event_name == "on_tool_start":
            emitted.extend(self._finalize_all_open_blocks())
            input_data = raw_event.get("data", {}).get("input", {})
            emitted.append(
                ToolStartEvent(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    tool_id=run_id,
                    tool_name=raw_event.get("name", "tool"),
                    arguments=input_data if isinstance(input_data, dict) else {},
                )
            )
            return emitted

        if event_name == "on_tool_end":
            data = raw_event.get("data", {})
            state, output_summary = _tool_end_state(data.get("output"))
            emitted.append(
                ToolEndEvent(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    tool_id=run_id,
                    tool_name=raw_event.get("name", "tool"),
                    state=state,
                    output_summary=output_summary,
                )
            )
            self.steps.append(
                ToolCallStep(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    tool_name=raw_event.get("name", "tool"),
                    arguments=data.get("input", {})
                    if isinstance(data.get("input"), dict)
                    else {},
                    state=state,
                    output_summary=output_summary,
                    raw_output=data.get("output"),
                )
            )
            return emitted

        if event_name == "on_tool_error":
            data = raw_event.get("data", {})
            message = str(data.get("error", "Tool execution failed"))
            emitted.append(
                ErrorEvent(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    message=message,
                )
            )
            self.steps.append(
                ToolCallStep(
                    run_id=run_id,
                    root_run_id=root_run_id,
                    parent_run_id=parent_run_id,
                    depth=depth,
                    sequence=self._next_sequence(),
                    tool_name=raw_event.get("name", "tool"),
                    arguments=data.get("input", {})
                    if isinstance(data.get("input"), dict)
                    else {},
                    state=ToolCallState.FAILED,
                    output_summary=message,
                )
            )
            return emitted

        return emitted

    def finish(self) -> list[StreamEvent]:
        """Flush remaining state and emit the final run result event."""
        emitted = self._finalize_all_open_blocks()

        if self.root_run_id is None:
            return emitted

        result = AgentRunResult(
            run_id=self.root_run_id,
            root_run_id=self.root_run_id,
            message="".join(self.message_parts),
            steps=self.steps,
        )
        emitted.append(
            RunEndEvent(
                run_id=self.root_run_id,
                root_run_id=self.root_run_id,
                sequence=self._next_sequence(),
                result=result,
            )
        )
        return emitted


async def normalize_langchain_events(
    raw_events: AsyncIterator[dict[str, Any]],
    *,
    query: str,
) -> AsyncIterator[StreamEvent]:
    """Normalize raw LangChain astream_events(v2) output into app events."""
    accumulator = _RunAccumulator(query)
    async for raw_event in raw_events:
        for event in accumulator.consume(raw_event):
            yield event
    for event in accumulator.finish():
        yield event
