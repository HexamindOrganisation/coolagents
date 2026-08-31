"""Shared accumulator for framework → hexgate ``StreamEvent`` normalizers.

The OpenAI, Google, and Pydantic serve adapters each fold their framework's
native run events into the framework-agnostic
:class:`~hexgate.streaming.StreamEvent` contract. The bookkeeping is identical —
a monotonic ``sequence``, one synthesized flat run id, open text/reasoning blocks,
a ``call_id → (name, args)`` correlation map, persisted ``steps``, an assembled
``message``, and terminal ``finish()`` / ``error()`` — so it lives here once.

A subclass implements only :meth:`StreamAccumulator.consume`, extracting the
framework-specific fields and calling the shared ``emit_*`` helpers.
:func:`run_normalizer` drives the accumulator over an event iterator with the
common bracket-and-fail-safe loop.

The LangChain normalizer in :mod:`hexgate.streaming.normalize` predates this and
keeps its own inline accumulator; this module imports its ``_summarize_output`` /
``_tool_end_state`` helpers rather than the other way round (one-directional, no
import cycle), so that module is untouched.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from hexgate.streaming import (
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
from hexgate.streaming.normalize import _tool_end_state

logger = logging.getLogger(__name__)


def _jsonable(value: Any) -> Any:
    """Return a JSON-serializable form of a tool's raw output.

    ``ToolCallStep.raw_output`` is serialized when serve ships the terminal
    ``RunEndEvent`` via ``model_dump_json()``; a tool may return an arbitrary
    object that pydantic can't serialize, which would raise and drop the run-end
    frame. Keep JSON-native values as-is; stringify anything else so
    serialization always succeeds.
    """
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


@dataclass
class _OpenBlock:
    """One streamed text or reasoning block before finalization."""

    block_id: str
    block_type: BlockType
    parts: list[str] = field(default_factory=list)


class StreamAccumulator:
    """Fold one framework's run events into normalized :class:`StreamEvent`s.

    Runs are treated as flat (no LangChain-style ``parent_ids`` tree): every
    event shares one synthesized root ``run_id`` at depth 0, and ``sequence`` is
    assigned monotonically. Subclasses override :meth:`consume`.
    """

    def __init__(self, query: str) -> None:
        self.query = query
        self.run_id = str(uuid4())
        self.sequence = 0
        self.started = False
        # Open text/reasoning blocks, keyed by a framework-supplied string (an
        # item id or part index) so a message block and a reasoning block that
        # stream interleaved never collide.
        self.blocks: dict[str, _OpenBlock] = {}
        # call_id → (tool_name, arguments) recorded at tool-start, so a
        # tool-result that carries neither can be labeled.
        self.tool_calls: dict[str, tuple[str, dict[str, Any]]] = {}
        # Synthesized ids for a tool call that carries no id (e.g. hosted
        # computer/shell calls). Reused FIFO at tool-end so start↔end share a
        # tool_id and correlate in ChatState.
        self._pending_callless: list[str] = []
        self.steps: list[TextStep | ReasoningStep | ToolCallStep] = []
        self.message_parts: list[str] = []

    # -- primitives -----------------------------------------------------------

    def _next_sequence(self) -> int:
        self.sequence += 1
        return self.sequence

    def _node(self) -> dict[str, Any]:
        """Shared ancestry kwargs for a flat single-run event."""
        return {
            "run_id": self.run_id,
            "root_run_id": self.run_id,
            "parent_run_id": None,
            "depth": 0,
        }

    def _run_start(self) -> RunStartEvent:
        self.started = True
        return RunStartEvent(
            **self._node(), sequence=self._next_sequence(), query=self.query
        )

    def _ensure_started(self) -> list[StreamEvent]:
        """Emit the run-start first if nothing did (empty stream / immediate
        raise), so a terminal event is never sent unbracketed."""
        return [self._run_start()] if not self.started else []

    # -- text / reasoning blocks ---------------------------------------------

    def emit_delta(
        self, key: str, block_type: BlockType, text: str
    ) -> list[StreamEvent]:
        """Open the block for ``key`` on first delta, then emit the delta.

        ``key`` separates concurrent blocks (a text item vs a reasoning item);
        pass a stable per-block identifier (item id or part index as a string).
        """
        if not text:
            return []
        emitted: list[StreamEvent] = []
        block = self.blocks.get(key)
        if block is None:
            block = _OpenBlock(block_id=str(uuid4()), block_type=block_type)
            self.blocks[key] = block
            emitted.append(
                BlockStartEvent(
                    **self._node(),
                    sequence=self._next_sequence(),
                    block_id=block.block_id,
                    block_type=block_type,
                )
            )
        block.parts.append(text)
        if block_type == BlockType.TEXT:
            self.message_parts.append(text)
        emitted.append(
            BlockDeltaEvent(
                **self._node(),
                sequence=self._next_sequence(),
                block_id=block.block_id,
                block_type=block_type,
                text=text,
            )
        )
        return emitted

    def finalize_blocks(self) -> list[StreamEvent]:
        """Close every open block, emitting a BlockEnd + persisting a step."""
        emitted: list[StreamEvent] = []
        for block in self.blocks.values():
            emitted.append(
                BlockEndEvent(
                    **self._node(),
                    sequence=self._next_sequence(),
                    block_id=block.block_id,
                    block_type=block.block_type,
                )
            )
            text = "".join(block.parts)
            if block.block_type == BlockType.REASONING:
                self.steps.append(
                    ReasoningStep(
                        **self._node(), sequence=self._next_sequence(), text=text
                    )
                )
            else:
                self.steps.append(
                    TextStep(**self._node(), sequence=self._next_sequence(), text=text)
                )
        self.blocks.clear()
        return emitted

    # -- tool calls -----------------------------------------------------------

    def emit_tool_start(
        self, call_id: str | None, tool_name: str, arguments: dict[str, Any]
    ) -> list[StreamEvent]:
        """Close any open block, then start a tool call, recording it for the
        matching end. A tool call ends the current assistant text block."""
        emitted = self.finalize_blocks()
        if not call_id:
            call_id = str(uuid4())
            self._pending_callless.append(call_id)
        self.tool_calls[call_id] = (tool_name, arguments)
        emitted.append(
            ToolStartEvent(
                **self._node(),
                sequence=self._next_sequence(),
                tool_id=call_id,
                tool_name=tool_name,
                arguments=arguments,
            )
        )
        return emitted

    def emit_tool_end(
        self,
        call_id: str | None,
        output: Any,
        *,
        state_override: ToolCallState | None = None,
    ) -> list[StreamEvent]:
        """End a tool call and persist its step.

        ``state_override`` is for frameworks that report success/failure
        explicitly (pydantic's ``ToolReturnPart.outcome``); otherwise the state
        is inferred from the output (``{"ok": false}`` / an ``"error"`` key).
        """
        if not call_id:
            call_id = (
                self._pending_callless.pop(0)
                if self._pending_callless
                else str(uuid4())
            )
        tool_name, arguments = self.tool_calls.get(call_id, ("tool", {}))
        inferred_state, summary = _tool_end_state(output)
        state = state_override or inferred_state
        self.steps.append(
            ToolCallStep(
                **self._node(),
                sequence=self._next_sequence(),
                tool_name=tool_name,
                arguments=arguments,
                state=state,
                output_summary=summary,
                raw_output=_jsonable(output),
            )
        )
        return [
            ToolEndEvent(
                **self._node(),
                sequence=self._next_sequence(),
                tool_id=call_id,
                tool_name=tool_name,
                state=state,
                output_summary=summary,
            )
        ]

    def emit_error(self, message: str) -> list[StreamEvent]:
        """Emit a non-terminal error event (an in-stream failure signal)."""
        return [
            ErrorEvent(**self._node(), sequence=self._next_sequence(), message=message)
        ]

    # -- dispatch + terminals -------------------------------------------------

    def consume(self, event: Any) -> list[StreamEvent]:
        """Convert one framework event into zero or more normalized events.

        Subclasses override this. They should call :meth:`_ensure_started`'s
        counterpart by emitting the run-start before their first output — the
        base does this in :meth:`_consume_wrapped`.
        """
        raise NotImplementedError

    def _consume_wrapped(self, event: Any) -> list[StreamEvent]:
        """Emit the run-start on the first event, then dispatch to ``consume``."""
        emitted = self._ensure_started()
        emitted.extend(self.consume(event))
        return emitted

    def finish(self) -> list[StreamEvent]:
        """Flush open blocks and emit the terminal run-end event."""
        emitted = self._ensure_started()
        emitted.extend(self.finalize_blocks())
        result = AgentRunResult(
            run_id=self.run_id,
            root_run_id=self.run_id,
            message="".join(self.message_parts),
            steps=self.steps,
        )
        emitted.append(
            RunEndEvent(
                run_id=self.run_id,
                root_run_id=self.run_id,
                sequence=self._next_sequence(),
                result=result,
            )
        )
        return emitted

    def error(self, message: str) -> list[StreamEvent]:
        """Flush open blocks and emit a terminal error event.

        Terminal on its own — no trailing run-end — since a fatal stream error
        ends the turn; :meth:`ChatState.apply_event` marks streaming stopped.
        """
        emitted = self._ensure_started()
        emitted.extend(self.finalize_blocks())
        emitted.append(
            ErrorEvent(**self._node(), sequence=self._next_sequence(), message=message)
        )
        return emitted


async def run_normalizer(
    accumulator: StreamAccumulator,
    events: AsyncIterator[Any],
    *,
    error_log: str = "serve stream failed",
) -> AsyncIterator[StreamEvent]:
    """Drive ``accumulator`` over ``events`` with the shared bracket loop.

    Emits run-start on the first event (via ``_consume_wrapped``), then either
    ``finish()`` on clean completion or a terminal ``error()`` if the framework
    stream raises — so a mid-stream exception surfaces as an event instead of
    tearing down the relay task.
    """
    try:
        async for event in events:
            for normalized in accumulator._consume_wrapped(event):
                yield normalized
    except Exception as exc:  # noqa: BLE001 — surface any failure as an event
        logger.exception(error_log)
        for normalized in accumulator.error(str(exc)):
            yield normalized
        return
    for normalized in accumulator.finish():
        yield normalized
