"""OpenAI Agents SDK → hexgate ``StreamEvent`` normalizer + serve driver.

Maps the ``agents`` SDK's ``RunResultStreaming.stream_events()`` output onto the
framework-agnostic :class:`~hexgate.streaming.StreamEvent` contract the dashboard
Playground consumes. This is the OpenAI sibling of the LangChain normalizer in
:mod:`hexgate.streaming.normalize`; it reuses the same accumulator shape
(sequence counter, one open text/reasoning block, persisted ``steps``, an
assembled ``message``, ``finish()`` → :class:`~hexgate.streaming.RunEndEvent`).

``agents`` yields three event kinds (``agents/stream_events.py``):

* ``RawResponsesStreamEvent`` (``type == "raw_response_event"``) — the raw
  Responses-API stream event passed straight through; text/reasoning deltas
  live here.
* ``RunItemStreamEvent`` (``type == "run_item_stream_event"``) — a ``.name`` +
  ``.item``; tool calls (``tool_called`` → ``ToolCallItem``) and tool outputs
  (``tool_output`` → ``ToolCallOutputItem``) live here.
* ``AgentUpdatedStreamEvent`` — ignored.

Field access is defensive (``getattr``) so we don't bind to a specific
``openai`` Responses-types version, and so a ``raw_item`` that is a dict or a
computer/shell call (not a function call) degrades to empty args rather than
raising.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
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
    ToolCallStep,
    ToolEndEvent,
    ToolStartEvent,
)

# Reuse the framework-agnostic tool-output inference the LangChain normalizer
# uses, so summaries and success/failure render identically across adapters:
# ``_tool_end_state`` returns ``(state, summary)`` and detects ``{"ok": false}``
# failure payloads, including hexgate's own GuardedTool refusals.
from hexgate.streaming.normalize import _tool_end_state

if TYPE_CHECKING:
    from hexgate.adapters.openai.runner import HexgateRunner
    from hexgate.runtime import HexgateContext

logger = logging.getLogger(__name__)

# Raw Responses-API streaming-event ``.type`` discriminators we consume. Other
# raw event types (item added/done, function-call-arg deltas, completed, …) are
# ignored: the aggregated ``run_item_stream_event`` items carry what we need.
_TEXT_DELTA = "response.output_text.delta"
# Reasoning models stream chain-of-thought as raw reasoning deltas. Summarized
# reasoning (the default for the o-series / gpt-5) arrives as the *summary*
# variant, so both must be captured or the reasoning block renders empty.
_REASONING_DELTAS = frozenset(
    {"response.reasoning_text.delta", "response.reasoning_summary_text.delta"}
)


def _jsonable(value: Any) -> Any:
    """Return a JSON-serializable form of a tool's raw output.

    ``ToolCallStep.raw_output`` is serialized when serve ships the terminal
    ``RunEndEvent`` via ``model_dump_json()``; an OpenAI ``@function_tool`` may
    return an arbitrary object that pydantic can't serialize, which would raise
    and drop the run-end frame. Keep JSON-native values as-is; stringify
    anything else so serialization always succeeds.
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


class _OpenAIRunAccumulator:
    """Fold OpenAI stream events into normalized :class:`StreamEvent`s.

    OpenAI runs are flat (no LangChain-style ``parent_ids`` tree), so every
    event shares one synthesized root ``run_id`` at depth 0. ``sequence`` is
    assigned monotonically here, exactly like the LangChain accumulator.
    """

    def __init__(self, query: str) -> None:
        self.query = query
        self.run_id = str(uuid4())
        self.sequence = 0
        self.started = False
        # Open text/reasoning blocks, keyed by the SDK output item_id so a
        # message block and a reasoning block never collide.
        self.blocks: dict[str, _OpenBlock] = {}
        # call_id → (tool_name, arguments) recorded at tool_called, so the
        # matching tool_output (which carries neither) can be labeled.
        self.tool_calls: dict[str, tuple[str, dict[str, Any]]] = {}
        # Synthesized ids for the rare tool call that carries no call_id (hosted
        # computer/shell calls). Reused FIFO at tool_output so a start and its
        # end still share a tool_id and correlate in ChatState.
        self._pending_callless: list[str] = []
        self.steps: list[TextStep | ReasoningStep | ToolCallStep] = []
        self.message_parts: list[str] = []

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

    # -- deltas ---------------------------------------------------------------

    def _delta(
        self, item_id: str | None, block_type: BlockType, text: str
    ) -> list[StreamEvent]:
        if not text:
            return []
        emitted: list[StreamEvent] = []
        # Fall back to the block-type name when the SDK omits item_id, so text
        # and reasoning still stay in separate blocks.
        key = item_id or block_type.value
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

    def _finalize_blocks(self) -> list[StreamEvent]:
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

    @staticmethod
    def _extract_args(item: Any) -> dict[str, Any]:
        """Best-effort dict of a ToolCallItem's arguments.

        Function calls carry ``arguments`` as a JSON *string*; parse it. Non
        function calls (computer/shell) or unparseable args degrade to ``{}``.
        """
        raw = getattr(item, "raw_item", None)
        if isinstance(raw, dict):
            args = raw.get("arguments")
        else:
            args = getattr(raw, "arguments", None)
        if isinstance(args, str):
            try:
                parsed = json.loads(args)
            except (json.JSONDecodeError, ValueError):
                return {}
            return parsed if isinstance(parsed, dict) else {}
        if isinstance(args, dict):
            return args
        return {}

    def _tool_start(self, item: Any) -> ToolStartEvent:
        call_id = getattr(item, "call_id", None)
        if not call_id:
            call_id = str(uuid4())
            self._pending_callless.append(call_id)
        tool_name = getattr(item, "tool_name", None) or "tool"
        arguments = self._extract_args(item)
        self.tool_calls[call_id] = (tool_name, arguments)
        return ToolStartEvent(
            **self._node(),
            sequence=self._next_sequence(),
            tool_id=call_id,
            tool_name=tool_name,
            arguments=arguments,
        )

    def _tool_end(self, item: Any) -> ToolEndEvent:
        call_id = getattr(item, "call_id", None)
        if not call_id:
            # Match the FIFO id minted for the corresponding callless start so
            # start↔end share a tool_id; a truly orphan end gets a fresh id.
            call_id = (
                self._pending_callless.pop(0)
                if self._pending_callless
                else str(uuid4())
            )
        tool_name, arguments = self.tool_calls.get(call_id, ("tool", {}))
        output = getattr(item, "output", None)
        # Reuse the shared inference: a structured ``{"ok": false}`` failure
        # (e.g. a hexgate GuardedTool refusal) is marked FAILED, matching the
        # native adapter. A tool error the SDK folds into plain output text has
        # no structured marker and still reads as COMPLETED — a known limit.
        state, summary = _tool_end_state(output)
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
        return ToolEndEvent(
            **self._node(),
            sequence=self._next_sequence(),
            tool_id=call_id,
            tool_name=tool_name,
            state=state,
            output_summary=summary,
        )

    # -- dispatch -------------------------------------------------------------

    def consume(self, event: Any) -> list[StreamEvent]:
        """Convert one OpenAI stream event into zero or more normalized events."""
        emitted: list[StreamEvent] = []
        if not self.started:
            emitted.append(self._run_start())

        etype = getattr(event, "type", None)
        if etype == "raw_response_event":
            data = getattr(event, "data", None)
            dtype = getattr(data, "type", None)
            if dtype == _TEXT_DELTA:
                emitted.extend(
                    self._delta(
                        getattr(data, "item_id", None),
                        BlockType.TEXT,
                        getattr(data, "delta", "") or "",
                    )
                )
            elif dtype in _REASONING_DELTAS:
                emitted.extend(
                    self._delta(
                        getattr(data, "item_id", None),
                        BlockType.REASONING,
                        getattr(data, "delta", "") or "",
                    )
                )
            return emitted

        if etype == "run_item_stream_event":
            name = getattr(event, "name", None)
            item = getattr(event, "item", None)
            if name == "tool_called":
                # A tool call ends any open assistant text block first.
                emitted.extend(self._finalize_blocks())
                emitted.append(self._tool_start(item))
            elif name == "tool_output":
                emitted.append(self._tool_end(item))
            return emitted

        # agent_updated_stream_event and unhandled run-item names: no-op.
        return emitted

    def _ensure_started(self) -> list[StreamEvent]:
        """Emit the run-start first if nothing did (empty stream / immediate
        raise), so a terminal event is never sent unbracketed."""
        return [self._run_start()] if not self.started else []

    def finish(self) -> list[StreamEvent]:
        """Flush open blocks and emit the terminal run-end event."""
        emitted = self._ensure_started()
        emitted.extend(self._finalize_blocks())
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
        emitted.extend(self._finalize_blocks())
        emitted.append(
            ErrorEvent(**self._node(), sequence=self._next_sequence(), message=message)
        )
        return emitted


async def normalize_openai_events(
    events: AsyncIterator[Any], *, query: str
) -> AsyncIterator[StreamEvent]:
    """Normalize an OpenAI ``stream_events()`` iterator into ``StreamEvent``s.

    Fatal errors are *raised* out of the OpenAI SDK's ``stream_events()``
    (``MaxTurnsExceeded``, guardrail tripwires, or a tool exception when
    ``failure_error_function=None``). Catch them and emit a terminal
    :class:`~hexgate.streaming.ErrorEvent` so the dashboard closes the turn
    cleanly instead of the exception tearing the relay task down.
    """
    accumulator = _OpenAIRunAccumulator(query)
    try:
        async for event in events:
            for normalized in accumulator.consume(event):
                yield normalized
    except Exception as exc:  # noqa: BLE001 — surface any failure as an event
        logger.exception("openai serve stream failed")
        for normalized in accumulator.error(str(exc)):
            yield normalized
        return
    for normalized in accumulator.finish():
        yield normalized


async def astream_openai(
    runner: HexgateRunner,
    agent: Any,
    input: Any,
    *,
    hexgate_context: HexgateContext,
    query: str,
) -> AsyncIterator[StreamEvent]:
    """Stream a policy-enforced OpenAI agent as normalized ``StreamEvent``s.

    ``runner.run_streamed`` opens the :class:`HexgateContext` scope internally
    (its wrapped ``stream_events()`` re-enters it), refreshes the cached policy
    binding for this run, and enforces the ban gate before spawning the agent
    loop — so this driver only wires the raw stream into the normalizer.
    """
    result = runner.run_streamed(agent, input, hexgate_context=hexgate_context)
    async for event in normalize_openai_events(result.stream_events(), query=query):
        yield event
