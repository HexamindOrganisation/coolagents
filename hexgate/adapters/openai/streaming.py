"""OpenAI Agents SDK → hexgate ``StreamEvent`` normalizer + serve driver.

Maps the ``agents`` SDK's ``RunResultStreaming.stream_events()`` output onto the
framework-agnostic :class:`~hexgate.streaming.StreamEvent` contract the dashboard
Playground consumes. The accumulator bookkeeping lives in
:mod:`hexgate.streaming._accumulator`; this module only defines the OpenAI
``consume`` mapping and the serve driver.

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
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from hexgate.streaming import BlockType, StreamEvent
from hexgate.streaming._accumulator import StreamAccumulator, run_normalizer

if TYPE_CHECKING:
    from hexgate.adapters.openai.runner import HexgateRunner
    from hexgate.runtime import HexgateContext

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


class _OpenAIRunAccumulator(StreamAccumulator):
    """Map OpenAI stream events onto the shared accumulator."""

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

    def consume(self, event: Any) -> list[StreamEvent]:
        etype = getattr(event, "type", None)
        if etype == "raw_response_event":
            data = getattr(event, "data", None)
            dtype = getattr(data, "type", None)
            delta = getattr(data, "delta", "") or ""
            item_id = getattr(data, "item_id", None)
            if dtype == _TEXT_DELTA:
                return self.emit_delta(item_id or "text", BlockType.TEXT, delta)
            if dtype in _REASONING_DELTAS:
                return self.emit_delta(
                    item_id or "reasoning", BlockType.REASONING, delta
                )
            return []

        if etype == "run_item_stream_event":
            name = getattr(event, "name", None)
            item = getattr(event, "item", None)
            if name == "tool_called":
                return self.emit_tool_start(
                    getattr(item, "call_id", None),
                    getattr(item, "tool_name", None) or "tool",
                    self._extract_args(item),
                )
            if name == "tool_output":
                return self.emit_tool_end(
                    getattr(item, "call_id", None), getattr(item, "output", None)
                )
            return []

        # agent_updated_stream_event and unhandled run-item names: no-op.
        return []


async def normalize_openai_events(
    events: AsyncIterator[Any], *, query: str
) -> AsyncIterator[StreamEvent]:
    """Normalize an OpenAI ``stream_events()`` iterator into ``StreamEvent``s.

    Fatal errors are *raised* out of the OpenAI SDK's ``stream_events()``
    (``MaxTurnsExceeded``, guardrail tripwires, or a tool exception when
    ``failure_error_function=None``); ``run_normalizer`` turns them into a
    terminal :class:`~hexgate.streaming.ErrorEvent`.
    """
    async for event in run_normalizer(
        _OpenAIRunAccumulator(query), events, error_log="openai serve stream failed"
    ):
        yield event


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
