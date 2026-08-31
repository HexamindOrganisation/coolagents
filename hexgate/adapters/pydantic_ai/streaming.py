"""Pydantic AI → hexgate ``StreamEvent`` normalizer + serve driver.

Maps pydantic-ai ``AgentStreamEvent``s onto the framework-agnostic
:class:`~hexgate.streaming.StreamEvent` contract. The accumulator bookkeeping
lives in :mod:`hexgate.streaming._accumulator`; this module defines the pydantic
``consume`` mapping and the serve driver.

Two pydantic specifics shape this:

* **Node iteration.** Streaming comes from ``agent.iter()`` → per-node
  ``node.stream()``: a model-request node yields ``PartStartEvent`` /
  ``PartDeltaEvent`` (text/thinking), a call-tools node yields
  ``FunctionToolCallEvent`` / ``FunctionToolResultEvent``. The driver flattens
  both into one event stream for the accumulator. Tool *calls* are taken from
  ``FunctionToolCallEvent`` (fully assembled), not the model stream's
  ``ToolCallPart``, so args need no delta reassembly.
* **In-band failures.** A tool failure surfaces as ``ToolReturnPart.outcome`` in
  ``{failed, denied}`` or a ``RetryPromptPart`` — not an exception — so the tool
  end carries an explicit state. Only fatal ``AgentRunError`` subclasses raise.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

from hexgate.runtime import HexgateContext
from hexgate.streaming import BlockType, StreamEvent, ToolCallState
from hexgate.streaming._accumulator import StreamAccumulator, run_normalizer

if TYPE_CHECKING:
    from hexgate.adapters.pydantic_ai.agent import HexgatePydanticAgent
    from hexgate.approvals import ApprovalHandler


class _PydanticRunAccumulator(StreamAccumulator):
    """Map pydantic-ai stream events onto the shared accumulator."""

    @staticmethod
    def _args(part: Any) -> dict[str, Any]:
        as_dict = getattr(part, "args_as_dict", None)
        if callable(as_dict):
            try:
                return as_dict()
            except Exception:  # noqa: BLE001 — malformed args degrade to empty
                return {}
        args = getattr(part, "args", None)
        return args if isinstance(args, dict) else {}

    def _part(self, index: int, part: Any) -> list[StreamEvent]:
        """A newly-started part carrying its first chunk (text/thinking only).

        ``ToolCallPart`` here is ignored — the authoritative tool-call event is
        ``FunctionToolCallEvent`` from the call-tools node.
        """
        kind = getattr(part, "part_kind", None)
        if kind == "text":
            return self.emit_delta(
                f"text-{index}", BlockType.TEXT, getattr(part, "content", "") or ""
            )
        if kind == "thinking":
            return self.emit_delta(
                f"thinking-{index}",
                BlockType.REASONING,
                getattr(part, "content", "") or "",
            )
        return []

    def _part_delta(self, index: int, delta: Any) -> list[StreamEvent]:
        kind = getattr(delta, "part_delta_kind", None)
        if kind == "text":
            return self.emit_delta(
                f"text-{index}",
                BlockType.TEXT,
                getattr(delta, "content_delta", "") or "",
            )
        if kind == "thinking":
            return self.emit_delta(
                f"thinking-{index}",
                BlockType.REASONING,
                getattr(delta, "content_delta", "") or "",
            )
        return []

    def _tool_result(self, result: Any) -> list[StreamEvent]:
        call_id = getattr(result, "tool_call_id", None)
        outcome = getattr(result, "outcome", None)
        if outcome is not None:  # ToolReturnPart — explicit success/failed/denied
            output = getattr(result, "content", None)
            # A 'denied' outcome collapses to FAILED: the StreamEvent contract
            # has no dedicated DENIED tool state today, so approval/policy
            # denials render like a failure (fidelity limit, not a bug).
            state = (
                ToolCallState.COMPLETED
                if outcome == "success"
                else ToolCallState.FAILED
            )
        else:  # RetryPromptPart — a tool error / validation retry
            content = getattr(result, "content", None)
            output = content if isinstance(content, str) else str(content)
            state = ToolCallState.FAILED
        return self.emit_tool_end(call_id, output, state_override=state)

    def consume(self, event: Any) -> list[StreamEvent]:
        kind = getattr(event, "event_kind", None)
        if kind == "part_start":
            return self._part(getattr(event, "index", 0), getattr(event, "part", None))
        if kind == "part_delta":
            return self._part_delta(
                getattr(event, "index", 0), getattr(event, "delta", None)
            )
        if kind == "function_tool_call":
            part = getattr(event, "part", None)
            return self.emit_tool_start(
                getattr(part, "tool_call_id", None),
                getattr(part, "tool_name", None) or "tool",
                self._args(part),
            )
        if kind == "function_tool_result":
            return self._tool_result(getattr(event, "result", None))
        # Builtin/hosted-tool events (web search, code execution) are not
        # rendered: they run provider-side, aren't hexgate-enforced, and their
        # event shape is in flux (deprecated ``builtin_tool_*`` events vs. newer
        # ``BuiltinToolCallPart`` parts). Only ``@agent.tool`` function calls,
        # which go through the policy enforcer, are surfaced.
        return []


async def normalize_pydantic_events(
    events: AsyncIterator[Any], *, query: str
) -> AsyncIterator[StreamEvent]:
    """Normalize a flattened pydantic-ai event stream into ``StreamEvent``s."""
    async for event in run_normalizer(
        _PydanticRunAccumulator(query), events, error_log="pydantic serve stream failed"
    ):
        yield event


class PydanticServeDriver:
    """Owns the wrapped pydantic proxy + conversation history for one serve
    connection. Built once by ``build_runtime_from_local_agent``; :meth:`astream`
    is bound as the runtime's streaming seam."""

    def __init__(
        self,
        *,
        agent: Any,
        approval_handler: ApprovalHandler | None = None,
        api_key: str | None = None,
    ) -> None:
        from hexgate.adapters.pydantic_ai.wrapper import wrap_pydantic_agent

        self._proxy: HexgatePydanticAgent = wrap_pydantic_agent(
            agent=agent, approval_handler=approval_handler, api_key=api_key
        )
        # pydantic's own message objects, carried across turns for memory.
        self._history: list[Any] = []

    async def astream(
        self, agent_input: Any, ctx: HexgateContext | None, query: str
    ) -> AsyncIterator[StreamEvent]:
        from pydantic_ai import Agent

        run_ctx = ctx or HexgateContext(user_id="")
        # A fresh conversation (first turn / post-reset) drops prior history.
        turns = len(agent_input) if isinstance(agent_input, (list, tuple)) else 0
        if turns <= 1:
            self._history = []

        result_box: dict[str, Any] = {}

        async def _events() -> AsyncIterator[Any]:
            async with self._proxy.iter(
                query,
                hexgate_context=run_ctx,
                message_history=self._history or None,
            ) as run:
                async for node in run:
                    if Agent.is_model_request_node(node) or Agent.is_call_tools_node(
                        node
                    ):
                        async with node.stream(run.ctx) as node_stream:
                            async for event in node_stream:
                                yield event
                result_box["result"] = run.result

        async for normalized in normalize_pydantic_events(_events(), query=query):
            yield normalized

        result = result_box.get("result")
        if result is not None:
            all_messages = getattr(result, "all_messages", None)
            if callable(all_messages):
                self._history = list(all_messages())
