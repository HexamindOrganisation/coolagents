"""OpenAI Agents SDK per-call token usage capture via ``RunHooks``.

``Runner.run``/``run_sync``/``run_streamed`` invoke ``on_llm_end`` once per
underlying model call, so a single run with several turns (tool-calling
loops, handoffs) can emit more than one usage event.
"""

from __future__ import annotations

from agents import Agent, RunContextWrapper
from agents.items import ModelResponse
from agents.lifecycle import RunHooks

from hexgate.tracing.usage import emit_llm_usage


class HexgateUsageHooks(RunHooks):
    """Emits one :class:`~hexgate.tracing.usage.LlmUsageEvent` per
    ``on_llm_end`` callback."""

    def __init__(self, *, api_key: str) -> None:
        self._api_key = api_key

    async def on_llm_end(
        self,
        context: RunContextWrapper,
        agent: Agent,
        response: ModelResponse,
    ) -> None:
        # agent.model is `str | Model | None` — only the str case gives a
        # clean name; a Model implementation has no guaranteed name field.
        model = agent.model if isinstance(agent.model, str) else ""
        emit_llm_usage(
            agent.name,
            model,
            response.usage.input_tokens,
            response.usage.output_tokens,
            api_key=self._api_key,
        )
