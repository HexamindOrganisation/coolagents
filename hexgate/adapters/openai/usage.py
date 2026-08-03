"""OpenAI Agents SDK per-call token usage capture via ``RunHooks``.

``Runner.run``/``run_sync``/``run_streamed`` invoke ``on_llm_end`` once per
underlying model call, so a single run with several turns (tool-calling
loops, handoffs) can emit more than one usage event.
"""

from __future__ import annotations

import logging

from agents import Agent, RunContextWrapper
from agents.items import ModelResponse
from agents.lifecycle import RunHooks

from hexgate.tracing.usage import emit_llm_usage

_log = logging.getLogger(__name__)


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
        try:
            emit_llm_usage(
                agent.name,
                model,
                response.usage.input_tokens,
                response.usage.output_tokens,
                api_key=self._api_key,
            )
        except Exception:
            # The SDK doesn't guard hooks.on_llm_end itself — an unhandled
            # exception here propagates out of Runner.run* and fails the
            # whole agent turn, even though the model already responded.
            _log.exception("emit_llm_usage raised; ignoring")
