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
        # agent.model is `str | Model | None`. None means the agent didn't
        # set one and the runner/SDK default applies -- that default is
        # resolved deep in the SDK's run loop and never reaches this hook,
        # so "default" is an honest placeholder rather than a guess.
        if isinstance(agent.model, str):
            model = agent.model
        elif agent.model is None:
            model = "default"
        else:
            # Standard Model impls expose the real id in .model; class name is a
            # last resort for an exotic Model that doesn't.
            model = getattr(agent.model, "model", None) or type(agent.model).__name__
        emit_llm_usage(
            agent.name,
            model,
            response.usage.input_tokens,
            response.usage.output_tokens,
            api_key=self._api_key,
        )
