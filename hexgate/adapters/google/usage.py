"""Google ADK per-call token usage capture via a ``BasePlugin``.

``after_model_callback`` fires once per underlying model call, so a single
run with several turns (tool-calling loops, sub-agent handoffs) can emit
more than one usage event. ``callback_context.agent_name`` is read per-call
rather than fixed at construction, since one ``Runner`` can drive several
named sub-agents.
"""

from __future__ import annotations

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin

from hexgate.tracing.usage import emit_llm_usage


class HexgateUsagePlugin(BasePlugin):
    """Emits one :class:`~hexgate.tracing.usage.LlmUsageEvent` per
    ``after_model_callback`` callback. Never rewrites the response — always
    returns ``None`` so the real model output reaches the agent unchanged."""

    def __init__(self, *, api_key: str) -> None:
        super().__init__(name="hexgate_usage")
        self._api_key = api_key

    async def after_model_callback(
        self,
        *,
        callback_context: CallbackContext,
        llm_response: LlmResponse,
    ) -> LlmResponse | None:
        usage = llm_response.usage_metadata
        if usage is None:
            return None
        emit_llm_usage(
            callback_context.agent_name,
            llm_response.model_version or "",
            usage.prompt_token_count or 0,
            usage.candidates_token_count or 0,
            api_key=self._api_key,
        )
        return None
