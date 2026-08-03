"""Google ADK per-call token usage capture via a ``BasePlugin``.

``after_model_callback`` fires once per underlying model call, so a single
run with several turns (tool-calling loops, sub-agent handoffs) can emit
more than one usage event. ``callback_context.agent_name`` is read per-call
rather than fixed at construction, since one ``Runner`` can drive several
named sub-agents.
"""

from __future__ import annotations

import logging

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin

from hexgate.tracing.usage import emit_llm_usage

_log = logging.getLogger(__name__)


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
        try:
            emit_llm_usage(
                callback_context.agent_name,
                llm_response.model_version or "",
                usage.prompt_token_count or 0,
                usage.candidates_token_count or 0,
                api_key=self._api_key,
            )
        except Exception:
            # PluginManager re-raises an unhandled plugin exception as a
            # RuntimeError, which would fail the whole run — usage
            # reporting must not be able to take down a real model call.
            _log.exception("emit_llm_usage raised; ignoring")
        return None
