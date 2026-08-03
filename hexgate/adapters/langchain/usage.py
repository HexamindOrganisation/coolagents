"""LangChain per-call token usage capture via a ``BaseCallbackHandler``.

LangGraph propagates ``config["callbacks"]`` down through every node, so a
handler placed there (see ``HexgateLangchainAgent._with_callbacks``) has its
``on_llm_end`` invoked by the framework itself on each underlying chat-model
call — not something this module drives directly. A single ``.invoke()`` can
therefore emit more than one usage event, once per LLM turn in the run.
"""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult

from hexgate.tracing.usage import emit_llm_usage


class HexgateUsageCallbackHandler(BaseCallbackHandler):
    """Emits one :class:`~hexgate.tracing.usage.LlmUsageEvent` per
    ``on_llm_end`` callback.

    Reads the standardized ``UsageMetadata`` off the response message when
    the provider populates it, falling back to ``llm_output["token_usage"]``
    for providers that only fill the legacy field. Does nothing when
    neither is present — a provider that reports no usage must not
    synthesize a zeroed event.
    """

    def __init__(self, *, agent_name: str, api_key: str | None = None) -> None:
        self._agent_name = agent_name
        self._api_key = api_key

    async def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        # Async so LangChain's AsyncCallbackManager awaits this inline on the
        # real event loop (asyncio.iscoroutinefunction check in
        # _ahandle_event_for_handler) instead of dispatching it to a thread
        # pool executor — a plain sync def here runs off-loop, and
        # emit_llm_usage's sender never gets a valid loop to schedule its
        # HTTP send on, silently dropping every event.
        usage = _extract_usage(response)
        if usage is None:
            return
        input_tokens, output_tokens = usage
        model = _model_name(response)
        emit_llm_usage(
            self._agent_name,
            model,
            input_tokens,
            output_tokens,
            api_key=self._api_key,
        )


def _model_name(response: LLMResult) -> str:
    """Read the model name off the response.

    ``llm_output`` is ``None`` for a streamed response (LangChain's default
    ``_combine_llm_outputs`` — and even providers that override it, like
    ChatOpenAI, only combine per-chunk outputs that are non-``None``, which
    streaming chunks typically aren't) — confirmed empirically against a
    real streaming ``ChatOpenAI`` call, not assumed. ``response_metadata``
    on the message is populated in both the streaming and non-streaming
    case, so it's the primary source; ``llm_output`` stays as a fallback
    for providers that only populate the legacy field.
    """
    message = response.generations[0][0].message  # type: ignore[union-attr]
    response_metadata = getattr(message, "response_metadata", None) or {}
    return response_metadata.get("model_name") or (response.llm_output or {}).get(
        "model_name", ""
    )


def _extract_usage(response: LLMResult) -> tuple[int, int] | None:
    """(input_tokens, output_tokens), or None when the provider reported no
    usage at all."""
    usage_metadata = response.generations[0][0].message.usage_metadata  # type: ignore[union-attr]
    if usage_metadata:
        return usage_metadata["input_tokens"], usage_metadata["output_tokens"]
    token_usage = (response.llm_output or {}).get("token_usage")
    if not token_usage:
        return None
    return token_usage.get("prompt_tokens", 0), token_usage.get("completion_tokens", 0)
