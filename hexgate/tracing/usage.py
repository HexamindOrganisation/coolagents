from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar
from uuid import UUID, uuid4

from hexgate.runtime.context import get_current_context
from hexgate.runtime.run_facts import get_run_facts
from hexgate.tracing import semconv
from hexgate.tracing._senders import AuditSender, get_or_create_sender
from hexgate.tracing._senders import get_sender as _get_sender
from hexgate.tracing._senders import shutdown as _shutdown_all

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LlmUsageEvent:
    """One LLM call's token usage, emitted as a span under scope
    ``hexgate.usage``. ``occurred_at`` becomes the span's start time."""

    SCOPE: ClassVar[str] = semconv.SCOPE_USAGE

    agent_name: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    status: str  # e.g., "success", "error"
    session_id: str = ""
    user_id: str = ""
    error_code: str | None = None  # optional error code if status is "error"
    # Joins this row to the policy_decision rows of the same invocation. ``""``
    # outside a run scope. A plain field, not a RunAttribution: llm_invocation
    # carries one run column.
    run_id: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def span_attributes(self) -> dict[str, Any]:
        """Flat span attributes: official ``gen_ai.*`` names for model and
        token counts, ``sec_ai.*`` for everything Hexgate-specific.

        ``run_id`` is omitted outside a run scope, never sent as ``""`` — see
        :meth:`hexgate.security.decision.RunAttribution.as_span_attributes`."""
        attrs: dict[str, Any] = {
            semconv.EVENT_ID: str(self.event_id),
            semconv.AGENT_NAME: self.agent_name,
            semconv.SESSION_ID: self.session_id,
            semconv.USER_ID: self.user_id,
            semconv.GEN_AI_REQUEST_MODEL: self.model,
            semconv.GEN_AI_USAGE_INPUT_TOKENS: self.input_tokens,
            semconv.GEN_AI_USAGE_OUTPUT_TOKENS: self.output_tokens,
            semconv.LATENCY_MS: self.latency_ms,
            semconv.STATUS: self.status,
            semconv.ERROR_CODE: self.error_code or "",
        }
        if self.run_id:
            attrs[semconv.RUN_ID] = self.run_id
        return attrs


def emit_llm_usage(
    agent_name: str,
    model: str,
    input_tokens: int,
    output_tokens: int,
    *,
    latency_ms: int = 0,
    status: str = "success",
    error_code: str | None = None,
    api_key: str | None = None,
) -> None:
    """Resolve identity from the active HexgateContext scope and emit one
    :class:`LlmUsageEvent` through the shared sender registry.

    The single entry point every adapter's usage hook calls into — never
    raises. Every adapter (LangChain, OpenAI Agents, Google ADK, Pydantic
    AI) calls this from a framework hook that either re-raises on an
    unhandled exception (Google's ``PluginManager``) or doesn't guard the
    call at all (OpenAI's run loop, Pydantic AI's inline call site); a
    failure here must not fail the agent run whose usage it's reporting.
    Tokens are always recorded into the active run's facts; the event is only
    emitted if a sender is configured for ``api_key`` — no-op otherwise
    (no key resolvable, or ``HEXGATE_LOCAL_MODE`` on), mirroring
    ``PolicyEnforcer.decide()``'s audit.
    """
    try:
        # Before the sender check: a token cap must work with no platform
        # attached, or run.total_tokens stays a permanent 0 in local mode.
        # Bound once, so the tokens and the run_id come from the same object.
        facts = get_run_facts()
        facts.record_llm_usage(input_tokens, output_tokens)

        sender = configure_usage_sender(api_key)
        if sender is None:
            return
        context = get_current_context()
        sender.emit(
            LlmUsageEvent(
                agent_name=agent_name,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
                status=status,
                session_id=context.session_id
                if (context is not None and context.session_id)
                else "",
                user_id=context.user_id if context is not None else "",
                error_code=error_code,
                run_id=facts.id,
            )
        )
    except Exception:
        _log.exception("emit_llm_usage raised; ignoring")


def configure_usage_sender(
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the LLM-usage sender for ``api_key``. Idempotent per key.

    Shares the registry (and the ``HEXGATE_LOCAL_MODE`` gate) with
    :func:`hexgate.audit.configure` via ``hexgate.tracing._senders`` — the
    same api_key configured for decisions returns the very same sender here;
    the span's instrumentation scope keeps the event types apart.
    """
    return get_or_create_sender(api_key, base_url)


def get_usage_sender(api_key: str | None = None) -> AuditSender | None:
    """Return the LLM-usage sender for ``api_key`` (or ``HEXGATE_API_KEY``),
    if configured. Never creates one."""
    return _get_sender(api_key)


async def shutdown() -> None:
    """Flush queued events and stop every sender in the shared registry —
    decisions, LLM usage and ban enforcements alike. Safe to call multiple
    times; equivalent to :func:`hexgate.audit.shutdown` — either name
    flushes the whole shared registry."""
    await _shutdown_all()
