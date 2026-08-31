from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from hexgate.runtime.context import get_current_context
from hexgate.runtime.run_facts import get_run_facts
from hexgate.tracing._senders import AuditSender, get_or_create_sender
from hexgate.tracing._senders import get_sender as _get_sender
from hexgate.tracing._senders import shutdown as _shutdown_all

_log = logging.getLogger(__name__)

_LLM_USAGE_PATH = "/v1/audit/llm-invocations"


@dataclass(frozen=True, slots=True)
class LlmUsageEvent:
    agent_name: str
    model: str
    input_tokens: int
    output_tokens: int
    latency_ms: int
    status: str  # e.g., "success", "error"
    session_id: str = ""
    user_id: str = ""
    error_code: str | None = None  # optional error code if status is "error"
    # The run this model request belongs to, so llm_invocation rows join to the
    # policy_decision rows of the same invocation. ``""`` outside a run scope,
    # matching ``run_facts.DETACHED.id``; a plain field rather than the six-way
    # RunAttribution because llm_invocation carries one run column, and the
    # counters mid-request are not what a token total should be read from.
    run_id: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_payload(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "occurred_at": self.occurred_at.isoformat(),
            "agent_name": self.agent_name,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_ms": self.latency_ms,
            "status": self.status,
            "error_code": self.error_code or "",
            # None, never "": the platform types run_id as ``UUID | None`` and
            # rejects an empty string with a 422, which the sender drops rather
            # than retries — losing the whole usage record, not just its
            # attribution.
            "run_id": self.run_id or None,
        }


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
        # Bound once, so the tokens recorded and the run they are attributed to
        # are structurally the same run rather than incidentally so.
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
    same api_key configured for decisions gets its own sender here, keyed
    separately by endpoint path so the two event types never collide.
    """
    return get_or_create_sender(_LLM_USAGE_PATH, api_key, base_url)


def get_usage_sender(api_key: str | None = None) -> AuditSender | None:
    """Return the LLM-usage sender for ``api_key`` (or ``HEXGATE_API_KEY``),
    if configured. Never creates one."""
    return _get_sender(_LLM_USAGE_PATH, api_key)


async def shutdown() -> None:
    """Drain in-flight emits and close every sender in the shared registry
    (decisions and LLM usage alike). Safe to call multiple times;
    equivalent to :func:`hexgate.audit.shutdown` — either name drains the
    whole shared registry."""
    await _shutdown_all()
