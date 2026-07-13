"""Framework-agnostic Langfuse helpers.

Split from :mod:`hexgate.tracing.langfuse` so consumers that only need
the Langfuse client + observe decorator + trace-URL helper (adapter
runners, ``@agent_tool``-decorated built-ins, the CLI trace hint) can
avoid the LangChain-tied ``CallbackHandler`` path.

The LC-flavored helpers (``get_langfuse_handler``,
``get_langfuse_runnable_config``, the ``CallbackHandler`` re-export)
stay in :mod:`hexgate.tracing.langfuse`; they eagerly import
``langfuse.langchain`` and ``langchain_core.runnables``.
"""

from __future__ import annotations

from typing import Any, Protocol

from langfuse import get_client, observe, propagate_attributes


class LangfuseHandler(Protocol):
    """Structural type for the Langfuse callback handler used by hexgate."""

    last_trace_id: str | None
    langfuse_metadata: dict[str, Any]


def maybe_get_trace_url(handler: LangfuseHandler | None = None) -> str | None:
    """Return the current trace URL if Langfuse is active."""
    client = get_client()
    trace_id = getattr(handler, "last_trace_id", None) if handler is not None else None
    try:
        return client.get_trace_url(trace_id=trace_id)
    except Exception:
        return None


__all__ = [
    "LangfuseHandler",
    "get_client",
    "maybe_get_trace_url",
    "observe",
    "propagate_attributes",
]
