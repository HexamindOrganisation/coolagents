"""Shared helpers for resolving an approval_handler return value.

Every adapter (LangChain, OpenAI Agents, Pydantic AI, Google ADK) needs
the same normalization: accept a `bool` shortcut, accept a sync
callable, accept an async callable, coerce to bool. Extracted here so
the three adapter-local copies don't drift — the LangChain version
already has a guard the others were missing.
"""

from __future__ import annotations

from inspect import isawaitable
from typing import Any

from hexgate.approvals import ApprovalHandler
from hexgate.security.decision import Decision


def resolve_approval_sync(handler: ApprovalHandler, decision: Decision) -> bool:
    """Resolve a NEEDS_APPROVAL decision from a sync caller.

    Rejects a coroutine-returning handler: the caller has no event loop
    to await it in. The right fix in that case is to switch to an async
    tool invocation path (ainvoke / astream / astream_events on
    LangChain, `run_async` on Google ADK, etc.).
    """
    if isinstance(handler, bool):
        return handler
    result: Any = handler(decision)
    if isawaitable(result):
        raise RuntimeError(
            "approval_handler returned a coroutine; sync tool invocation cannot "
            "await it — use an async entry point (ainvoke / astream / "
            "astream_events / run_async / etc.) so the handler can be awaited."
        )
    return bool(result)


async def resolve_approval_async(handler: ApprovalHandler, decision: Decision) -> bool:
    """Resolve a NEEDS_APPROVAL decision from an async caller.

    Accepts both sync-callable and async-callable handlers uniformly —
    ``bool`` short-circuits without invocation.
    """
    if isinstance(handler, bool):
        return handler
    result: Any = handler(decision)
    if isawaitable(result):
        result = await result
    return bool(result)


__all__ = ["resolve_approval_async", "resolve_approval_sync"]
