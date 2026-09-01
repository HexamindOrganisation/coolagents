"""Internal helpers shared across all four framework adapters.

Not part of the public API — each adapter's own module is the supported
import surface.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Iterator

from langfuse import propagate_attributes

from hexgate.runtime import HexgateContext, run_scope
from hexgate.tracing._senders import DEFAULT_DRAIN_TIMEOUT, pending_send_tasks

# Langfuse silently drops a propagated metadata value over 200 chars, so the
# joined role list is truncated to fit (with an ASCII ellipsis — non-ASCII
# values are dropped too). Only bites on an unusually large role list.
_MAX_METADATA_CHARS = 200


def drain_pending_tasks(
    loop: asyncio.AbstractEventLoop, *, drain_timeout: float = DEFAULT_DRAIN_TIMEOUT
) -> None:
    """Give hexgate's own still-pending audit-send tasks on ``loop`` one
    last chance to finish.

    A fire-and-forget audit-send (policy decision / LLM usage) from the
    last turn can still be scheduled and pending once the top-level run
    settles, with nothing left to pump the loop for it — silently
    abandoned otherwise. Scoped to ``pending_send_tasks(loop)`` rather than
    every task on the loop — ``loop`` is a thread's shared default loop,
    not one hexgate owns exclusively, and awaiting (or, on timeout,
    cancelling) a caller's unrelated task would be a surprising, unrelated
    side effect. ``return_exceptions=True`` so a failed send can't raise
    out of here and crash the caller's run.

    Bounded by ``drain_timeout``: an unreachable platform can hold a send
    open for well over 10s (POST timeout, then a 503 jitter sleep, then a
    retry POST), and this runs synchronously inside the caller's
    ``run_sync()`` — a dropped audit event beats hanging its return.
    """
    pending = pending_send_tasks(loop)
    if not pending:
        return
    try:
        loop.run_until_complete(
            asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), drain_timeout
            )
        )
    except TimeoutError:
        pass


def langfuse_propagate_kwargs(context: HexgateContext, tag: str) -> dict[str, Any]:
    """Build the ``propagate_attributes(**kwargs)`` mapping for a Langfuse
    span tagged ``tag``, carrying the active context's identity."""
    # Langfuse drops non-string metadata values, so stamp the role list as a
    # comma-joined string (not the lossy single role), truncated to the cap.
    roles = ", ".join(context.user_roles)
    if len(roles) > _MAX_METADATA_CHARS:
        roles = roles[: _MAX_METADATA_CHARS - 3] + "..."
    return {
        "tags": [tag],
        "user_id": context.user_id,
        "session_id": context.session_id,
        "metadata": {"user_roles": roles},
    }


@asynccontextmanager
async def abind(
    context: HexgateContext, agent_name: str, tag: str
) -> AsyncIterator[None]:
    """Async run boundary shared by every adapter proxy: identity scope, run facts,
    then Langfuse propagation, so the facts are live wherever a tool call executes.

    Takes the span ``tag`` rather than the built kwargs — it embeds the caller's
    method name, and resolving it here keeps the attributes read inside the scopes.
    """
    async with context:
        with run_scope(agent_name):
            with propagate_attributes(**langfuse_propagate_kwargs(context, tag)):
                yield


@contextmanager
def bind(context: HexgateContext, agent_name: str, tag: str) -> Iterator[None]:
    """Sync mirror of :func:`abind`."""
    with context.sync_scope():
        with run_scope(agent_name):
            with propagate_attributes(**langfuse_propagate_kwargs(context, tag)):
                yield
