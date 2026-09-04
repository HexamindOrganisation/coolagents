"""Internal helpers shared across all four framework adapters.

Not part of the public API — each adapter's own module is the supported
import surface.
"""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncIterator, Iterator

from langfuse import propagate_attributes

from hexgate.runtime import HexgateContext, run_scope

# Langfuse silently drops a propagated metadata value over 200 chars, so the
# joined role list is truncated to fit (with an ASCII ellipsis — non-ASCII
# values are dropped too). Only bites on an unusually large role list.
_MAX_METADATA_CHARS = 200


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
