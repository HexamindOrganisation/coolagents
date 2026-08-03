"""Internal helpers shared across all four framework adapters.

Not part of the public API — each adapter's own module is the supported
import surface.
"""

from __future__ import annotations

import asyncio
from typing import Any

from hexgate.runtime import User


def drain_pending_tasks(loop: asyncio.AbstractEventLoop) -> None:
    """Give any still-pending tasks on ``loop`` one last chance to finish.

    A fire-and-forget audit-send (policy decision / LLM usage) from the
    last turn can still be scheduled and pending once the top-level run
    settles, with nothing left to pump the loop for it — silently
    abandoned otherwise. ``return_exceptions=True`` so a failed send can't
    raise out of here and crash the caller's run.
    """
    pending = asyncio.all_tasks(loop)
    if pending:
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))


def langfuse_propagate_kwargs(user: User, tag: str) -> dict[str, Any]:
    """Build the ``propagate_attributes(**kwargs)`` mapping for a Langfuse
    span tagged ``tag``, carrying the active User's identity."""
    return {
        "tags": [tag],
        "user_id": user.user_id,
        "session_id": user.session_id,
        "metadata": {"user_role": user.role},
    }
