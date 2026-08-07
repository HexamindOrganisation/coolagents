"""Execution-time context — :class:`HexgateContext` (per-invocation scope,
read via :func:`get_current_context` by all SDK adapters) and
:class:`ToolUseContext` (per-tool meta-argument carrying Biscuit-extracted
facts).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass

from pydantic import BaseModel, Field, PrivateAttr

from hexgate.runtime.workspace import Workspace


@dataclass(slots=True)
class ToolUseContext:
    """Runtime context injected into tools as a hidden meta-argument.

    ``biscuit_facts`` carries the single-arity facts the SDK extracted from
    a verified Biscuit envelope — ``user``, ``scope``, numeric limits, etc.
    The policy engine reads them through this context so callers don't have
    to thread facts down to each tool by hand. ``None`` means *no token
    facts present* (local-only flows); ``{}`` means *facts checked but
    nothing extracted*.

    ``verified_attributes`` carries the signed ``attr("key", value)`` facts from
    the same envelope (trusted ABAC tier) — the enforcer prefers these over the
    spoofable :class:`HexgateContext.attributes` bag for trusted keys. Same
    ``None`` / ``{}`` convention as ``biscuit_facts``.
    """

    workspace: Workspace | None = None
    agent_name: str | None = None
    biscuit_facts: dict[str, list[str | int]] | None = None
    verified_attributes: dict[str, str | int | bool] | None = None


_CURRENT_TOOL_USE_CONTEXT: ContextVar[ToolUseContext | None] = ContextVar(
    "hexgate_tool_use_context",
    default=None,
)


def get_current_tool_use_context() -> ToolUseContext | None:
    """Return the current runtime tool context, when one is active."""
    return _CURRENT_TOOL_USE_CONTEXT.get()


def set_current_tool_use_context(
    context: ToolUseContext,
) -> Token[ToolUseContext | None]:
    """Install a tool-use context for the current execution flow."""
    return _CURRENT_TOOL_USE_CONTEXT.set(context)


def reset_current_tool_use_context(token: Token[ToolUseContext | None]) -> None:
    """Restore the previous tool-use context after a run completes."""
    _CURRENT_TOOL_USE_CONTEXT.reset(token)


AttrValue = str | int | bool | list[str]


class HexgateContext(BaseModel):
    """Request-scoped invocation context — async context manager.

    Binds an agent invocation to a caller for the duration of a block. The
    runtime checks for an active context on each invocation, lazily mints a
    per-request Biscuit (signed by the platform-bound
    :class:`~hexgate.cloud.HexgateClient`), and selects a policy from
    ``primary_role``. The policy's per-tool ``constraints`` then evaluate
    against each call's arguments. Four distinct jobs live here, deliberately
    named:

    * identity / audit    -> ``user_id`` / ``session_id``
    * policy selection     -> ``user_roles`` (only ``primary_role`` used today)
    * token lifetime       -> ``ttl_seconds`` (feeds attenuation, never policy)
    * ABAC filter surface  -> ``attributes`` (feeds the ``ctx.*`` constraint
      namespace; untrusted/spoofable — same trust tier as ``user_roles``, since
      both are read from this contextvar rather than a verified token. A future
      signed tier will let declared keys be token-verified.)

    Two invocation styles, same machinery underneath:

    * Ambient (FastAPI-friendly)::

          async with HexgateContext(user_id="alice", user_roles=["billing"]):
              async for event in stream_agent(agent, handler, input):
                  ...

    * Explicit (when contextvar inheritance is unreliable, e.g. you spawn
      a task without copying context)::

          ctx = ToolUseContext(biscuit_facts={"user": ["alice"]})
          async for event in stream_agent(
              agent, handler, input, tool_use_context=ctx
          ):
              ...

    The class is intentionally async-only — ``__aenter__`` / ``__aexit__``
    are cheap today but reserved for I/O later (audit emission on exit,
    KMS-backed signing on enter, JWKS freshness check, etc.). Sync callers
    can still wrap with ``asyncio.run(...)``.
    """

    user_id: str
    user_roles: list[str] = Field(
        default_factory=list,
        description="The roles of the end user invoking the agent.",
    )
    session_id: str | None = None
    ttl_seconds: int | None = None
    attributes: dict[str, AttrValue] = Field(
        default_factory=dict,
        description=(
            "Caller attributes for ABAC ctx.* filtering. Untrusted (spoofable, "
            "same tier as user_roles) until the signed tier verifies them."
        ),
    )

    # Stack of shadowed values (supports nested scopes). We save/restore via
    # set() rather than reset(token): async-generator finalizers run __aexit__
    # in a different Context, where a token reset would raise — set() doesn't.
    _saved: list["HexgateContext | None"] = PrivateAttr(default_factory=list)

    @property
    def primary_role(self) -> str | None:
        """Single role used for policy selection today. Multi-role widens the
        *selector* later; callers read this, never ``user_roles[0]`` directly."""
        return self.user_roles[0] if self.user_roles else None

    async def __aenter__(self) -> "HexgateContext":
        self._saved.append(_CURRENT_CONTEXT.get())
        _CURRENT_CONTEXT.set(self)
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._saved:
            _CURRENT_CONTEXT.set(self._saved.pop())

    @contextmanager
    def sync_scope(self) -> Iterator["HexgateContext"]:
        """Sync mirror of ``async with self`` for sync entry points."""
        self._saved.append(_CURRENT_CONTEXT.get())
        _CURRENT_CONTEXT.set(self)
        try:
            yield self
        finally:
            if self._saved:
                _CURRENT_CONTEXT.set(self._saved.pop())


_CURRENT_CONTEXT: ContextVar[HexgateContext | None] = ContextVar(
    "hexgate_current_context",
    default=None,
)


def get_current_context() -> HexgateContext | None:
    """Return the active :class:`HexgateContext` for this flow, if any."""
    return _CURRENT_CONTEXT.get()
