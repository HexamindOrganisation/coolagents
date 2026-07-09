"""Proxy around a pydantic_ai ``Agent`` for Hexgate-aware calls."""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator

from langfuse import get_client, propagate_attributes
from pydantic_ai import Agent
from pydantic_ai.agent import AgentRun, AgentRunResult
from pydantic_ai.result import StreamedRunResult

from hexgate.runtime import User

if TYPE_CHECKING:
    from hexgate.security.bans import BanGate
    from hexgate.security.binding import PolicyBinding


class HexgatePydanticAgent:
    """Proxy around a pydantic_ai ``Agent`` that opens a User scope per call.

    Tools are already enforcer-installed at construction (by
    :func:`wrap_pydantic_agent`). This proxy pushes the active
    :class:`User` onto the contextvar and propagates identity into
    Langfuse spans. ``user`` is per-call, so one proxy serves many
    users concurrently. When a policy binding is attached, every run
    method refreshes it first (fail-soft; 304 when unchanged).
    """

    def __init__(
        self,
        *,
        agent: Agent,
        api_key: str,
        agent_name: str,
        binding: PolicyBinding | None = None,
        ban_gate: BanGate | None = None,
    ) -> None:
        self._agent = agent
        self._binding = binding
        self._ban_gate = ban_gate
        self._api_key = api_key
        self._agent_name = agent_name
        self._langfuse = get_client()
        self._setup_observability()

    async def _refresh_async(self) -> None:
        """Refresh the policy binding, if attached (async entry points)."""
        if self._binding is not None:
            await self._binding.refresh_async()

    def _refresh(self) -> None:
        """Refresh the policy binding, if one is attached (sync entry points)."""
        if self._binding is not None:
            self._binding.refresh()

    async def _check_ban_async(self, user: User) -> None:
        """Refuse a banned agent/user before running, if a gate is attached."""
        if self._ban_gate is not None:
            await self._ban_gate.check_async(user)

    def _check_ban(self, user: User) -> None:
        if self._ban_gate is not None:
            self._ban_gate.check(user)

    def _setup_observability(self) -> None:
        """Globally instrument all pydantic_ai Agents (idempotent)."""
        Agent.instrument_all()

    def _propagate_kwargs(self, user: User, method: str) -> dict[str, Any]:
        return {
            "tags": [f"pydantic_ai.agent.{method}"],
            "user_id": user.user_id,
            "session_id": user.session_id,
            "metadata": {"user_role": user.role},
        }

    @asynccontextmanager
    async def _abind(self, user: User, method: str) -> AsyncIterator[None]:
        """Async User scope + Langfuse propagation."""
        async with user:
            with propagate_attributes(**self._propagate_kwargs(user, method)):
                yield

    @contextmanager
    def _bind(self, user: User, method: str) -> Iterator[None]:
        """Sync User scope + Langfuse propagation."""
        with user.sync_scope():
            with propagate_attributes(**self._propagate_kwargs(user, method)):
                yield

    async def run(
        self,
        *args: Any,
        user: User,
        **kwargs: Any,
    ) -> AgentRunResult[Any]:
        """Run the agent asynchronously inside a User scope."""
        await self._refresh_async()
        await self._check_ban_async(user)
        async with self._abind(user, "run"):
            return await self._agent.run(*args, **kwargs)

    def run_sync(
        self,
        *args: Any,
        user: User,
        **kwargs: Any,
    ) -> AgentRunResult[Any]:
        """Run the agent synchronously inside a User scope."""
        self._refresh()
        self._check_ban(user)
        with self._bind(user, "run_sync"):
            return self._agent.run_sync(*args, **kwargs)

    @asynccontextmanager
    async def run_stream(
        self,
        *args: Any,
        user: User,
        **kwargs: Any,
    ) -> AsyncIterator[StreamedRunResult[Any, Any]]:
        """Stream the agent response asynchronously inside a User scope."""
        await self._refresh_async()
        await self._check_ban_async(user)
        async with self._abind(user, "run_stream"):
            async with self._agent.run_stream(*args, **kwargs) as result:
                yield result

    @asynccontextmanager
    async def iter(
        self,
        *args: Any,
        user: User,
        **kwargs: Any,
    ) -> AsyncIterator[AgentRun[Any, Any]]:
        """Iterate over the agent execution graph asynchronously."""
        await self._refresh_async()
        await self._check_ban_async(user)
        async with self._abind(user, "iter"):
            async with self._agent.iter(*args, **kwargs) as run:
                yield run

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the wrapped agent."""
        return getattr(self._agent, name)
