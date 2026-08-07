"""Proxy around a pydantic_ai ``Agent`` for Hexgate-aware calls."""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator

from langfuse import get_client, propagate_attributes
from pydantic_ai import Agent
from pydantic_ai.agent import AgentRun, AgentRunResult
from pydantic_ai.result import StreamedRunResult

from hexgate.adapters._common import langfuse_propagate_kwargs
from hexgate.adapters.pydantic_ai.usage import emit_run_usage
from hexgate.runtime import HexgateContext

if TYPE_CHECKING:
    from hexgate.security.bans import BanGate
    from hexgate.security.binding import PolicyBinding


class HexgatePydanticAgent:
    """Proxy around a pydantic_ai ``Agent`` that opens a HexgateContext scope per call.

    Tools are already enforcer-installed at construction (by
    :func:`wrap_pydantic_agent`). This proxy pushes the active
    :class:`HexgateContext` onto the contextvar and propagates identity into
    Langfuse spans. ``hexgate_context`` is per-call, so one proxy serves many
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

    async def _check_ban_async(self, context: HexgateContext) -> None:
        """Refuse a banned agent/user before running, if a gate is attached."""
        if self._ban_gate is not None:
            await self._ban_gate.check_async(context)

    def _check_ban(self, context: HexgateContext) -> None:
        if self._ban_gate is not None:
            self._ban_gate.check(context)

    def _setup_observability(self) -> None:
        """Globally instrument all pydantic_ai Agents (idempotent)."""
        Agent.instrument_all()

    def _propagate_kwargs(self, context: HexgateContext, method: str) -> dict[str, Any]:
        return langfuse_propagate_kwargs(context, f"pydantic_ai.agent.{method}")

    @asynccontextmanager
    async def _abind(self, context: HexgateContext, method: str) -> AsyncIterator[None]:
        """Async HexgateContext scope + Langfuse propagation."""
        async with context:
            with propagate_attributes(**self._propagate_kwargs(context, method)):
                yield

    @contextmanager
    def _bind(self, context: HexgateContext, method: str) -> Iterator[None]:
        """Sync HexgateContext scope + Langfuse propagation."""
        with context.sync_scope():
            with propagate_attributes(**self._propagate_kwargs(context, method)):
                yield

    async def run(
        self,
        *args: Any,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> AgentRunResult[Any]:
        """Run the agent asynchronously inside a HexgateContext scope."""
        await self._refresh_async()
        await self._check_ban_async(hexgate_context)
        async with self._abind(hexgate_context, "run"):
            result = await self._agent.run(*args, **kwargs)
            emit_run_usage(self._agent_name, self._agent, result, api_key=self._api_key)
            return result

    def run_sync(
        self,
        *args: Any,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> AgentRunResult[Any]:
        """Run the agent synchronously inside a HexgateContext scope."""
        self._refresh()
        self._check_ban(hexgate_context)
        with self._bind(hexgate_context, "run_sync"):
            result = self._agent.run_sync(*args, **kwargs)
            emit_run_usage(self._agent_name, self._agent, result, api_key=self._api_key)
            return result

    @asynccontextmanager
    async def run_stream(
        self,
        *args: Any,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> AsyncIterator[StreamedRunResult[Any, Any]]:
        """Stream the agent response asynchronously inside a HexgateContext scope."""
        await self._refresh_async()
        await self._check_ban_async(hexgate_context)
        async with self._abind(hexgate_context, "run_stream"):
            async with self._agent.run_stream(*args, **kwargs) as result:
                yield result
                # Emit usage only if the run completed, not if the caller aborted mid-stream,
                # because the usage counts from pydantic's side are 0 until the run completes.
                # This can happen if a user cancels a LLM request mid-response: we will never
                # know the total number of input / output tokens, however they are still charged by the LLM provider.
                # This is a known limitation of pydantic_ai's usage reporting, and we will not be able to report usage in this case.
                if result.is_complete:
                    emit_run_usage(
                        self._agent_name, self._agent, result, api_key=self._api_key
                    )

    @asynccontextmanager
    async def iter(
        self,
        *args: Any,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> AsyncIterator[AgentRun[Any, Any]]:
        """Iterate over the agent execution graph asynchronously."""
        await self._refresh_async()
        await self._check_ban_async(hexgate_context)
        async with self._abind(hexgate_context, "iter"):
            async with self._agent.iter(*args, **kwargs) as run:
                yield run
                if run.result is not None:
                    emit_run_usage(
                        self._agent_name, self._agent, run, api_key=self._api_key
                    )

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the wrapped agent.

        Only the wrapped run methods (run/run_sync/run_stream/iter) enforce the
        ban gate + HexgateContext scope; methods reached here (to_a2a, to_ag_ui, …) bypass
        them.
        """
        return getattr(self._agent, name)
