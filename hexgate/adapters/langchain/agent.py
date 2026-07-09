"""Proxy around a pre-built ``CompiledStateGraph`` for Hexgate-aware calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, AsyncIterator, Iterator, Literal

from langchain_core.runnables import RunnableConfig
from langfuse import get_client, propagate_attributes
from langfuse.langchain import CallbackHandler
from langgraph.graph.state import CompiledStateGraph

from hexgate.adapters.langchain.usage import HexgateUsageCallbackHandler
from hexgate.runtime import User

if TYPE_CHECKING:
    from hexgate.security.binding import PolicyBinding


class HexgateLangchainAgent:
    """Proxy around a ``CompiledStateGraph`` that opens a User scope per call.

    Tools are already enforcer-installed at construction (by
    :func:`wrap_langchain_agent`). This proxy pushes the active
    :class:`User` onto the contextvar and propagates identity into
    Langfuse spans. ``user`` is per-call, so one proxy serves many
    users concurrently. When a policy binding is attached, every run
    method refreshes it first (fail-soft; 304 when unchanged).
    """

    def __init__(
        self,
        *,
        agent: CompiledStateGraph,
        api_key: str,
        tool_names: list[str],
        agent_name: str = "default",
        binding: PolicyBinding | None = None,
    ) -> None:
        self._agent = agent
        self._binding = binding
        self._api_key = api_key
        self._tool_names = tool_names
        self._langfuse = get_client()
        self._callback_handler = CallbackHandler()
        self._usage_handler = HexgateUsageCallbackHandler(
            agent_name=agent_name, api_key=api_key
        )

    async def _refresh_async(self) -> None:
        """Refresh the policy binding, if attached (async entry points)."""
        if self._binding is not None:
            await self._binding.refresh_async()

    def _refresh(self) -> None:
        """Refresh the policy binding, if one is attached (sync entry points)."""
        if self._binding is not None:
            self._binding.refresh()

    def _propagate_kwargs(self, user: User, method: str) -> dict[str, Any]:
        return {
            "tags": [f"langchain.agent.{method}"],
            "user_id": user.user_id,
            "session_id": user.session_id,
            "metadata": {"user_role": user.role},
        }

    def _with_callbacks(self, config: RunnableConfig | None) -> RunnableConfig:
        """Append the Hexgate callback handlers to ``config['callbacks']``."""
        merged: RunnableConfig = dict(config) if config else {}
        callbacks = list(merged.get("callbacks") or [])
        for handler in (self._callback_handler, self._usage_handler):
            if handler not in callbacks:
                callbacks.append(handler)
        merged["callbacks"] = callbacks
        return merged

    async def ainvoke(
        self,
        input: dict[str, Any],
        *,
        user: User,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Invoke the agent asynchronously inside a User scope."""
        await self._refresh_async()
        async with user:
            with propagate_attributes(**self._propagate_kwargs(user, "ainvoke")):
                return await self._agent.ainvoke(
                    input, self._with_callbacks(config), **kwargs
                )

    def invoke(
        self,
        input: dict[str, Any],
        *,
        user: User,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Invoke the agent synchronously inside a User scope."""
        self._refresh()
        with user.sync_scope():
            with propagate_attributes(**self._propagate_kwargs(user, "invoke")):
                return self._agent.invoke(input, self._with_callbacks(config), **kwargs)

    async def astream(
        self,
        input: dict[str, Any],
        *,
        user: User,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream the agent asynchronously inside a User scope."""
        await self._refresh_async()
        async with user:
            with propagate_attributes(**self._propagate_kwargs(user, "astream")):
                async for chunk in self._agent.astream(
                    input, self._with_callbacks(config), **kwargs
                ):
                    yield chunk

    def stream(
        self,
        input: dict[str, Any],
        *,
        user: User,
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> Iterator[dict[str, Any]]:
        """Stream the agent synchronously inside a User scope."""
        self._refresh()
        with user.sync_scope():
            with propagate_attributes(**self._propagate_kwargs(user, "stream")):
                yield from self._agent.stream(
                    input, self._with_callbacks(config), **kwargs
                )

    async def astream_events(
        self,
        input: dict[str, Any],
        *,
        user: User,
        config: RunnableConfig | None = None,
        version: Literal["v1", "v2"] = "v2",
        **kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream the agent events asynchronously inside a User scope."""
        await self._refresh_async()
        async with user:
            with propagate_attributes(**self._propagate_kwargs(user, "astream_events")):
                async for event in self._agent.astream_events(
                    input,
                    config=self._with_callbacks(config),
                    version=version,
                    **kwargs,
                ):
                    yield event

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the wrapped agent."""
        return getattr(self._agent, name)
