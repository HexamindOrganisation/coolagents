"""``Runner`` wrapper: opens a :class:`User` scope around each ``Runner.run*``
call so the wrapped tools' enforcers can resolve the active role.
Langfuse propagation mirrors the User identity into trace metadata.

One policy binding is cached per agent name (first run resolves, later
runs are ETag/304 refreshes); the per-call rewrap closes over the cached
enforcer, so a refresh swap reaches every clone.
"""

import asyncio
from contextlib import contextmanager

import nest_asyncio
from agents import (
    Agent,
    RunConfig,
    Runner,
    RunResult,
    RunResultStreaming,
    RunState,
    TContext,
    TResponseInputItem,
)
from langfuse import get_client, propagate_attributes
from openinference.instrumentation.openai_agents import OpenAIAgentsInstrumentor

from hexgate.adapters.openai.wrapper import wrap_openai_agent
from hexgate.agents.factory import ApprovalHandler
from hexgate.config.env import resolve_api_key
from hexgate.runtime import User
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer


class HexgateRunner:
    """Runner for OpenAI agents with Hexgate tool policy and observability."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        approval_handler: ApprovalHandler | None = None,
    ):
        self.api_key = resolve_api_key(api_key)
        if self.api_key is None:
            raise ValueError(
                "HEXGATE_API_KEY is not set. Pass api_key= explicitly or set the HEXGATE_API_KEY environment variable."
            )
        # Cached per agent name — keeps the ETag memory alive across runs.
        self._bindings: dict[str, PolicyBinding] = {}
        self._approval_handler = approval_handler

    def _binding_for(self, agent: Agent) -> PolicyBinding:
        """Get-or-resolve the cached policy binding for ``agent``'s name.

        First call resolves (loud-failure point) and rebuilds the
        enforcer with this runner's audit sender. Fail-loud: an
        unregistered agent (platform 404) raises — register it first with
        ``hexgate register``.
        """
        # `or "default"` collapses a None/empty name to a real string (matches
        # the pydantic_ai adapter) so a null identity never reaches the cache
        # key or the platform resolve / enforcer / audit below.
        name = getattr(agent, "name", None) or "default"
        binding = self._bindings.get(name)
        if binding is None:
            resolved = resolve_policy(name, api_key=self.api_key)
            enforcer = build_enforcer(
                resolved.engine, agent_name=name, api_key=self.api_key
            )
            binding = PolicyBinding(enforcer, resolved.source)
            self._bindings[name] = binding
        return binding

    def _setup_observability(self):
        """Install Langfuse + OpenAIAgentsInstrumentor (idempotent)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop: safe to patch (and only useful for sync entry points).
            # Patching a live loop breaks asyncio.current_task() on Python 3.12+.
            nest_asyncio.apply()
        get_client()
        OpenAIAgentsInstrumentor().instrument()

    @contextmanager
    def _propagate(self, user: User, agent_name: str):
        """Propagate User identity into Langfuse spans for the block."""
        kwargs: dict[str, any] = {"tags": [f"openai.runner.run.{agent_name}"]}
        kwargs["user_id"] = user.user_id
        kwargs["session_id"] = user.session_id
        kwargs["metadata"] = {"user_role": user.role}
        with propagate_attributes(**kwargs):
            yield

    async def run(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        user: User,
        run_config: RunConfig | None = None,
        **kwargs,
    ) -> RunResult:
        """Run the OpenAI agent asynchronously inside a User scope."""
        self._setup_observability()
        binding = self._binding_for(agent)
        await binding.refresh_async()  # per-run policy pull; 304 when unchanged
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )
        async with user:
            with self._propagate(user, agent.name):
                return await Runner.run(
                    wrapped_agent, input, run_config=run_config, **kwargs
                )

    def run_sync(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        user: User,
        run_config: RunConfig | None = None,
        **kwargs,
    ) -> RunResult:
        """Run the OpenAI agent synchronously inside a User scope."""
        self._setup_observability()
        binding = self._binding_for(agent)
        binding.refresh()  # per-run policy pull; 304 when unchanged
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )
        with user.sync_scope():
            with self._propagate(user, agent.name):
                return Runner.run_sync(
                    wrapped_agent, input, run_config=run_config, **kwargs
                )

    def run_streamed(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        user: User,
        run_config: RunConfig | None = None,
        **kwargs,
    ) -> RunResultStreaming:
        """Stream the OpenAI agent inside a User scope.

        ``Runner.run_streamed`` returns sync but spawns the agent loop as a
        background task that snapshots the current contextvars at creation;
        tools fire there, not in ``stream_events``. So the User scope must be
        active around the ``run_streamed`` call for the task to inherit it —
        the wrapped iterator re-opens it for exit/audit semantics.
        """
        self._setup_observability()
        binding = self._binding_for(agent)
        binding.refresh()  # must precede the wrap + setup
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )

        with user.sync_scope():
            with self._propagate(user, agent.name):
                result = Runner.run_streamed(
                    wrapped_agent, input, run_config=run_config, **kwargs
                )

        original_stream_events = result.stream_events

        async def _stream_events_with_scope():
            async with user:
                with self._propagate(user, agent.name):
                    async for event in original_stream_events():
                        yield event

        result.stream_events = _stream_events_with_scope
        return result
