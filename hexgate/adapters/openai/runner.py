"""``Runner`` wrapper: opens a :class:`HexgateContext` scope around each ``Runner.run*``
call so the wrapped tools' enforcers can resolve the active role.
Langfuse propagation mirrors the HexgateContext identity into trace metadata.

One policy binding is cached per agent name (first run resolves, later
runs are ETag/304 refreshes); the per-call rewrap closes over the cached
enforcer, so a refresh swap reaches every clone.
"""

import asyncio
import warnings
from contextlib import contextmanager

import nest_asyncio
from agents import (
    Agent,
    RunConfig,
    RunHooks,
    Runner,
    RunResult,
    RunResultStreaming,
    RunState,
    TContext,
    TResponseInputItem,
)
from agents.lifecycle import RunHooksBase
from langfuse import get_client, propagate_attributes
from openinference.instrumentation.openai_agents import OpenAIAgentsInstrumentor

from hexgate.adapters._common import drain_pending_tasks, langfuse_propagate_kwargs
from hexgate.adapters.openai.usage import HexgateUsageHooks
from hexgate.adapters.openai.wrapper import wrap_openai_agent
from hexgate.approvals import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.runtime import HexgateContext
from hexgate.security.bans import BanGate, resolve_ban_gate
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer


class _CompositeRunHooks(RunHooks):
    """Fan a run's lifecycle callbacks out to multiple ``RunHooks``.

    ``Runner.run*`` accepts exactly one ``hooks=`` object; when the caller
    already passed one, ``HexgateUsageHooks`` must not replace it — this
    composes both and forwards every ``RunHooksBase`` callback to each in
    turn.
    """

    def __init__(self, hooks: list[RunHooksBase]) -> None:
        self._hooks = hooks

    async def on_llm_start(self, context, agent, system_prompt, input_items) -> None:
        for hook in self._hooks:
            await hook.on_llm_start(context, agent, system_prompt, input_items)

    async def on_llm_end(self, context, agent, response) -> None:
        for hook in self._hooks:
            await hook.on_llm_end(context, agent, response)

    async def on_agent_start(self, context, agent) -> None:
        for hook in self._hooks:
            await hook.on_agent_start(context, agent)

    async def on_agent_end(self, context, agent, output) -> None:
        for hook in self._hooks:
            await hook.on_agent_end(context, agent, output)

    async def on_handoff(self, context, from_agent, to_agent) -> None:
        for hook in self._hooks:
            await hook.on_handoff(context, from_agent, to_agent)

    async def on_tool_start(self, context, agent, tool) -> None:
        for hook in self._hooks:
            await hook.on_tool_start(context, agent, tool)

    async def on_tool_end(self, context, agent, tool, result) -> None:
        for hook in self._hooks:
            await hook.on_tool_end(context, agent, tool, result)


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
        # One client shared by the policy and ban resolvers below.
        self._client = HexgateClient(HexgateConfig.from_env(api_key=self.api_key))
        # Cached per agent name — keeps the ETag memory alive across runs.
        self._bindings: dict[str, PolicyBinding] = {}
        # Ban gates cached per agent name too (None cached to avoid re-resolving).
        self._ban_gates: dict[str, BanGate | None] = {}
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
            resolved = resolve_policy(name, api_key=self.api_key, client=self._client)
            enforcer = build_enforcer(
                resolved.engine, agent_name=name, api_key=self.api_key
            )
            binding = PolicyBinding(enforcer, resolved.source)
            self._bindings[name] = binding
        return binding

    def _ban_gate_for(self, agent: Agent) -> BanGate | None:
        """Get-or-resolve the cached ban gate for ``agent``'s name (``None`` in
        local mode / no key). ``None`` is cached too, so we resolve once."""
        name = getattr(agent, "name", None) or "default"
        if name not in self._ban_gates:
            self._ban_gates[name] = resolve_ban_gate(
                name, api_key=self.api_key, client=self._client
            )
        return self._ban_gates[name]

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
    def _propagate(self, context: HexgateContext, agent_name: str):
        """Propagate HexgateContext identity into Langfuse spans for the block."""
        with propagate_attributes(
            **langfuse_propagate_kwargs(context, f"openai.runner.run.{agent_name}")
        ):
            yield

    def _merge_hooks(self, hooks: RunHooks | None) -> RunHooks:
        """Compose caller-supplied ``hooks`` with the usage hook — never
        clobber a hooks object the caller already passed."""
        usage_hooks = HexgateUsageHooks(api_key=self.api_key)
        if hooks is None:
            return usage_hooks
        return _CompositeRunHooks([hooks, usage_hooks])

    async def run(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
<<<<<<< HEAD
        *,
=======
>>>>>>> 38ae2327044067c3956d3748d22806d5a9c9cb41
        hexgate_context: HexgateContext,
        run_config: RunConfig | None = None,
        hooks: RunHooks | None = None,
        **kwargs,
    ) -> RunResult:
        """Run the OpenAI agent asynchronously inside a HexgateContext scope."""
        self._setup_observability()
        binding = self._binding_for(agent)
        await binding.refresh_async()  # per-run policy pull; 304 when unchanged
        ban_gate = self._ban_gate_for(agent)
        if ban_gate is not None:
            await ban_gate.check_async(hexgate_context)
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )
        async with hexgate_context:
            with self._propagate(hexgate_context, agent.name):
                return await Runner.run(
                    wrapped_agent,
                    input,
                    run_config=run_config,
                    hooks=self._merge_hooks(hooks),
                    **kwargs,
                )

    def run_sync(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
<<<<<<< HEAD
        *,
=======
>>>>>>> 38ae2327044067c3956d3748d22806d5a9c9cb41
        hexgate_context: HexgateContext,
        run_config: RunConfig | None = None,
        hooks: RunHooks | None = None,
        **kwargs,
    ) -> RunResult:
        """Run the OpenAI agent synchronously inside a HexgateContext scope."""
        self._setup_observability()
        binding = self._binding_for(agent)
        binding.refresh()  # per-run policy pull; 304 when unchanged
        ban_gate = self._ban_gate_for(agent)
        if ban_gate is not None:
            ban_gate.check(hexgate_context)
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )
        with hexgate_context.sync_scope():
            with self._propagate(hexgate_context, agent.name):
                try:
                    return Runner.run_sync(
                        wrapped_agent,
                        input,
                        run_config=run_config,
                        hooks=self._merge_hooks(hooks),
                        **kwargs,
                    )
                finally:
                    self._drain_default_loop()

    def _drain_default_loop(self) -> None:
        """``AgentRunner.run_sync`` (the ``agents`` SDK) deliberately keeps
        its per-thread default loop open across calls rather than closing
        it, but ``run_until_complete`` only waits for the top-level run —
        not sibling tasks on the same loop. The last turn's fire-and-forget
        audit-send (policy decision / LLM usage) can still be scheduled and
        pending when ``run_sync`` returns, with nothing left to pump the
        loop for it. Give it one last chance here; don't close the loop —
        the SDK expects to find the same one open on the next call.

        If ``Runner.run_sync`` is mocked out and never touches asyncio,
        ``get_event_loop`` just hands back a freshly created, empty loop —
        so there's simply nothing pending to drain. The ``RuntimeError``
        guard instead covers callers with no loop set on the current
        thread at all (e.g. a background thread, or a test that has
        explicitly called ``asyncio.set_event_loop(None)``)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                return
        drain_pending_tasks(loop)

    def run_streamed(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
<<<<<<< HEAD
        *,
=======
>>>>>>> 38ae2327044067c3956d3748d22806d5a9c9cb41
        hexgate_context: HexgateContext,
        run_config: RunConfig | None = None,
        hooks: RunHooks | None = None,
        **kwargs,
    ) -> RunResultStreaming:
        """Stream the OpenAI agent inside a HexgateContext scope.

        ``Runner.run_streamed`` returns sync but spawns the agent loop as a
        background task that snapshots the current contextvars at creation;
        tools fire there, not in ``stream_events``. So the HexgateContext scope must be
        active around the ``run_streamed`` call for the task to inherit it —
        the wrapped iterator re-opens it for exit/audit semantics.
        """
        self._setup_observability()
        binding = self._binding_for(agent)
        binding.refresh()  # must precede the wrap + setup
        ban_gate = self._ban_gate_for(agent)
        if ban_gate is not None:
            # Before run_streamed spawns its task, so a banned run yields nothing.
            ban_gate.check(hexgate_context)
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
        )

        with hexgate_context.sync_scope():
            with self._propagate(hexgate_context, agent.name):
                result = Runner.run_streamed(
                    wrapped_agent,
                    input,
                    run_config=run_config,
                    hooks=self._merge_hooks(hooks),
                    **kwargs,
                )

        original_stream_events = result.stream_events

        async def _stream_events_with_scope():
            async with hexgate_context:
                with self._propagate(hexgate_context, agent.name):
                    async for event in original_stream_events():
                        yield event

        result.stream_events = _stream_events_with_scope
        return result
