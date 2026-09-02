"""``Runner`` wrapper: opens a :class:`HexgateContext` scope around each ``Runner.run*``
call so the wrapped tools' enforcers can resolve the active role.
Langfuse propagation mirrors the HexgateContext identity into trace metadata.

One policy binding is cached per agent name (first run resolves, later
runs are ETag/304 refreshes); the per-call rewrap closes over the cached
enforcer, so a refresh swap reaches every clone.
"""

import asyncio
from collections.abc import Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

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

from hexgate.adapters._common import langfuse_propagate_kwargs
from hexgate.adapters.openai.usage import HexgateUsageHooks
from hexgate.adapters.openai.wrapper import wrap_openai_agent
from hexgate.approvals import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.runtime import HexgateContext, run_scope, use_run_facts
from hexgate.security.agent_gate import (
    HandoffDepthExceededError,
    resolve_agent_gate,
    resolve_reach_gate,
    warn_if_tool_reach_unenforced,
)
from hexgate.security.bans import BanGate, resolve_ban_gate
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer
from hexgate.security.naming import canonical_agent_name

if TYPE_CHECKING:
    from hexgate.guards.types import Guard, GuardObserver


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


class _HexgateReachHooks(RunHooks):
    """Enforce agent-to-agent reach at the SDK handoff seam.

    ``on_handoff`` fires (awaited, via ``asyncio.gather``) after the target agent
    is resolved but before the handoff completes, so raising here vetoes the
    transfer and the target never runs. Reach is governed by the *source* agent's
    policy, so this looks up the source's cached binding and decides
    ``agent.handoff:<target>``. Only handoffs from a Hexgate-governed source (the
    resolved top-level agent) are gated; a handoff from an un-governed sub-agent is
    left alone here (sub-agent governance is a later slice). Agent-as-tool reach
    (``Agent.as_tool``) has no target handle at this seam and is not gated.
    """

    def __init__(self, runner: "HexgateRunner") -> None:
        self._runner = runner
        self._depth = 0  # per-run: this hook is rebuilt on every run

    async def on_handoff(self, context, from_agent, to_agent) -> None:
        # Depth cap first, as a runaway guard independent of reach policy: a
        # handoff transfers control forward, so the count of handoffs in this run
        # is the chain depth. Counts every handoff, governed source or not.
        self._depth += 1
        cap = self._runner._max_handoff_depth
        if cap is not None and self._depth > cap:
            raise HandoffDepthExceededError(self._depth, cap)
        binding = self._runner._bindings.get(canonical_agent_name(from_agent))
        if binding is None:
            return  # source is not Hexgate-governed; reach from it isn't gated here
        if not binding.enforcer.policy.declares_reach():
            return  # no 'agents' block — skip building a gate on the hot handoff path
        gate = resolve_reach_gate(
            binding.enforcer, approval_handler=self._runner._approval_handler
        )
        await gate.check_reach_async(canonical_agent_name(to_agent), via="handoff")


class HexgateRunner:
    """Runner for OpenAI agents with Hexgate tool policy and observability."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        approval_handler: ApprovalHandler | None = None,
        guards: "Sequence[Guard] | None" = None,
        guard_observer: "GuardObserver | None" = None,
        max_handoff_depth: int | None = None,
    ):
        # ``guards`` (not ``hooks``) on purpose: ``run*`` below already take a
        # ``hooks=`` that means the agents SDK's ``RunHooks`` (we mirror the SDK
        # Runner). Naming the guard list ``guards`` keeps the two from shadowing
        # each other; ``_merge_hooks`` rejects a guard list passed to ``run``.
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
        # Handoff-chain depth cap (None = no cap); enforced per run by the reach hook.
        self._max_handoff_depth = max_handoff_depth
        # Guards are fixed per runner; threaded into each per-call rewrap below,
        # where wrap_openai_agent builds the pipeline (matching the other adapters).
        self._guards = guards
        self._guard_observer = guard_observer

    def _binding_for(self, agent: Agent) -> PolicyBinding:
        """Get-or-resolve the cached policy binding for ``agent``'s name.

        First call resolves (loud-failure point) and rebuilds the
        enforcer with this runner's audit sender. Fail-loud: an
        unregistered agent (platform 404) raises — register it first with
        ``hexgate register``.
        """
        # Shared derivation (trim + blank/None → "default") so a null identity
        # never reaches the cache key or the platform resolve / enforcer / audit
        # below, and so it matches how a reach target would be named.
        name = canonical_agent_name(agent)
        binding = self._bindings.get(name)
        if binding is None:
            resolved = resolve_policy(name, api_key=self.api_key, client=self._client)
            enforcer = build_enforcer(
                resolved.engine, agent_name=name, api_key=self.api_key
            )
            # Handoff reach is enforced (on_handoff); agent-as-tool reach is not,
            # so warn if the policy declares a via: tool target.
            warn_if_tool_reach_unenforced(
                resolved.engine, framework="OpenAI Agents", agent_name=name
            )
            binding = PolicyBinding(enforcer, resolved.source)
            self._bindings[name] = binding
        return binding

    def _ban_gate_for(self, agent: Agent) -> BanGate | None:
        """Get-or-resolve the cached ban gate for ``agent``'s name (``None`` in
        local mode / no key). ``None`` is cached too, so we resolve once."""
        name = canonical_agent_name(agent)
        if name not in self._ban_gates:
            self._ban_gates[name] = resolve_ban_gate(
                name, api_key=self.api_key, client=self._client
            )
        return self._ban_gates[name]

    async def _check_admission_async(self, binding: PolicyBinding) -> None:
        """Refuse a caller not admitted by the top-level agent's policy, before the
        run starts. Must run inside the active HexgateContext scope (admission reads
        the caller's role from it). No-op when the policy declares no admission."""
        gate = resolve_agent_gate(
            binding.enforcer, approval_handler=self._approval_handler
        )
        await gate.check_admission_async()

    def _check_admission_sync(self, binding: PolicyBinding) -> None:
        """Sync mirror of :meth:`_check_admission_async`."""
        gate = resolve_agent_gate(
            binding.enforcer, approval_handler=self._approval_handler
        )
        gate.check_admission()

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
        """Compose the caller's ``hooks`` with Hexgate's own — never clobber a
        hooks object the caller already passed.

        Always installs the usage hook and the reach hook (which enforces
        ``agent.handoff:*`` at the SDK handoff seam), so the result is always a
        composite fanning out to every hook in turn.
        """
        installed: list[RunHooksBase] = [
            HexgateUsageHooks(api_key=self.api_key),
            _HexgateReachHooks(self),
        ]
        if hooks is not None:
            if not isinstance(hooks, RunHooksBase):
                # A Hexgate guard list passed to run(hooks=...) instead of the
                # constructor would otherwise crash at the first lifecycle callback,
                # far from the mistake. Name it here.
                raise TypeError(
                    f"run(hooks=...) takes an agents RunHooks object, got "
                    f"{type(hooks).__name__}. Hexgate guards go on the constructor: "
                    "HexgateRunner(guards=[...])."
                )
            installed.insert(0, hooks)
        return _CompositeRunHooks(installed)

    async def run(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        *,
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
            guards=self._guards,
            guard_observer=self._guard_observer,
        )
        async with hexgate_context:
            await self._check_admission_async(binding)  # in-scope: reads the role
            with run_scope(agent.name), self._propagate(hexgate_context, agent.name):
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
        *,
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
            guards=self._guards,
            guard_observer=self._guard_observer,
        )
        with hexgate_context.sync_scope():
            self._check_admission_sync(binding)  # in-scope: reads the role
            with run_scope(agent.name), self._propagate(hexgate_context, agent.name):
                return Runner.run_sync(
                    wrapped_agent,
                    input,
                    run_config=run_config,
                    hooks=self._merge_hooks(hooks),
                    **kwargs,
                )

    def run_streamed(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        *,
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

        Admission is checked synchronously before the task spawns (so a refused run
        yields nothing). Like any sync entrypoint, an *async* ``approval_handler``
        cannot be awaited here and fails closed on a NEEDS_APPROVAL admission
        verdict; use the async ``run`` entrypoint if admission approval is async.
        """
        self._setup_observability()
        binding = self._binding_for(agent)
        binding.refresh()  # must precede the wrap + setup
        ban_gate = self._ban_gate_for(agent)
        if ban_gate is not None:
            # Before run_streamed spawns its task, so a banned run yields nothing.
            ban_gate.check(hexgate_context)
        return self._launch_streamed(
            agent,
            input,
            binding=binding,
            hexgate_context=hexgate_context,
            run_config=run_config,
            hooks=hooks,
            kwargs=kwargs,
        )

    async def arun_streamed(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        *,
        hexgate_context: HexgateContext,
        run_config: RunConfig | None = None,
        hooks: RunHooks | None = None,
        **kwargs,
    ) -> RunResultStreaming:
        """Async-friendly ``run_streamed`` for callers already on an event loop.

        ``run_streamed`` refreshes the policy binding and ban gate with blocking
        sync HTTP; on an asyncio loop that freezes the loop thread (which, under
        ``hexgate serve``, would stall the approval-reply and ping/pong frames
        the per-frame dispatch depends on). This awaits the async variants
        first, then launches ``Runner.run_streamed`` on-loop. It stays on-loop
        rather than ``to_thread`` because ``run_streamed`` returns immediately
        and spawns the agent loop as an ``asyncio.create_task`` that must inherit
        both this running loop and the active contextvar scope.
        """
        self._setup_observability()
        binding = self._binding_for(agent)
        await binding.refresh_async()  # per-run policy pull; 304 when unchanged
        ban_gate = self._ban_gate_for(agent)
        if ban_gate is not None:
            await ban_gate.check_async(hexgate_context)
        return self._launch_streamed(
            agent,
            input,
            binding=binding,
            hexgate_context=hexgate_context,
            run_config=run_config,
            hooks=hooks,
            kwargs=kwargs,
        )

    def _launch_streamed(
        self,
        agent: Agent,
        input: str | list[TResponseInputItem] | RunState[TContext],
        *,
        binding: PolicyBinding,
        hexgate_context: HexgateContext,
        run_config: RunConfig | None,
        hooks: RunHooks | None,
        kwargs: dict[str, Any],
    ) -> RunResultStreaming:
        """Wrap the agent, launch ``Runner.run_streamed`` inside the context
        scope, and re-wrap ``stream_events`` to re-enter it. Shared by the sync
        ``run_streamed`` and async ``arun_streamed`` after each has refreshed the
        binding + ban gate in its own way.

        ``run_streamed`` returns sync but spawns the agent loop as a background
        task that snapshots the current contextvars at creation; tools fire
        there, not in ``stream_events``. So the scope must be active around the
        ``run_streamed`` call for the task to inherit it; the wrapped iterator
        re-opens it for exit/audit semantics.
        """
        wrapped_agent = wrap_openai_agent(
            agent,
            enforcer=binding.enforcer,
            approval_handler=self._approval_handler,
            guards=self._guards,
            guard_observer=self._guard_observer,
        )

        with hexgate_context.sync_scope():
            # Before run_streamed spawns its task, so a non-admitted run yields nothing.
            self._check_admission_sync(binding)
            # Scope must be open around run_streamed(): it snapshots the
            # contextvars into the background task where tools fire, and that
            # snapshot keeps the facts alive after this block exits.
            with run_scope(agent.name) as run_facts:
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
                # Re-bind the snapshotted facts, not a second run: one
                # invocation must have one run id.
                with use_run_facts(run_facts):
                    with self._propagate(hexgate_context, agent.name):
                        async for event in original_stream_events():
                            yield event

        result.stream_events = _stream_events_with_scope
        return result
