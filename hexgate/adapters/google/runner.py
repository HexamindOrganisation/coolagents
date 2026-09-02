"""Google ADK ``Runner`` wrapper: opens a :class:`HexgateContext` scope around each
``Runner.run*`` call so the wrapped tools' enforcers can resolve the
active role. Langfuse propagation mirrors HexgateContext identity into spans.
"""

import asyncio
from collections.abc import Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, AsyncGenerator, Generator

import nest_asyncio
from google.adk.agents import BaseAgent
from google.adk.apps import App
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import Runner
from google.adk.sessions import BaseSessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types
from langfuse import get_client, propagate_attributes
from openinference.instrumentation.google_adk import GoogleADKInstrumentor

from hexgate.adapters._common import langfuse_propagate_kwargs
from hexgate.adapters.google.usage import HexgateUsagePlugin
from hexgate.adapters.google.wrapper import wrap_google_agent
from hexgate.approvals import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.runtime import HexgateContext, run_scope
from hexgate.security.agent_gate import (
    HandoffDepthExceededError,
    resolve_agent_gate,
    resolve_reach_gate,
)
from hexgate.security.bans import resolve_ban_gate
from hexgate.security.naming import canonical_agent_name, canonical_name

if TYPE_CHECKING:
    from hexgate.guards.types import Guard, GuardObserver


class _HexgateReachPlugin(BasePlugin):
    """Enforce agent-to-agent reach at the ADK tool seam.

    ADK expresses delegation as tool calls: ``transfer_to_agent(agent_name=...)``
    (handoff, control transfers) and :class:`AgentTool` (agent-as-tool, the caller
    keeps control). ``before_tool_callback`` fires before either runs, so deciding
    the target's reach key here and raising :class:`ReachNotAllowedError` on a deny
    stops the transfer/delegation before it happens. Reach is governed by the
    source agent's policy; only the governed root's reach is gated (a transfer
    originating from an un-governed sub-agent is left alone, matching the OpenAI
    adapter). Ordinary tools fall through — they are already gated by the wrapped
    enforcer.
    """

    def __init__(self, runner: "HexgateRunner") -> None:
        super().__init__(name="hexgate_reach")
        self._runner = runner
        # Handoff depth per invocation (this plugin is shared across runs, unlike
        # the OpenAI per-run hook), cleared in after_run_callback.
        self._depth: dict[str, int] = {}

    async def before_tool_callback(self, *, tool, tool_args, tool_context) -> None:
        # A raise here aborts the run, so after_run_callback never fires; drop this
        # invocation's depth entry on the way out to keep the shared map from
        # leaking one entry per aborted (over-depth or reach-denied) run.
        try:
            return await self._gate_tool(tool, tool_args, tool_context)
        except Exception:
            self._depth.pop(tool_context.invocation_id, None)
            raise

    async def _gate_tool(self, tool, tool_args, tool_context) -> None:
        is_transfer = tool.name == "transfer_to_agent"
        # Depth cap first, as a runaway guard independent of reach policy and of
        # which agent transfers: a transfer moves control forward, so the count of
        # transfers in one invocation is the chain depth.
        cap = self._runner._max_handoff_depth
        if is_transfer and cap is not None:
            inv = tool_context.invocation_id
            self._depth[inv] = self._depth.get(inv, 0) + 1
            if self._depth[inv] > cap:
                raise HandoffDepthExceededError(self._depth[inv], cap)
        if canonical_name(tool_context.agent_name) != self._runner._agent_name:
            return None  # source is not the governed root; reach from it isn't gated
        if is_transfer:
            target, via = tool_args.get("agent_name"), "handoff"
        elif isinstance(tool, AgentTool):
            target, via = getattr(tool.agent, "name", None), "tool"
        else:
            return None  # ordinary tool; the wrapped enforcer already gates it
        if not target:
            return None
        if not self._runner._binding.enforcer.policy.declares_reach():
            return None  # no 'agents' block — skip building a gate on the hot seam
        gate = resolve_reach_gate(
            self._runner._binding.enforcer,
            approval_handler=self._runner._approval_handler,
        )
        await gate.check_reach_async(canonical_name(target), via=via)
        return None

    async def after_run_callback(self, *, invocation_context) -> None:
        # Drop this invocation's depth counter so the map does not grow unbounded.
        self._depth.pop(invocation_context.invocation_id, None)
        return None


class HexgateRunner:
    """Runner for Google ADK agents with Hexgate tool policy and observability."""

    def __init__(
        self,
        *,
        agent: BaseAgent,
        app_name: str,
        session_service: BaseSessionService,
        api_key: str | None = None,
        approval_handler: ApprovalHandler | None = None,
        guards: "Sequence[Guard] | None" = None,
        guard_observer: "GuardObserver | None" = None,
        max_handoff_depth: int | None = None,
        **runner_kwargs: Any,
    ):
        # ``guards`` matches the OpenAI runner's constructor. ADK's ``run`` has
        # no ``hooks=`` to collide with (it takes ``**runner_kwargs``), so the
        # name is for cross-runner symmetry, not disambiguation.
        self.api_key = resolve_api_key(api_key)
        if self.api_key is None:
            raise ValueError(
                "HEXGATE_API_KEY is not set. Pass api_key= explicitly or set the HEXGATE_API_KEY environment variable."
            )
        # Policy resolves at construction (the loud-failure point); the
        # Runner is built once — refresh swaps the enforcer's policy
        # without touching it. One client is shared with the ban resolver.
        self._approval_handler = approval_handler
        # Handoff-chain depth cap (None = no cap); enforced per invocation by the
        # reach plugin.
        self._max_handoff_depth = max_handoff_depth
        client = HexgateClient(HexgateConfig.from_env(api_key=self.api_key))
        self._wrapped_agent, self._binding = wrap_google_agent(
            agent,
            api_key=self.api_key,
            approval_handler=approval_handler,
            client=client,
            guards=guards,
            guard_observer=guard_observer,
        )
        plugins = list(runner_kwargs.pop("plugins", None) or [])
        plugins.append(HexgateUsagePlugin(api_key=self.api_key))
        # Reach enforcement at the ADK transfer/AgentTool seam. Appended after the
        # caller's plugins so it always runs; it never rewrites tool input.
        plugins.append(_HexgateReachPlugin(self))
        app = App(name=app_name, root_agent=self._wrapped_agent, plugins=plugins)
        self._runner = Runner(
            app=app,
            session_service=session_service,
            **runner_kwargs,
        )
        self._agent_name = canonical_agent_name(agent)
        self._ban_gate = resolve_ban_gate(
            self._agent_name, api_key=self.api_key, client=client
        )

    async def _check_admission_async(self) -> None:
        """Refuse a caller not admitted by the root agent's policy before the run
        drives. Must run inside the active HexgateContext scope. No-op when the
        policy declares no admission."""
        gate = resolve_agent_gate(
            self._binding.enforcer, approval_handler=self._approval_handler
        )
        await gate.check_admission_async()

    def _check_admission_sync(self) -> None:
        """Sync mirror of :meth:`_check_admission_async`."""
        gate = resolve_agent_gate(
            self._binding.enforcer, approval_handler=self._approval_handler
        )
        gate.check_admission()

    def _setup_observability(self):
        """Install Langfuse + GoogleADKInstrumentor (idempotent)."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No running loop: safe to patch (and only useful for sync entry points).
            # Patching a live loop breaks asyncio.current_task() on Python 3.12+.
            nest_asyncio.apply()
        get_client()
        GoogleADKInstrumentor().instrument()

    @contextmanager
    def _propagate(self, context: HexgateContext):
        """Propagate HexgateContext identity into Langfuse spans for the block."""
        with propagate_attributes(
            **langfuse_propagate_kwargs(
                context, f"google.runner.run.{self._agent_name}"
            )
        ):
            yield

    def run(
        self,
        *,
        new_message: types.Content,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> Generator[Any, None, None]:
        """Run the Google ADK agent synchronously, yielding events.

        ADK's ``Runner.run`` drives the agent loop in a worker thread whose
        context cannot see our :class:`HexgateContext` scope, so the tools' enforcers
        lose the active role. We drive ``run_async`` inline on a per-call loop
        instead, keeping execution in this scoped thread.
        """
        self._setup_observability()
        self._binding.refresh()  # per-run policy pull; 304 when unchanged
        if self._ban_gate is not None:
            self._ban_gate.check(hexgate_context)
        with (
            hexgate_context.sync_scope(),
            run_scope(self._agent_name),
            self._propagate(hexgate_context),
        ):
            self._check_admission_sync()  # in-scope: reads the caller's role
            agen = self._runner.run_async(
                user_id=hexgate_context.user_id,
                session_id=hexgate_context.session_id,
                new_message=new_message,
                **kwargs,
            )
            loop = asyncio.new_event_loop()
            try:
                while True:
                    try:
                        yield loop.run_until_complete(agen.__anext__())
                    except StopAsyncIteration:
                        break
            finally:
                loop.run_until_complete(agen.aclose())
                loop.close()

    async def run_async(
        self,
        *,
        new_message: types.Content | None = None,
        hexgate_context: HexgateContext,
        session_id: str | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[Any, None]:
        """Run the Google ADK agent asynchronously, yielding events.

        ``session_id`` overrides the ADK session used for the run; it defaults to
        ``hexgate_context.session_id``. Pass it explicitly to decouple the ADK
        conversation store from the caller-facing session id that lands in audit
        (``hexgate serve`` does this so audit stays correlatable while ADK memory
        is managed separately).
        """
        self._setup_observability()
        await self._binding.refresh_async()  # per-run policy pull; 304 when unchanged
        if self._ban_gate is not None:
            await self._ban_gate.check_async(hexgate_context)
        adk_session_id = (
            session_id if session_id is not None else hexgate_context.session_id
        )
        async with hexgate_context:
            await self._check_admission_async()  # in-scope: reads the caller's role
            with run_scope(self._agent_name), self._propagate(hexgate_context):
                async for event in self._runner.run_async(
                    user_id=hexgate_context.user_id,
                    session_id=adk_session_id,
                    new_message=new_message,
                    **kwargs,
                ):
                    yield event
