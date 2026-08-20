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
from google.adk.runners import Runner
from google.adk.sessions import BaseSessionService
from google.genai import types
from langfuse import get_client, propagate_attributes
from openinference.instrumentation.google_adk import GoogleADKInstrumentor

from hexgate.adapters._common import drain_pending_tasks, langfuse_propagate_kwargs
from hexgate.adapters.google.usage import HexgateUsagePlugin
from hexgate.adapters.google.wrapper import wrap_google_agent
from hexgate.approvals import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.runtime import HexgateContext, run_scope
from hexgate.security.bans import resolve_ban_gate

if TYPE_CHECKING:
    from hexgate.guards.types import Guard, GuardObserver


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
        app = App(name=app_name, root_agent=self._wrapped_agent, plugins=plugins)
        self._runner = Runner(
            app=app,
            session_service=session_service,
            **runner_kwargs,
        )
        self._agent_name = getattr(agent, "name", "default")
        self._ban_gate = resolve_ban_gate(
            self._agent_name, api_key=self.api_key, client=client
        )

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
                # The last turn's fire-and-forget audit-send task (policy
                # decision / LLM usage) may still be in flight — there's no
                # further turn left to keep this loop spinning in the
                # background while it completes. Give it one last chance
                # before tearing the loop down, or its event is silently
                # dropped.
                drain_pending_tasks(loop)
                loop.close()

    async def run_async(
        self,
        *,
        new_message: types.Content | None = None,
        hexgate_context: HexgateContext,
        **kwargs: Any,
    ) -> AsyncGenerator[Any, None]:
        """Run the Google ADK agent asynchronously, yielding events."""
        self._setup_observability()
        await self._binding.refresh_async()  # per-run policy pull; 304 when unchanged
        if self._ban_gate is not None:
            await self._ban_gate.check_async(hexgate_context)
        async with hexgate_context:
            with run_scope(self._agent_name), self._propagate(hexgate_context):
                async for event in self._runner.run_async(
                    user_id=hexgate_context.user_id,
                    session_id=hexgate_context.session_id,
                    new_message=new_message,
                    **kwargs,
                ):
                    yield event
