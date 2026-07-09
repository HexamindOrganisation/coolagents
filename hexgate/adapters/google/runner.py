"""Google ADK ``Runner`` wrapper: opens a :class:`User` scope around each
``Runner.run*`` call so the wrapped tools' enforcers can resolve the
active role. Langfuse propagation mirrors User identity into spans.
"""

import asyncio
from contextlib import contextmanager
from typing import Any, AsyncGenerator, Generator

import nest_asyncio
from google.adk.agents import BaseAgent
from google.adk.runners import Runner
from google.adk.sessions import BaseSessionService
from google.genai import types
from langfuse import get_client, propagate_attributes
from openinference.instrumentation.google_adk import GoogleADKInstrumentor

from hexgate.adapters.google.wrapper import wrap_google_agent
from hexgate.agents.factory import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.runtime import User
from hexgate.security.bans import resolve_ban_gate


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
        **runner_kwargs: Any,
    ):
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
        )
        self._runner = Runner(
            agent=self._wrapped_agent,
            app_name=app_name,
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
    def _propagate(self, user: User):
        """Propagate User identity into Langfuse spans for the block."""
        kwargs: dict[str, Any] = {"tags": [f"google.runner.run.{self._agent_name}"]}
        kwargs["user_id"] = user.user_id
        kwargs["session_id"] = user.session_id
        kwargs["metadata"] = {"user_role": user.role}
        with propagate_attributes(**kwargs):
            yield

    def run(
        self,
        *,
        new_message: types.Content,
        user: User,
        **kwargs: Any,
    ) -> Generator[Any, None, None]:
        """Run the Google ADK agent synchronously, yielding events.

        ADK's ``Runner.run`` drives the agent loop in a worker thread whose
        context cannot see our :class:`User` scope, so the tools' enforcers
        lose the active role. We drive ``run_async`` inline on a per-call loop
        instead, keeping execution in this scoped thread.
        """
        self._setup_observability()
        self._binding.refresh()  # per-run policy pull; 304 when unchanged
        if self._ban_gate is not None:
            self._ban_gate.check(user)
        with user.sync_scope(), self._propagate(user):
            agen = self._runner.run_async(
                user_id=user.user_id,
                session_id=user.session_id,
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
        user: User,
        **kwargs: Any,
    ) -> AsyncGenerator[Any, None]:
        """Run the Google ADK agent asynchronously, yielding events."""
        self._setup_observability()
        await self._binding.refresh_async()  # per-run policy pull; 304 when unchanged
        if self._ban_gate is not None:
            await self._ban_gate.check_async(user)
        async with user:
            with self._propagate(user):
                async for event in self._runner.run_async(
                    user_id=user.user_id,
                    session_id=user.session_id,
                    new_message=new_message,
                    **kwargs,
                ):
                    yield event
