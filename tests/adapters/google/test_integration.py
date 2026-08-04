"""End-to-end verification that a real (wrapped) google-adk agent, run
through :class:`HexgateRunner`, actually talks to the live platform for its
policy and lands both a tool-call decision and an LLM-usage event in
ClickHouse — the two audit paths ``PolicyEnforcer.decide()`` and
``HexgateUsagePlugin.after_model_callback`` feed. This is plumbing, not
model-quality: the "LLM" is a two-turn scripted fake (see ``_ScriptedLlm``
below) so the run is free and deterministic.

Requires: `make clickhouse-up` and `make platform-api` running, and
`HEXGATE_API_KEY` set to a token minted via the dashboard (or the
platform API directly).

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import uuid
from typing import Any, AsyncGenerator

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.sessions import InMemorySessionService
from google.adk.tools.function_tool import FunctionTool
from google.genai import types
from pydantic import PrivateAttr

from hexgate.adapters.google.runner import HexgateRunner
from hexgate.cli.register.register import register_agent
from hexgate.runtime import User
from tests.adapters.conftest import HexgatePlatformEnv
from tests.adapters.helpers import (
    AGENT_NAME_PREFIX,
    USER_ID_PREFIX,
    assert_policy_and_usage_events_landed,
)

pytestmark = pytest.mark.integration


def get_weather(city: str) -> str:
    """Return a canned weather report for a city."""
    return f"It is sunny in {city}."


class _ScriptedLlm(BaseLlm):
    """A deterministic, two-turn fake model — no network call, no API key.

    google-adk 1.32.0 ships no public equivalent to pydantic_ai's
    ``TestModel`` (the closest thing found, ``_ConformanceTestGemini`` in
    ``google.adk.cli.conformance``, is a private, Gemini-subclassing replay
    shim built for the ADK CLI's own conformance-test tooling, not a general
    unit-test double). ``BaseLlm`` is a small abstract interface
    (``generate_content_async`` only), so this hand-rolled subclass is the
    minimal way to drive a real wrapped agent for free: turn 1 always emits
    a ``get_weather`` function call (forcing a real policy decision through
    the enforcer), turn 2 emits plain text so the ADK flow's
    ``Event.is_final_response()`` check ends the run.
    """

    _call_count: int = PrivateAttr(default=0)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self._call_count += 1
        usage = types.GenerateContentResponseUsageMetadata(
            prompt_token_count=5, candidates_token_count=5
        )
        if self._call_count == 1:
            content = types.Content(
                role="model",
                parts=[
                    types.Part.from_function_call(
                        name="get_weather", args={"city": "Paris"}
                    )
                ],
            )
        else:
            content = types.Content(
                role="model", parts=[types.Part(text="It is sunny in Paris.")]
            )
        yield LlmResponse(
            model_version=self.model, content=content, usage_metadata=usage
        )


def test_wrapped_run_pulls_policy_and_lands_decision_and_usage_events(
    hexgate_platform_env: HexgatePlatformEnv,
) -> None:
    """One wrapped-agent run against the live platform, checked from both
    ends: the policy that gated ``get_weather`` came from the platform (not
    an allow-all default), and both audit paths (decision + usage) actually
    reached ClickHouse.

    ``get_weather`` is deliberately read-shaped: the platform's starter
    policy classifies tool names by substring heuristic
    (``platform/api/hexgate_api/features/agents/compiler.py::_classify_tool``)
    and only read-shaped tools get an explicit ``allow`` for the fallback
    ``default`` role — every other tool bucket denies by default. That makes
    the expected outcome deterministic: 'allow', not 'either'.
    """
    agent_name = f"{AGENT_NAME_PREFIX}google_{uuid.uuid4().hex[:8]}"
    session_id = f"s-{uuid.uuid4().hex[:8]}"

    raw_agent = LlmAgent(
        name=agent_name,
        model=_ScriptedLlm(model="hexgate-scripted-fake"),
        tools=[FunctionTool(func=get_weather)],
    )
    register_agent(raw_agent)

    runner = HexgateRunner(
        agent=raw_agent,
        app_name=agent_name,
        session_service=InMemorySessionService(),
        api_key=hexgate_platform_env.api_key,
        auto_create_session=True,
    )
    user = User(user_id=f"{USER_ID_PREFIX}google", session_id=session_id, role="tester")
    new_message = types.Content(
        role="user", parts=[types.Part(text="What's the weather in Paris?")]
    )

    events: list[Any] = list(runner.run(new_message=new_message, user=user))
    assert events  # the scripted model produced at least the final turn

    # Both sends are fire-and-forget (background thread / task) — poll
    # rather than assume they've landed the instant run() returns.
    assert_policy_and_usage_events_landed(
        hexgate_platform_env, agent_name, session_id, "get_weather"
    )
