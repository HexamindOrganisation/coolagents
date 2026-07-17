"""Version-compat probe for the google-adk adapter.

Wrap seam: ``BaseTool.run_async(*, args, tool_context)`` (patched) and
``agent.model_copy(update={"tools": ...})`` — the ``Agent`` must stay a
pydantic model. See ``hexgate/adapters/google/``.
"""

from __future__ import annotations

import os

import pytest

from tests.version_compat import _probe
from tests.version_compat._probe import ALLOWED_TOOL, DENIED_TOOL, DENY_MARKER
from tests.version_compat.conftest import AGENT_NAMES

pytestmark = pytest.mark.version_compat

# All probes run on OpenAI + OPENAI_API_KEY so the matrix needs a single
# provider key. Google ADK is model-native to Gemini, so it reaches OpenAI
# through its LiteLLM wrapper. Construction is keyless (Tier 0/1 stays
# offline); only the Tier 2 run touches OPENAI_API_KEY.
MODEL = "openai/gpt-4o-mini"


def get_weather(city: str) -> str:
    _probe.record_execution(ALLOWED_TOOL)
    return f"{city}: sunny, 21C"


def delete_user(user_id: str) -> str:
    _probe.record_execution(DENIED_TOOL)
    return f"deleted {user_id}"


def _build_agent():
    from google.adk.agents import Agent
    from google.adk.models.lite_llm import LiteLlm

    return Agent(
        name=AGENT_NAMES["google"],
        model=LiteLlm(model=MODEL),
        tools=[get_weather, delete_user],
    )


def _build_wrapped():
    from hexgate.adapters.google.wrapper import wrap_google_agent

    return wrap_google_agent(_build_agent(), api_key="local-probe-key")


def test_contract():
    """Tier 0 — the ADK types + run_async surface the adapter needs exist."""
    from google.adk.agents import BaseAgent  # noqa: F401
    from google.adk.apps import App  # noqa: F401
    from google.adk.runners import Runner  # noqa: F401
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.function_tool import FunctionTool  # noqa: F401
    from google.adk.tools.tool_context import ToolContext  # noqa: F401

    assert hasattr(BaseTool, "run_async")


async def test_deny_path_blocks_and_does_not_execute(probe_user):
    """Tier 1 — the denied tool's run_async returns the deny marker."""
    wrapped, _binding = _build_wrapped()
    tool = next(t for t in wrapped.tools if t.name == DENIED_TOOL)
    with probe_user.sync_scope():
        # tool_context is unused on the deny short-circuit
        result = await tool.run_async(args={"user_id": "u1"}, tool_context=None)
    assert DENY_MARKER in str(result)
    assert not _probe.was_executed(DENIED_TOOL)


def test_allow_decision(probe_user):
    """Tier 1 — the resolved policy allows the allowed tool."""
    _wrapped, binding = _build_wrapped()
    with probe_user.sync_scope():
        decision = binding.enforcer.decide(ALLOWED_TOOL, {"city": "Paris"})
    assert decision.allowed


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="Tier 2 e2e needs OPENAI_API_KEY (LiteLLM → OpenAI)",
)
async def test_e2e_allow_executes(probe_user):
    """Tier 2 — a full runner drives the seam and runs the allowed tool."""
    from google.adk.sessions import InMemorySessionService
    from google.genai import types

    from hexgate.adapters.google import HexgateRunner

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="version_probe",
        user_id=probe_user.user_id,
        session_id=probe_user.session_id,
    )
    runner = HexgateRunner(
        agent=_build_agent(),
        app_name="version_probe",
        session_service=session_service,
        api_key="local-probe-key",
    )
    message = types.Content(role="user", parts=[types.Part(text="Weather in Tokyo?")])
    async for _event in runner.run_async(new_message=message, user=probe_user):
        pass
    assert _probe.was_executed(ALLOWED_TOOL)
