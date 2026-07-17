"""Version-compat probe for the openai-agents adapter.

Wrap seam: ``FunctionTool.on_invoke_tool`` (patched) and
``dataclasses.replace(agent, tools=...)`` — the ``Agent`` must stay a
dataclass. See ``hexgate/adapters/openai/``.
"""

from __future__ import annotations

import os

import pytest

from tests.version_compat import _probe
from tests.version_compat._probe import ALLOWED_TOOL, DENIED_TOOL, DENY_MARKER
from tests.version_compat.conftest import AGENT_NAMES

pytestmark = pytest.mark.version_compat


def _build_agent():
    from agents import Agent, function_tool

    @function_tool
    def get_weather(city: str) -> str:
        _probe.record_execution(ALLOWED_TOOL)
        return f"{city}: sunny, 21C"

    @function_tool
    def delete_user(user_id: str) -> str:
        _probe.record_execution(DENIED_TOOL)
        return f"deleted {user_id}"

    return Agent(
        name=AGENT_NAMES["openai"],
        instructions="Use the tools when asked.",
        tools=[get_weather, delete_user],
        model="gpt-4o-mini",
    )


def _build_wrapped():
    from hexgate.adapters.openai.wrapper import wrap_openai_agent
    from hexgate.security.binding import resolve_policy
    from hexgate.security.enforcer import build_enforcer

    agent = _build_agent()
    resolved = resolve_policy(agent.name)
    enforcer = build_enforcer(resolved.engine, agent_name=agent.name)
    return wrap_openai_agent(agent, enforcer=enforcer), enforcer


def test_contract():
    """Tier 0 — Agent is still a dataclass and tools expose on_invoke_tool."""
    import dataclasses

    from agents import Agent, FunctionTool  # noqa: F401

    assert dataclasses.is_dataclass(Agent)
    tool = _build_agent().tools[0]
    assert hasattr(tool, "on_invoke_tool")


async def test_deny_path_blocks_and_does_not_execute(probe_user):
    """Tier 1 — the denied tool's on_invoke_tool returns the deny marker."""
    wrapped, _ = _build_wrapped()
    tool = next(t for t in wrapped.tools if t.name == DENIED_TOOL)
    with probe_user.sync_scope():
        # ToolContext is unused on the deny short-circuit
        result = await tool.on_invoke_tool(None, '{"user_id": "u1"}')
    assert DENY_MARKER in str(result)
    assert not _probe.was_executed(DENIED_TOOL)


def test_allow_decision(probe_user):
    """Tier 1 — the resolved policy allows the allowed tool."""
    _, enforcer = _build_wrapped()
    with probe_user.sync_scope():
        decision = enforcer.decide(ALLOWED_TOOL, {"city": "Paris"})
    assert decision.allowed


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"), reason="Tier 2 e2e needs OPENAI_API_KEY"
)
async def test_e2e_allow_executes(probe_user):
    """Tier 2 — a full runner drives the seam and runs the allowed tool."""
    from hexgate.adapters.openai import HexgateRunner

    runner = HexgateRunner()
    await runner.run(
        agent=_build_agent(), input="What is the weather in Tokyo?", user=probe_user
    )
    assert _probe.was_executed(ALLOWED_TOOL)
