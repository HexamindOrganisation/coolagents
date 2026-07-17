"""Version-compat probe for the langchain adapter.

Wrap seam: ``install_enforcer_on_tools`` mutates each StructuredTool's
``func``/``coroutine`` in place; non-allow renders the structured-error
dict. See ``hexgate/adapters/langchain/``.
"""

from __future__ import annotations

import os

import pytest

from tests.version_compat import _probe
from tests.version_compat._probe import ALLOWED_TOOL, DENIED_TOOL, DENY_MARKER
from tests.version_compat.conftest import AGENT_NAMES

pytestmark = pytest.mark.version_compat


def _build_tools():
    from langchain_core.tools import tool

    @tool
    def get_weather(city: str) -> str:
        """Return a weather report for a city."""
        _probe.record_execution(ALLOWED_TOOL)
        return f"{city}: sunny, 21C"

    @tool
    def delete_user(user_id: str) -> str:
        """Delete a user account."""
        _probe.record_execution(DENIED_TOOL)
        return f"deleted {user_id}"

    return [get_weather, delete_user]


def _model():
    from langchain_openai import ChatOpenAI

    # Real key when present (Tier 2 e2e); dummy for offline Tier 0/1 construction.
    key = os.environ.get("OPENAI_API_KEY", "sk-probe-dummy")
    return ChatOpenAI(model="gpt-4o-mini", api_key=key)


def _build_wrapped(tools):
    from langchain.agents import create_agent

    from hexgate.adapters.langchain import wrap_langchain_agent

    graph = create_agent(model=_model(), tools=tools, name=AGENT_NAMES["langchain"])
    # Mutates `tools` in place, installing the enforcer on each.
    return wrap_langchain_agent(agent=graph, tools=tools)


def test_contract():
    """Tier 0 — create_agent + StructuredTool.func + graph type still exist."""
    from langchain.agents import create_agent  # noqa: F401
    from langchain_core.tools import StructuredTool
    from langgraph.graph.state import CompiledStateGraph  # noqa: F401

    tool = _build_tools()[0]
    assert isinstance(tool, StructuredTool)
    assert hasattr(tool, "func")


def test_deny_path_blocks_and_does_not_execute(probe_user):
    """Tier 1 — the denied tool's guarded func returns the structured error."""
    tools = _build_tools()
    _build_wrapped(tools)  # installs enforcer on `tools` in place
    denied = next(t for t in tools if t.name == DENIED_TOOL)
    with probe_user.sync_scope():
        result = denied.func(user_id="u1")
    assert isinstance(result, dict) and result.get("ok") is False
    assert DENY_MARKER in str(result.get("error"))
    assert not _probe.was_executed(DENIED_TOOL)


def test_allow_decision(probe_user):
    """Tier 1 — the resolved policy allows the allowed tool."""
    tools = _build_tools()
    wrapped = _build_wrapped(tools)
    with probe_user.sync_scope():
        decision = wrapped._binding.enforcer.decide(ALLOWED_TOOL, {"city": "Paris"})
    assert decision.allowed


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"), reason="Tier 2 e2e needs OPENAI_API_KEY"
)
async def test_e2e_allow_executes(probe_user):
    """Tier 2 — a full graph run drives the seam and runs the allowed tool."""
    tools = _build_tools()
    wrapped = _build_wrapped(tools)
    await wrapped.ainvoke(
        {"messages": [{"role": "user", "content": "Weather in Tokyo?"}]},
        user=probe_user,
    )
    assert _probe.was_executed(ALLOWED_TOOL)
