"""Version-compat probe for deepagents.

deepagents has no adapter of its own: ``create_deep_agent`` returns a
``CompiledStateGraph`` that is wrapped through the **langchain** adapter
(``wrap_langchain_agent``). The interesting axis is the langchain /
langgraph versions deepagents pulls in transitively.
"""

from __future__ import annotations

import os

import pytest

from tests.framework_compat import _probe
from tests.framework_compat._probe import ALLOWED_TOOL, DENIED_TOOL, DENY_MARKER
from tests.framework_compat.conftest import AGENT_NAMES

INSTRUCTIONS = "You are a helpful assistant. Use the available tools."

# deepagents has no adapter of its own and rides the installed langchain. If
# that pairing is incompatible (e.g. deepagents importing a symbol a newer
# langchain moved), it fails at import — a genuine matrix result, so skip the
# whole module with the captured reason rather than erroring as a scaffold bug.
try:
    from deepagents import create_deep_agent as _create_deep_agent

    _IMPORT_ERROR: Exception | None = None
except Exception as exc:  # noqa: BLE001 — surface any import-time incompatibility
    _create_deep_agent = None
    _IMPORT_ERROR = exc

pytestmark = [
    pytest.mark.framework_compat,
    pytest.mark.skipif(
        _IMPORT_ERROR is not None,
        reason=f"deepagents incompatible with installed langchain: {_IMPORT_ERROR!r}",
    ),
]


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
    from hexgate.adapters.langchain import wrap_langchain_agent

    graph = _create_deep_agent(model=_model(), tools=tools, system_prompt=INSTRUCTIONS)
    # deepagents may leave graph.name unset; resolve_policy needs a non-empty
    # lookup key, so name it explicitly before wrapping.
    if not getattr(graph, "name", None):
        graph.name = AGENT_NAMES["deepagents"]
    return wrap_langchain_agent(agent=graph, tools=tools)


def test_contract():
    """Tier 0 — create_deep_agent returns a langchain-adapter-shaped graph."""
    from langgraph.graph.state import CompiledStateGraph

    tools = _build_tools()
    graph = _create_deep_agent(model=_model(), tools=tools, system_prompt=INSTRUCTIONS)
    assert isinstance(graph, CompiledStateGraph)


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
    """Tier 2 — a full deep-agent run drives the seam and runs the allowed tool."""
    tools = _build_tools()
    wrapped = _build_wrapped(tools)
    await wrapped.ainvoke(
        {"messages": [{"role": "user", "content": "Weather in Tokyo?"}]},
        user=probe_user,
    )
    assert _probe.was_executed(ALLOWED_TOOL)
