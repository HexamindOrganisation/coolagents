"""Version-compat probe for the pydantic_ai adapter.

Wrap seam: ``agent._function_toolset.tools`` (dict) + the per-tool
``Tool.function_schema.call`` callable, both private. See
``hexgate/adapters/pydantic_ai/``.
"""

from __future__ import annotations

import os

import pytest

from tests.version_compat import _probe
from tests.version_compat._probe import ALLOWED_TOOL, DENIED_TOOL, DENY_MARKER
from tests.version_compat.conftest import AGENT_NAMES

pytestmark = pytest.mark.version_compat

# Tier 2 talks to a real model; Tier 0/1 use pydantic_ai's TestModel so no
# provider key is needed at construction and the seam test stays offline.
MODEL = "openai:gpt-4o-mini"


def _build_wrapped(model=None):
    from pydantic_ai import Agent

    from hexgate.adapters.pydantic_ai import wrap_pydantic_agent

    if model is None:
        from pydantic_ai.models.test import TestModel

        model = TestModel()
    agent = Agent(model, name=AGENT_NAMES["pydantic"])

    @agent.tool_plain
    def get_weather(city: str) -> str:
        _probe.record_execution(ALLOWED_TOOL)
        return f"{city}: sunny, 21C"

    @agent.tool_plain
    def delete_user(user_id: str) -> str:
        _probe.record_execution(DENIED_TOOL)
        return f"deleted {user_id}"

    return wrap_pydantic_agent(agent=agent)


def test_contract():
    """Tier 0 — the private surfaces the adapter reaches into still exist."""
    from pydantic_ai import Agent, RunContext  # noqa: F401
    from pydantic_ai.exceptions import ModelRetry  # noqa: F401
    from pydantic_ai.models.test import TestModel
    from pydantic_ai.tools import Tool  # noqa: F401

    agent = Agent(TestModel(), name="contract")
    toolset = agent._function_toolset
    assert hasattr(toolset, "tools")


async def test_deny_path_blocks_and_does_not_execute(probe_user):
    """Tier 1 — the denied tool's guarded call raises before running."""
    from pydantic_ai.exceptions import ModelRetry

    wrapped = _build_wrapped()
    tool = wrapped._agent._function_toolset.tools[DENIED_TOOL]
    with probe_user.sync_scope():
        with pytest.raises(ModelRetry) as excinfo:
            # context is unused on the deny short-circuit
            await tool.function_schema.call({"user_id": "u1"}, None)
    assert DENY_MARKER in str(excinfo.value)
    assert not _probe.was_executed(DENIED_TOOL)


def test_allow_decision(probe_user):
    """Tier 1 — the resolved policy allows the allowed tool."""
    wrapped = _build_wrapped()
    with probe_user.sync_scope():
        decision = wrapped._binding.enforcer.decide(ALLOWED_TOOL, {"city": "Paris"})
    assert decision.allowed


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"), reason="Tier 2 e2e needs OPENAI_API_KEY"
)
async def test_e2e_allow_executes(probe_user):
    """Tier 2 — a full model run drives the seam and runs the allowed tool."""
    wrapped = _build_wrapped(model=MODEL)
    await wrapped.run("What is the weather in Tokyo?", user=probe_user)
    assert _probe.was_executed(ALLOWED_TOOL)
