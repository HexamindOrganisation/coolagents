"""`HexgateAgent.enforce_policy(hooks=...)` wiring, including the guards-only
path where no policy engine is passed.

The LangChain graph build is stubbed (as tests/agents/test_factory.py does) so
these assert the tool-wrapping, not a real graph.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import tool

from hexgate.adapters.langchain.tools import GuardedTool
from hexgate.agents import factory
from hexgate.agents.factory import HexgateAgent
from hexgate.hooks import before_tool
from hexgate.hooks.types import Halt


@tool
def echo(text: str) -> str:
    """Echo the input back."""
    return text


def _agent(monkeypatch: pytest.MonkeyPatch) -> HexgateAgent:
    monkeypatch.setattr(factory, "create_langchain_agent", lambda **k: "graph")
    return HexgateAgent(
        graph="graph", model="m", tools=[echo], system_prompt=None, name="bot"
    )


def _hooks() -> list:
    return [before_tool(lambda call: Halt(reason="blocked"))]


def test_enforce_policy_none_with_hooks_wraps_tools_guards_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """policy=None + hooks still guards each tool via guards (no enforcer)."""
    agent = _agent(monkeypatch)

    guarded = agent.enforce_policy(None, hooks=_hooks())

    wrapped = guarded.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.enforcer is None
    assert wrapped.pipeline is not None
    assert len(wrapped.pipeline.pre) == 1


def test_enforce_policy_none_without_hooks_stays_unguarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _agent(monkeypatch)
    rebuilt = agent.enforce_policy(None)
    assert not isinstance(rebuilt.tools[0], GuardedTool)


def test_enforce_policy_none_empty_hooks_stays_unguarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _agent(monkeypatch)
    rebuilt = agent.enforce_policy(None, hooks=[])
    assert not isinstance(rebuilt.tools[0], GuardedTool)


def test_enforce_policy_with_policy_and_hooks_wraps_with_both(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hexgate.security import AgentPolicy, PolicySet
    from hexgate.security.policy_set import DEFAULT_ROLE_NAME

    agent = _agent(monkeypatch)
    policy: Any = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {"echo": {"mode": "allow"}},
                }
            )
        }
    )

    guarded = agent.enforce_policy(policy, hooks=_hooks())

    wrapped = guarded.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.pipeline is not None
    assert wrapped.enforcer is not None
