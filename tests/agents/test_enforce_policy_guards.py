"""`HexgateAgent.enforce_policy(guards=...)` wiring, including the guards-only
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
from hexgate.guards import before_tool
from hexgate.guards.types import Halt


@tool
def echo(text: str) -> str:
    """Echo the input back."""
    return text


def _agent(monkeypatch: pytest.MonkeyPatch) -> HexgateAgent:
    monkeypatch.setattr(factory, "create_langchain_agent", lambda **k: "graph")
    return HexgateAgent(
        graph="graph", model="m", tools=[echo], system_prompt=None, name="bot"
    )


def _guards() -> list:
    return [before_tool(lambda call: Halt(reason="blocked"))]


def test_enforce_policy_none_with_guards_wraps_tools_guards_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """policy=None + guards still guards each tool via guards (no enforcer)."""
    agent = _agent(monkeypatch)

    guarded = agent.enforce_policy(None, guards=_guards())

    wrapped = guarded.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.enforcer is None
    assert wrapped.pipeline is not None
    assert len(wrapped.pipeline.pre) == 1


def test_guards_only_path_keeps_approval_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A guard Halt(NEEDS_APPROVAL) must be approvable on the guards-only path."""
    agent = _agent(monkeypatch)

    guarded = agent.enforce_policy(None, guards=_guards(), approval_handler=True)

    wrapped = guarded.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.enforcer is None
    assert wrapped.approval_handler is True


def test_enforce_policy_none_without_guards_stays_unguarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _agent(monkeypatch)
    rebuilt = agent.enforce_policy(None)
    assert not isinstance(rebuilt.tools[0], GuardedTool)


def test_enforce_policy_none_empty_guards_stays_unguarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = _agent(monkeypatch)
    rebuilt = agent.enforce_policy(None, guards=[])
    assert not isinstance(rebuilt.tools[0], GuardedTool)


def test_enforce_policy_with_policy_and_guards_wraps_with_both(
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

    guarded = agent.enforce_policy(policy, guards=_guards())

    wrapped = guarded.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.pipeline is not None
    assert wrapped.enforcer is not None


def _stub_build(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(factory, "create_langchain_agent", lambda **k: "graph")
    monkeypatch.setattr(factory, "get_langfuse_handler", lambda **k: "handler")


def test_create_agent_guards_only_when_no_policy_binds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """create_agent(guards=..., bind_policy=False) still wraps tools with guards."""
    _stub_build(monkeypatch)

    agent, _ = factory.create_agent(
        model="m", tools=[echo], bind_policy=False, guards=_guards()
    )

    wrapped = agent.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.enforcer is None
    assert wrapped.pipeline is not None


def test_create_agent_binds_policy_and_guards_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """On the bind path, guards wrap the tools alongside the resolved policy."""
    from dataclasses import dataclass

    from hexgate.security import AgentPolicy, PolicySet
    from hexgate.security.policy_set import DEFAULT_ROLE_NAME

    _stub_build(monkeypatch)
    monkeypatch.setattr(factory, "resolve_api_key", lambda: None)

    engine = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {"echo": {"mode": "allow"}},
                }
            )
        }
    )

    @dataclass
    class _Resolved:
        engine: Any
        source: Any = None

    monkeypatch.setattr(
        "hexgate.security.binding.resolve_policy",
        lambda name, client=None: _Resolved(engine=engine),
    )

    agent, _ = factory.create_agent(
        model="m", tools=[echo], name="bot", bind_policy=True, guards=_guards()
    )

    wrapped = agent.tools[0]
    assert isinstance(wrapped, GuardedTool)
    assert wrapped.enforcer is not None
    assert wrapped.pipeline is not None
