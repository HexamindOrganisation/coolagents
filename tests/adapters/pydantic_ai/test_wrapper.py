"""Tests for the pydantic_ai adapter agent wrapper entry point (phase 7).

The allow-all ``build_policy_set`` placeholder is gone: wrap-time policy
comes from :func:`resolve_policy` (platform / local override; fail-loud on
a 404). These tests stub that seam so no platform is needed.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai import wrapper as wrapper_mod
from hexgate.adapters.pydantic_ai.agent import HexgatePydanticAgent
from hexgate.adapters.pydantic_ai.wrapper import (
    _clone_agent_with_tools,
    _extract_tools,
    wrap_pydantic_agent,
)
from hexgate.security import AgentPolicy, BaseToolPolicy, PolicySet, ResolvedPolicy
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _allow_all(tool_names: list[str]) -> PolicySet:
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy(
                tools={n: BaseToolPolicy(mode="allow") for n in tool_names}
            )
        }
    )


@pytest.fixture(autouse=True)
def _stub_resolve(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub the platform resolve seam with an allow-all engine.

    Wrapper mechanics (clone, toolset, key resolution) are what these
    tests cover; resolution itself is covered by the binding tests."""
    captured: dict[str, Any] = {}

    def fake_resolve(
        name: str, *, api_key: str, client: object = None
    ) -> ResolvedPolicy:
        captured.update(name=name, key=api_key)
        return ResolvedPolicy(_allow_all(["echo", "shout"]), None)

    monkeypatch.setattr(wrapper_mod, "resolve_policy", fake_resolve)
    return captured


def _make_agent(name: str | None = "my-agent", *, with_tools: bool = True) -> Agent:
    """Build a pydantic_ai Agent backed by a TestModel for wrapper tests."""

    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    def shout(text: str) -> str:
        """Shout the input back."""
        return f"SHOUT:{text}"

    tools: list[Tool] = (
        [Tool(echo, name="echo"), Tool(shout, name="shout")] if with_tools else []
    )
    return Agent(TestModel(), name=name, tools=tools)


def test_extract_tools_returns_registered_tools() -> None:
    """Pull every Tool registered on the agent's function toolset."""
    agent = _make_agent()

    extracted = _extract_tools(agent)

    assert sorted(t.name for t in extracted) == ["echo", "shout"]


def test_extract_tools_returns_empty_list_when_no_tools_are_registered() -> None:
    """An agent with no tools yields an empty list."""
    agent = _make_agent(with_tools=False)

    assert _extract_tools(agent) == []


def test_extract_tools_returns_empty_list_when_function_toolset_is_missing() -> None:
    """Tolerate agent-like objects without a `_function_toolset` attribute."""

    class BareAgent:
        """Stand in for an Agent that exposes no toolset."""

    assert _extract_tools(BareAgent()) == []  # type: ignore[arg-type]


def test_clone_agent_with_tools_does_not_mutate_original() -> None:
    """Cloning replaces tools on the copy only — the original keeps its tools."""
    agent = _make_agent()
    original_tool_names = sorted(t.name for t in _extract_tools(agent))

    clone = _clone_agent_with_tools(agent, [])

    assert clone is not agent
    assert clone.instrument is True
    assert clone._function_toolset is not agent._function_toolset
    assert clone._function_toolset.tools == {}
    assert sorted(t.name for t in _extract_tools(agent)) == original_tool_names


def test_clone_agent_with_tools_installs_provided_tools_on_clone() -> None:
    """The clone exposes exactly the wrapped tools, keyed by name."""
    agent = _make_agent()
    [echo_tool, _] = _extract_tools(agent)

    clone = _clone_agent_with_tools(agent, [echo_tool])

    assert list(clone._function_toolset.tools.keys()) == ["echo"]


def test_wrap_pydantic_agent_returns_hexgate_proxy() -> None:
    """Return a HexgatePydanticAgent populated with agent name and api key."""
    agent = _make_agent()

    wrapped = wrap_pydantic_agent(agent=agent, api_key="hexgate-key")

    assert isinstance(wrapped, HexgatePydanticAgent)
    assert wrapped._api_key == "hexgate-key"
    assert wrapped._agent_name == "my-agent"


def test_wrap_pydantic_agent_does_not_mutate_original_agent() -> None:
    """Wrapping must clone the agent so the input agent stays usable."""
    agent = _make_agent()
    original_tools = _extract_tools(agent)

    wrapped = wrap_pydantic_agent(agent=agent, api_key="k")

    assert wrapped._agent is not agent
    same_tools = _extract_tools(agent)
    assert {t.name for t in same_tools} == {t.name for t in original_tools}
    for original_tool in original_tools:
        assert original_tool.function_schema is original_tool.function_schema


def test_wrap_pydantic_agent_falls_back_to_env_var(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve the API key from HEXGATE_API_KEY when no explicit key is given."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")
    agent = _make_agent()

    wrapped = wrap_pydantic_agent(agent=agent)

    assert wrapped._api_key == "from-env"


def test_wrap_pydantic_agent_prefers_explicit_api_key_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit api_key argument wins over HEXGATE_API_KEY when both are set."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")

    wrapped = wrap_pydantic_agent(agent=_make_agent(), api_key="explicit")

    assert wrapped._api_key == "explicit"


def test_wrap_pydantic_agent_raises_when_no_api_key_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject construction when neither argument nor env var supplies a key."""
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="No API key provided"):
        wrap_pydantic_agent(agent=_make_agent())


def test_wrap_pydantic_agent_raises_when_api_key_is_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Treat an empty HEXGATE_API_KEY env var the same as missing."""
    monkeypatch.setenv("HEXGATE_API_KEY", "")

    with pytest.raises(ValueError, match="No API key provided"):
        wrap_pydantic_agent(agent=_make_agent(), api_key="")


def test_wrap_pydantic_agent_uses_default_name_when_agent_has_none() -> None:
    """Fall back to 'default' when the wrapped agent has no `name`."""
    agent = _make_agent(name=None)

    wrapped = wrap_pydantic_agent(agent=agent, api_key="k")

    assert wrapped._agent_name == "default"


def test_wrap_pydantic_agent_clone_has_wrapped_tools() -> None:
    """The cloned agent exposes wrapped (not original) Tool instances."""
    agent = _make_agent()
    original_tools = {t.name: t for t in _extract_tools(agent)}

    wrapped = wrap_pydantic_agent(agent=agent, api_key="k")

    cloned_tools = wrapped._agent._function_toolset.tools
    assert set(cloned_tools.keys()) == set(original_tools.keys())
    for name, cloned_tool in cloned_tools.items():
        assert cloned_tool is not original_tools[name]


def test_wrap_pydantic_agent_with_no_tools() -> None:
    """An agent with no tools wraps cleanly to an empty toolset."""
    agent = _make_agent(with_tools=False)

    wrapped = wrap_pydantic_agent(agent=agent, api_key="k")

    assert wrapped._agent._function_toolset.tools == {}


# ---------------------------------------------------------------------------
# Phase 7 — resolved policy, binding attachment, loud failures
# ---------------------------------------------------------------------------


def test_wrap_attaches_binding_sharing_the_tools_enforcer() -> None:
    """The proxy carries a binding whose enforcer is the one the wrapped
    toolset consults — a refresh swap reaches the tools, no re-wrap."""
    wrapped = wrap_pydantic_agent(agent=_make_agent(), api_key="k")

    assert wrapped._binding is not None
    assert isinstance(wrapped._binding.enforcer, PolicyEnforcer)
    assert wrapped._binding.enforcer.agent_name == "my-agent"


@pytest.mark.asyncio
async def test_wrap_enforces_the_resolved_policy_not_allow_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deny-by-default engine from resolve actually blocks the tools."""
    from pydantic_ai import ModelRetry

    monkeypatch.setattr(
        wrapper_mod,
        "resolve_policy",
        lambda name, *, api_key, client=None: ResolvedPolicy(
            PolicySet(
                {
                    DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                        {"default_policy": {"mode": "deny"}}
                    )
                }
            ),
            None,
        ),
    )

    wrapped = wrap_pydantic_agent(agent=_make_agent(), api_key="k")

    echo_tool = wrapped._agent._function_toolset.tools["echo"]
    with pytest.raises(ModelRetry, match="policy_denied"):
        await echo_tool.function_schema.call({"text": "hi"}, None)
