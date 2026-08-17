"""Tests for the OpenAI Agents adapter agent wrapping helpers (phase 6).

The allow-all ``build_policy_set`` placeholder is gone. The wrapper is
now mechanics-only — ``wrap_openai_agent(agent, enforcer=...)`` clones
with gated tools — while policy resolution + the binding cache + per-run
refresh all live in the runner (see test_runner.py).
"""

from __future__ import annotations

from typing import Any

import pytest
from agents import Agent, FunctionTool

from hexgate.adapters.openai.wrapper import wrap_openai_agent
from hexgate.runtime import HexgateContext
from hexgate.security import AgentPolicy, BaseToolPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _make_tool(name: str = "echo") -> FunctionTool:
    """Build a minimal FunctionTool that records every invocation it receives."""

    async def on_invoke(_ctx: Any, raw_args: str) -> str:
        return f"invoked:{raw_args}"

    return FunctionTool(
        name=name,
        description=f"{name} tool",
        params_json_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        on_invoke_tool=on_invoke,
    )


def _make_agent(name: str = "my-agent", *, with_tools: bool = True) -> Agent:
    """Build an agents.Agent fixture for wrapper tests."""
    tools = [_make_tool("echo"), _make_tool("shout")] if with_tools else []
    return Agent(name=name, tools=tools)


def _allow_all_enforcer(tool_names: list[str]) -> PolicyEnforcer:
    engine = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy(
                tools={n: BaseToolPolicy(mode="allow") for n in tool_names}
            )
        }
    )
    return PolicyEnforcer(engine, agent_name="my-agent")


def _deny_all_enforcer() -> PolicyEnforcer:
    engine = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {"default_policy": {"mode": "deny"}}
            )
        }
    )
    return PolicyEnforcer(engine, agent_name="my-agent")


# ---------------------------------------------------------------------------
# wrap_openai_agent — clone + non-mutation (mechanics only, enforcer passed in)
# ---------------------------------------------------------------------------


def test_wrap_openai_agent_returns_a_new_agent_with_wrapped_tools() -> None:
    """wrap_openai_agent returns a clone whose tools are policy-gated copies."""
    original = _make_agent()
    original_tools = list(original.tools)

    wrapped = wrap_openai_agent(
        original, enforcer=_allow_all_enforcer(["echo", "shout"])
    )

    assert wrapped is not original
    assert wrapped.name == original.name
    assert [t.name for t in wrapped.tools] == [t.name for t in original_tools]
    for original_tool, wrapped_tool in zip(original_tools, wrapped.tools):
        assert wrapped_tool is not original_tool


def test_wrap_openai_agent_does_not_mutate_original_agent() -> None:
    """The original agent's tool list and tool callables are left untouched."""
    original = _make_agent()
    original_tools = list(original.tools)
    original_invokes = [t.on_invoke_tool for t in original_tools]

    wrap_openai_agent(original, enforcer=_allow_all_enforcer(["echo", "shout"]))

    assert list(original.tools) == original_tools
    for tool, invoke in zip(original.tools, original_invokes):
        assert tool.on_invoke_tool is invoke


def test_wrap_openai_agent_with_no_tools_returns_clone_with_empty_tools() -> None:
    """An agent with no tools wraps cleanly to a clone with no tools."""
    original = _make_agent(with_tools=False)

    wrapped = wrap_openai_agent(original, enforcer=_allow_all_enforcer([]))

    assert wrapped is not original
    assert list(wrapped.tools) == []


@pytest.mark.asyncio
async def test_wrap_openai_agent_gates_tools_with_the_given_enforcer() -> None:
    """The cloned agent's tools call through the supplied enforcer."""
    wrapped = wrap_openai_agent(_make_agent(), enforcer=_deny_all_enforcer())

    [echo_tool, _] = wrapped.tools
    async with HexgateContext(user_id="u-1"):
        result = await echo_tool.on_invoke_tool(None, '{"text": "hi"}')
    assert isinstance(result, str)
    assert "policy_denied" in result


@pytest.mark.asyncio
async def test_wrap_openai_agent_runs_the_guards_flat_list() -> None:
    """The wrapper takes a flat guards list like the other adapters and runs the
    before/after guards around each tool call."""
    from hexgate.guards import before_tool
    from hexgate.guards.types import Halt

    wrapped = wrap_openai_agent(
        _make_agent(),
        enforcer=_allow_all_enforcer(["echo", "shout"]),
        guards=[before_tool(lambda call: Halt(reason="remove the credential"))],
    )

    [echo_tool, _] = wrapped.tools
    async with HexgateContext(user_id="u-1"):
        result = await echo_tool.on_invoke_tool(None, '{"text": "hi"}')
    assert "remove the credential" in result  # the guard halted before the tool ran


@pytest.mark.asyncio
async def test_refresh_swap_reaches_every_clone() -> None:
    """Rebinding enforcer.policy (what refresh does) flips decisions in ALL
    clones produced from the shared enforcer — the per-call rewrap is safe."""
    enforcer = _deny_all_enforcer()
    first_clone = wrap_openai_agent(_make_agent(), enforcer=enforcer)
    second_clone = wrap_openai_agent(_make_agent(), enforcer=enforcer)

    async with HexgateContext(user_id="u-1"):
        denied = await first_clone.tools[0].on_invoke_tool(None, '{"text": "x"}')
        assert "policy_denied" in denied

        enforcer.policy = PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy(
                    tools={
                        "echo": BaseToolPolicy(mode="allow"),
                        "shout": BaseToolPolicy(mode="allow"),
                    }
                )
            }
        )  # the refresh swap

        for clone in (first_clone, second_clone):
            allowed = await clone.tools[0].on_invoke_tool(None, '{"text": "x"}')
            assert allowed == 'invoked:{"text": "x"}'
