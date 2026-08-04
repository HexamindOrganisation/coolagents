"""Tests for the in-place :func:`install_enforcer_on_tool` LangChain mutator.

The new ``GuardedTool`` (used by ``HexgateAgent.enforce_policy``) is
covered in :mod:`test_guarded_tool`. This file targets the alternate
path used by :func:`wrap_langchain_agent` to retrofit pre-built
``CompiledStateGraph`` instances whose tool references can't be swapped.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import BaseTool, tool

from hexgate.adapters.langchain.tools import (
    install_enforcer_on_tool,
    install_enforcer_on_tools,
)
from hexgate.runtime import HexgateContext
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _enforcer_for(spec: dict[str, Any]) -> PolicyEnforcer:
    """Build a one-role enforcer from a flat AgentPolicy spec."""
    return PolicyEnforcer(
        PolicySet({DEFAULT_ROLE_NAME: AgentPolicy.model_validate(spec)})
    )


def _allow_enforcer(tool_name: str = "echo") -> PolicyEnforcer:
    return _enforcer_for(
        {
            "default_policy": {"mode": "deny"},
            "tools": {tool_name: {"mode": "allow"}},
        }
    )


def _deny_enforcer() -> PolicyEnforcer:
    return _enforcer_for({"default_policy": {"mode": "deny"}})


def _approval_enforcer(tool_name: str = "echo") -> PolicyEnforcer:
    return _enforcer_for(
        {
            "default_policy": {"mode": "deny"},
            "tools": {tool_name: {"mode": "approval_required"}},
        }
    )


def _make_sync_tool(name: str = "echo") -> BaseTool:
    """StructuredTool-style sync echo tool."""

    @tool(name)
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    return echo


def _make_async_tool(name: str = "echo") -> BaseTool:
    """StructuredTool-style async echo tool."""

    @tool(name)
    async def echo(text: str) -> str:
        """Echo the input back asynchronously."""
        return f"async:{text}"

    return echo


# ---------------------------------------------------------------------------
# install_enforcer_on_tool — basic shape
# ---------------------------------------------------------------------------


def test_install_returns_same_tool_and_sets_handle_tool_error() -> None:
    """Mutates the tool in place; returns the same object."""
    t = _make_sync_tool()

    result = install_enforcer_on_tool(t, enforcer=_allow_enforcer())

    assert result is t
    assert t.handle_tool_error is True
    assert getattr(t, "_hexgate_enforcer_installed") is True


def test_install_rejects_tool_without_func_or_coroutine() -> None:
    """Raise TypeError when the tool isn't StructuredTool-compatible."""

    class BareTool(BaseTool):
        name: str = "bare"
        description: str = "tool without func/coroutine"

        def _run(self, *_args: Any, **_kwargs: Any) -> str:
            """Pretend to do work."""
            return "ok"

    with pytest.raises(TypeError, match="StructuredTool-style"):
        install_enforcer_on_tool(BareTool(), enforcer=_allow_enforcer())


def test_reinstall_replaces_enforcer_without_stacking() -> None:
    """Re-installing rebinds the original ``func`` to the new enforcer."""
    t = _make_sync_tool()
    install_enforcer_on_tool(t, enforcer=_allow_enforcer())
    first_guard = t.func

    install_enforcer_on_tool(t, enforcer=_deny_enforcer())

    # New closure replaced the previous one.
    assert t.func is not first_guard
    # Calling it goes through the NEW enforcer → deny.
    result = t.func(text="hello")
    assert isinstance(result, dict)
    assert result["error"]["type"] == "policy_denied"


# ---------------------------------------------------------------------------
# Sync ``func`` branches
# ---------------------------------------------------------------------------


def test_sync_allow_delegates_to_original() -> None:
    t = _make_sync_tool()
    install_enforcer_on_tool(t, enforcer=_allow_enforcer())

    assert t.func(text="hi") == "echo:hi"


def test_sync_deny_returns_structured_error() -> None:
    t = _make_sync_tool()
    install_enforcer_on_tool(t, enforcer=_deny_enforcer())

    result = t.func(text="hi")

    assert result["ok"] is False
    assert result["error"]["type"] == "policy_denied"
    assert result["error"]["tool_name"] == "echo"


def test_sync_needs_approval_renders_structured_error() -> None:
    """install_enforcer_on_tool always renders NEEDS_APPROVAL as a structured
    error — no inline approval flow on the in-place mutator."""
    t = _make_sync_tool()
    install_enforcer_on_tool(t, enforcer=_approval_enforcer())

    result = t.func(text="hi")

    assert result["error"]["type"] == "approval_required"


# ---------------------------------------------------------------------------
# Async ``coroutine`` branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_allow_delegates_to_original() -> None:
    t = _make_async_tool()
    install_enforcer_on_tool(t, enforcer=_allow_enforcer())

    assert await t.coroutine(text="hi") == "async:hi"


@pytest.mark.asyncio
async def test_async_deny_returns_structured_error() -> None:
    t = _make_async_tool()
    install_enforcer_on_tool(t, enforcer=_deny_enforcer())

    result = await t.coroutine(text="hi")

    assert result["error"]["type"] == "policy_denied"


@pytest.mark.asyncio
async def test_async_needs_approval_renders_structured_error() -> None:
    t = _make_async_tool()
    install_enforcer_on_tool(t, enforcer=_approval_enforcer())

    result = await t.coroutine(text="hi")

    assert result["error"]["type"] == "approval_required"


# ---------------------------------------------------------------------------
# Role resolution via HexgateContext contextvar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_role_selects_matching_policy() -> None:
    """The active HexgateContext's role drives which AgentPolicy the enforcer applies."""
    policy_set = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {"default_policy": {"mode": "deny"}}
            ),
            "support": AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {"echo": {"mode": "allow"}},
                }
            ),
        }
    )
    enforcer = PolicyEnforcer(policy_set)
    t = _make_async_tool()
    install_enforcer_on_tool(t, enforcer=enforcer)

    # No HexgateContext → default role → denied.
    denied = await t.coroutine(text="hi")
    assert denied["error"]["type"] == "policy_denied"

    # support role → allowed.
    async with HexgateContext(user_id="u-1", user_roles=["support"]):
        allowed = await t.coroutine(text="hi")
    assert allowed == "async:hi"


# ---------------------------------------------------------------------------
# Batch installer
# ---------------------------------------------------------------------------


def test_install_on_tools_installs_each_and_returns_same_list() -> None:
    tools = [_make_sync_tool("a"), _make_sync_tool("b")]

    result = install_enforcer_on_tools(
        tools,
        enforcer=_enforcer_for(
            {
                "default_policy": {"mode": "deny"},
                "tools": {"a": {"mode": "allow"}, "b": {"mode": "allow"}},
            }
        ),
    )

    assert result is tools
    for t in tools:
        assert getattr(t, "_hexgate_enforcer_installed") is True


def test_install_on_tools_isolates_decisions_per_tool() -> None:
    """Each tool consults the enforcer independently — same enforcer, per-name decision."""
    tool_a = _make_sync_tool("tool_a")
    tool_b = _make_sync_tool("tool_b")
    install_enforcer_on_tools(
        [tool_a, tool_b],
        enforcer=_enforcer_for(
            {
                "default_policy": {"mode": "deny"},
                "tools": {
                    "tool_a": {"mode": "allow"},
                    "tool_b": {"mode": "deny"},
                },
            }
        ),
    )

    assert tool_a.func(text="x") == "echo:x"
    denied = tool_b.func(text="x")
    assert denied["error"]["type"] == "policy_denied"
