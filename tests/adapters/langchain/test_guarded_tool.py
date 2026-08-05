"""Tests for the :class:`GuardedTool` LangChain adapter.

``GuardedTool`` is the BaseTool-subclass path used by
:meth:`HexgateAgent.enforce_policy`. The sibling in-place
:func:`install_enforcer_on_tool` (used by ``wrap_langchain_agent`` to
retrofit pre-built ``CompiledStateGraph`` instances) is covered in
``test_tools.py``.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import BaseTool, tool

from hexgate.adapters.langchain.tools import GuardedTool
from hexgate.runtime import HexgateContext
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _policy_set(spec: dict[str, Any]) -> PolicySet:
    """Build a one-role PolicySet from a flat AgentPolicy spec."""
    return PolicySet({DEFAULT_ROLE_NAME: AgentPolicy.model_validate(spec)})


def _enforcer(spec: dict[str, Any]) -> PolicyEnforcer:
    """Build a PolicyEnforcer over a one-role bundle."""
    return PolicyEnforcer(_policy_set(spec))


def _allow_enforcer(tool_name: str = "echo") -> PolicyEnforcer:
    return _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "tools": {tool_name: {"mode": "allow"}},
        }
    )


def _deny_enforcer() -> PolicyEnforcer:
    return _enforcer({"default_policy": {"mode": "deny"}})


def _approval_enforcer(tool_name: str = "echo") -> PolicyEnforcer:
    return _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "tools": {tool_name: {"mode": "approval_required"}},
        }
    )


def _make_sync_tool(name: str = "echo") -> BaseTool:
    """A StructuredTool-style sync tool that echoes its input."""

    @tool(name)
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    return echo


def _make_async_tool(name: str = "echo") -> BaseTool:
    """A StructuredTool-style async tool that echoes its input."""

    @tool(name)
    async def echo(text: str) -> str:
        """Echo the input back asynchronously."""
        return f"echo-async:{text}"

    return echo


# ---------------------------------------------------------------------------
# Construction / wrap
# ---------------------------------------------------------------------------


def test_wrap_preserves_name_description_and_schema() -> None:
    """The guarded tool keeps everything the model sees."""
    inner = _make_sync_tool("custom_tool")

    guarded = GuardedTool.wrap(inner, enforcer=_allow_enforcer("custom_tool"))

    assert guarded.name == inner.name
    assert guarded.description == inner.description
    assert guarded.args_schema is inner.args_schema


def test_wrap_returns_a_new_instance_and_does_not_mutate_original() -> None:
    """``wrap`` returns a distinct object; the inner tool is untouched."""
    inner = _make_sync_tool()
    original_func = inner.func

    guarded = GuardedTool.wrap(inner, enforcer=_allow_enforcer())

    assert guarded is not inner
    assert guarded.wrapped_tool is inner
    assert inner.func is original_func


def test_rewrap_replaces_enforcer_without_stacking() -> None:
    """Wrapping an already-guarded tool unwraps it once before re-stamping."""
    inner = _make_sync_tool()
    first_enforcer = _allow_enforcer()
    second_enforcer = _deny_enforcer()

    once = GuardedTool.wrap(inner, enforcer=first_enforcer)
    twice = GuardedTool.wrap(once, enforcer=second_enforcer)

    # The new wrapper's enforcer is the second one — the first is gone, not nested.
    assert twice.enforcer is second_enforcer
    # The underlying tool is still the same primitive, not another GuardedTool.
    assert twice.wrapped_tool is inner
    assert not isinstance(twice.wrapped_tool, GuardedTool)


# ---------------------------------------------------------------------------
# _arun branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_arun_allow_delegates_to_wrapped_tool() -> None:
    """ALLOW → the wrapped coroutine runs and its result is returned verbatim."""
    guarded = GuardedTool.wrap(_make_async_tool(), enforcer=_allow_enforcer())

    result = await guarded._arun(text="hi")

    assert result == "echo-async:hi"


@pytest.mark.asyncio
async def test_arun_deny_returns_structured_error_and_skips_wrapped() -> None:
    """DENY → structured error dict, wrapped tool never invoked."""
    invocations: list[str] = []

    @tool("echo")
    async def echo(text: str) -> str:
        """Echo and record the call."""
        invocations.append(text)
        return text

    guarded = GuardedTool.wrap(echo, enforcer=_deny_enforcer())

    result = await guarded._arun(text="hi")

    assert isinstance(result, dict)
    assert result["ok"] is False
    assert result["error"]["type"] == "policy_denied"
    assert result["error"]["tool_name"] == "echo"
    assert invocations == []


@pytest.mark.asyncio
async def test_arun_needs_approval_without_handler_renders_error() -> None:
    """NEEDS_APPROVAL with no approval_handler → structured error, not invoked."""
    invocations: list[str] = []

    @tool("echo")
    async def echo(text: str) -> str:
        """Echo and record the call so the test can assert on it."""
        invocations.append(text)
        return text

    guarded = GuardedTool.wrap(echo, enforcer=_approval_enforcer())

    result = await guarded._arun(text="hi")

    assert result["error"]["type"] == "approval_required"
    assert invocations == []


@pytest.mark.asyncio
async def test_arun_needs_approval_with_truthy_bool_handler_invokes() -> None:
    """approval_handler=True → always approve, wrapped tool runs."""
    guarded = GuardedTool.wrap(
        _make_async_tool(), enforcer=_approval_enforcer(), approval_handler=True
    )

    result = await guarded._arun(text="hi")

    assert result == "echo-async:hi"


@pytest.mark.asyncio
async def test_arun_needs_approval_with_falsy_bool_handler_renders_error() -> None:
    """approval_handler=False → always deny, error returned, wrapped not run."""
    invocations: list[str] = []

    @tool("echo")
    async def echo(text: str) -> str:
        """Echo and record the call so the test can assert on it."""
        invocations.append(text)
        return text

    guarded = GuardedTool.wrap(
        echo, enforcer=_approval_enforcer(), approval_handler=False
    )

    result = await guarded._arun(text="hi")

    assert result["error"]["type"] == "approval_required"
    assert invocations == []


@pytest.mark.asyncio
async def test_arun_needs_approval_with_sync_callable_handler_sees_decision() -> None:
    """A sync callable approval_handler receives the Decision and gates the call."""
    seen: list[Decision] = []

    def approve(decision: Decision) -> bool:
        seen.append(decision)
        return True

    guarded = GuardedTool.wrap(
        _make_async_tool(), enforcer=_approval_enforcer(), approval_handler=approve
    )

    result = await guarded._arun(text="hi")

    assert result == "echo-async:hi"
    assert len(seen) == 1
    assert seen[0].outcome is DecisionOutcome.NEEDS_APPROVAL
    assert seen[0].tool_name == "echo"
    assert seen[0].arguments == {"text": "hi"}


@pytest.mark.asyncio
async def test_arun_needs_approval_with_async_callable_handler_is_awaited() -> None:
    """An async callable approval_handler is awaited before the decision is honored."""

    async def approve(decision: Decision) -> bool:
        assert decision.outcome is DecisionOutcome.NEEDS_APPROVAL
        return False

    invocations: list[str] = []

    @tool("echo")
    async def echo(text: str) -> str:
        """Echo and record the call so the test can assert on it."""
        invocations.append(text)
        return text

    guarded = GuardedTool.wrap(
        echo, enforcer=_approval_enforcer(), approval_handler=approve
    )

    result = await guarded._arun(text="hi")

    assert result["error"]["type"] == "approval_required"
    assert invocations == []


# ---------------------------------------------------------------------------
# _run branches (sync)
# ---------------------------------------------------------------------------


def test_run_allow_delegates_to_wrapped_tool() -> None:
    """Sync ALLOW path returns the wrapped tool's result."""
    guarded = GuardedTool.wrap(_make_sync_tool(), enforcer=_allow_enforcer())

    result = guarded._run(text="hi")

    assert result == "echo:hi"


def test_run_deny_returns_structured_error() -> None:
    """Sync DENY path renders the structured error."""
    guarded = GuardedTool.wrap(_make_sync_tool(), enforcer=_deny_enforcer())

    result = guarded._run(text="hi")

    assert result["error"]["type"] == "policy_denied"


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_run_with_async_approval_handler_raises_runtime_error() -> None:
    """A sync invocation can't await an async approval_handler — must raise clearly."""

    async def approve(_decision: Decision) -> bool:
        return True

    guarded = GuardedTool.wrap(
        _make_sync_tool(), enforcer=_approval_enforcer(), approval_handler=approve
    )

    with pytest.raises(RuntimeError, match="coroutine"):
        guarded._run(text="hi")


# ---------------------------------------------------------------------------
# Role resolution via HexgateContext contextvar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_role_selects_matching_role_policy() -> None:
    """The active HexgateContext's role drives which AgentPolicy the enforcer applies."""
    # Two roles: 'support' allows the tool, default denies.
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
    guarded = GuardedTool.wrap(_make_async_tool(), enforcer=enforcer)

    # No HexgateContext scope → default role → denied.
    denied = await guarded._arun(text="hi")
    assert denied["error"]["type"] == "policy_denied"

    # support role → allowed.
    async with HexgateContext(user_id="u-1", user_roles=["support"]):
        allowed = await guarded._arun(text="hi")
    assert allowed == "echo-async:hi"


# ---------------------------------------------------------------------------
# Error payload shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_payload_carries_role_when_user_scope_is_active() -> None:
    """The rendered error includes the role the decision was made against."""
    guarded = GuardedTool.wrap(_make_async_tool(), enforcer=_deny_enforcer())

    async with HexgateContext(user_id="u-1", user_roles=["billing"]):
        result = await guarded._arun(text="hi")

    assert result["error"]["role"] == "billing"
