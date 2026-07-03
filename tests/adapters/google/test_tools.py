"""Tests for the Google ADK adapter policy gate on tools."""

from __future__ import annotations

from typing import Any

import pytest
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.function_tool import FunctionTool

from hexgate.adapters.google.tools import _normalize, wrap_tool, wrap_tools
from hexgate.runtime import User
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _enforcer_for(spec: dict[str, Any]) -> PolicyEnforcer:
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


def _make_callable(name: str = "echo") -> Any:
    """Create a plain callable that ADK will wrap as a FunctionTool."""

    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    echo.__name__ = name
    return echo


def _make_function_tool(name: str = "echo") -> FunctionTool:
    """Create an ADK FunctionTool wrapping a sync echo function."""
    return FunctionTool(func=_make_callable(name))


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


def test_normalize_passes_base_tool_through() -> None:
    """A BaseTool input is returned unchanged, not re-wrapped."""
    tool = _make_function_tool()

    assert _normalize(tool) is tool


def test_normalize_wraps_callable_into_function_tool() -> None:
    """A plain callable is wrapped into a FunctionTool the gate can attach to."""
    fn = _make_callable("custom_name")

    normalized = _normalize(fn)

    assert isinstance(normalized, FunctionTool)
    assert normalized.name == "custom_name"


def test_normalize_rejects_non_callable_non_tool() -> None:
    """Refuse to normalize anything that is neither a BaseTool nor callable."""
    with pytest.raises(TypeError, match="BaseTool or callable"):
        _normalize(42)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# wrap_tool — basic shape
# ---------------------------------------------------------------------------


def test_wrap_tool_returns_a_distinct_copy() -> None:
    """wrap_tool returns a new BaseTool instance, leaving the original alone."""
    original = _make_function_tool()

    wrapped = wrap_tool(original, _allow_enforcer())

    assert wrapped is not original
    assert wrapped.run_async != original.run_async


def test_wrap_tool_preserves_metadata() -> None:
    """The wrapped tool keeps the original tool's name."""
    original = _make_function_tool("custom_tool")

    wrapped = wrap_tool(original, _allow_enforcer("custom_tool"))

    assert wrapped.name == "custom_tool"


def test_wrap_tool_accepts_plain_callable() -> None:
    """Wrapping a callable normalizes it into a FunctionTool with a gate."""
    fn = _make_callable("custom_name")

    wrapped = wrap_tool(fn, _allow_enforcer("custom_name"))

    assert isinstance(wrapped, BaseTool)
    assert wrapped.name == "custom_name"


# ---------------------------------------------------------------------------
# run_async branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allow_delegates_to_original_run_async() -> None:
    """An allow-mode policy forwards to the original run_async."""
    wrapped = wrap_tool(_make_function_tool(), _allow_enforcer())

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert result == "echo:hi"


@pytest.mark.asyncio
async def test_deny_renders_structured_marker() -> None:
    """A deny-mode policy short-circuits to the rendered denial — tool never runs."""
    wrapped = wrap_tool(_make_function_tool(), _deny_enforcer())

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert isinstance(result, str)
    assert "policy_denied" in result
    assert "echo" in result


@pytest.mark.asyncio
async def test_needs_approval_renders_marker_and_skips_tool() -> None:
    """NEEDS_APPROVAL always renders the marker — the tool never runs."""
    wrapped = wrap_tool(_make_function_tool(), _approval_enforcer())

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert "approval_required" in result
    assert "policy_denied" not in result


@pytest.mark.asyncio
async def test_original_tool_is_not_mutated_by_wrap_tool() -> None:
    """The original tool can still be invoked directly with its original behavior."""
    original = _make_function_tool()

    wrap_tool(original, _deny_enforcer())

    result = await original.run_async(args={"text": "hi"}, tool_context=None)
    assert result == "echo:hi"


# ---------------------------------------------------------------------------
# Role resolution via User contextvar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_role_selects_matching_policy() -> None:
    """The active User's role drives which AgentPolicy the enforcer applies."""
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
    wrapped = wrap_tool(_make_function_tool(), PolicyEnforcer(policy_set))

    # No User → default → denied.
    denied = await wrapped.run_async(args={"text": "hi"}, tool_context=None)
    assert "policy_denied" in denied

    # support → allowed.
    async with User(user_id="u-1", role="support"):
        allowed = await wrapped.run_async(args={"text": "hi"}, tool_context=None)
    assert allowed == "echo:hi"


# ---------------------------------------------------------------------------
# Batch wrap_tools
# ---------------------------------------------------------------------------


def test_wrap_tools_returns_distinct_list_of_copies() -> None:
    originals = [_make_function_tool("a"), _make_function_tool("b")]

    wrapped = wrap_tools(
        originals,
        _enforcer_for(
            {
                "default_policy": {"mode": "deny"},
                "tools": {"a": {"mode": "allow"}, "b": {"mode": "allow"}},
            }
        ),
    )

    assert wrapped is not originals
    assert len(wrapped) == 2
    for original_tool, wrapped_tool in zip(originals, wrapped):
        assert wrapped_tool is not original_tool
        assert wrapped_tool.name == original_tool.name


@pytest.mark.asyncio
async def test_wrap_tools_isolates_decisions_per_tool() -> None:
    """Each wrapped tool follows its own per-name decision under the same enforcer."""
    originals = [_make_function_tool("tool_a"), _make_function_tool("tool_b")]
    [tool_a, tool_b] = wrap_tools(
        originals,
        _enforcer_for(
            {
                "default_policy": {"mode": "deny"},
                "tools": {
                    "tool_a": {"mode": "allow"},
                    "tool_b": {"mode": "deny"},
                },
            }
        ),
    )

    allowed = await tool_a.run_async(args={"text": "x"}, tool_context=None)
    denied = await tool_b.run_async(args={"text": "x"}, tool_context=None)

    assert allowed == "echo:x"
    assert "policy_denied" in denied


@pytest.mark.asyncio
async def test_wrap_tools_accepts_mixed_callables_and_base_tools() -> None:
    """A mix of callables and BaseTools is normalized and gated uniformly."""
    fn = _make_callable("plain_fn")
    tool = _make_function_tool("tool_obj")

    wrapped = wrap_tools(
        [fn, tool],
        _enforcer_for(
            {
                "default_policy": {"mode": "deny"},
                "tools": {
                    "plain_fn": {"mode": "allow"},
                    "tool_obj": {"mode": "deny"},
                },
            }
        ),
    )

    [plain, gated] = wrapped
    assert plain.name == "plain_fn"
    assert gated.name == "tool_obj"
    allowed = await plain.run_async(args={"text": "x"}, tool_context=None)
    denied = await gated.run_async(args={"text": "x"}, tool_context=None)
    assert allowed == "echo:x"
    assert "policy_denied" in denied


# ---------------------------------------------------------------------------
# approval_handler on NEEDS_APPROVAL decisions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_handler_true_runs_original_tool() -> None:
    """An async handler that returns True lets the tool through."""
    seen: list[Any] = []

    async def approve(decision: Any) -> bool:
        seen.append(decision)
        return True

    wrapped = wrap_tool(
        _make_function_tool(),
        _approval_enforcer(),
        approval_handler=approve,
    )

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert result == "echo:hi"
    assert len(seen) == 1
    assert seen[0].tool_name == "echo"


@pytest.mark.asyncio
async def test_approval_handler_false_returns_marker() -> None:
    """A handler that returns False falls back to the [approval_required] marker."""

    async def deny(_: Any) -> bool:
        return False

    wrapped = wrap_tool(
        _make_function_tool(),
        _approval_enforcer(),
        approval_handler=deny,
    )

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert "approval_required" in result


@pytest.mark.asyncio
async def test_bool_approval_handler_short_circuits() -> None:
    """approval_handler=True skips the callback and runs the tool."""
    wrapped = wrap_tool(
        _make_function_tool(),
        _approval_enforcer(),
        approval_handler=True,
    )

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert result == "echo:hi"


@pytest.mark.asyncio
async def test_approval_handler_not_called_on_plain_deny() -> None:
    """A plain deny never consults the approval handler."""
    calls_to_handler: list[Any] = []

    async def approve(decision: Any) -> bool:
        calls_to_handler.append(decision)
        return True

    wrapped = wrap_tool(
        _make_function_tool(),
        _deny_enforcer(),
        approval_handler=approve,
    )

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert "policy_denied" in result
    assert calls_to_handler == []


@pytest.mark.asyncio
async def test_sync_approval_handler_is_accepted() -> None:
    """A plain sync callable is a valid handler too."""

    def approve(_: Any) -> bool:
        return True

    wrapped = wrap_tool(
        _make_function_tool(),
        _approval_enforcer(),
        approval_handler=approve,
    )

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert result == "echo:hi"
