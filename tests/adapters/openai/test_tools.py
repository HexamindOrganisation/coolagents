"""Tests for the OpenAI Agents adapter policy gate on tools."""

from __future__ import annotations

from typing import Any

import pytest
from agents import FunctionTool

from hexgate.adapters.openai.tools import _parse_args, wrap_tool, wrap_tools
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _allow_policy_set(tool_name: str = "echo") -> PolicySet:
    """A bundle that allows a single named tool, denying everything else."""
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {tool_name: {"mode": "allow"}},
                }
            )
        }
    )


def _deny_policy_set() -> PolicySet:
    """A bundle that denies every tool by default."""
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {"default_policy": {"mode": "deny"}}
            )
        }
    )


def _approval_required_policy_set(tool_name: str = "echo") -> PolicySet:
    """A bundle where the named tool requires approval."""
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {tool_name: {"mode": "approval_required"}},
                }
            )
        }
    )


def _enforcer(policy_set: PolicySet) -> PolicyEnforcer:
    return PolicyEnforcer(policy_set)


def _make_tool(name: str = "echo", calls: list[Any] | None = None) -> FunctionTool:
    """Build a minimal FunctionTool that records every invocation."""
    record: list[Any] = calls if calls is not None else []

    async def on_invoke(ctx: Any, raw_args: str) -> str:
        record.append({"ctx": ctx, "args": raw_args})
        return f"invoked:{raw_args}"

    return FunctionTool(
        name=name,
        description="Echo tool",
        params_json_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        on_invoke_tool=on_invoke,
    )


def test_parse_args_returns_none_for_empty_string() -> None:
    """Treat an empty payload as 'no parsable arguments'."""
    assert _parse_args("") is None


def test_parse_args_returns_none_for_invalid_json() -> None:
    """Tolerate junk payloads by returning None."""
    assert _parse_args("not json") is None


def test_parse_args_returns_none_for_non_object_json() -> None:
    """Only object payloads count — lists and scalars yield None."""
    assert _parse_args("[1, 2, 3]") is None
    assert _parse_args('"just a string"') is None
    assert _parse_args("42") is None


def test_parse_args_parses_object_payload() -> None:
    """Round-trip a JSON object into a dict for policy checks."""
    assert _parse_args('{"text": "hi", "n": 1}') == {"text": "hi", "n": 1}


def test_wrap_tool_rejects_non_function_tool() -> None:
    """Refuse to wrap anything that is not a FunctionTool."""

    class NotAFunctionTool:
        name = "fake"

    with pytest.raises(TypeError, match="FunctionTool"):
        wrap_tool(NotAFunctionTool(), _enforcer(_allow_policy_set()))  # type: ignore[arg-type]


def test_wrap_tool_returns_a_distinct_copy() -> None:
    """wrap_tool returns a new FunctionTool instance, leaving the original alone."""
    original = _make_tool()
    original_invoke = original.on_invoke_tool

    wrapped = wrap_tool(original, _enforcer(_allow_policy_set()))

    assert wrapped is not original
    assert wrapped.on_invoke_tool is not original_invoke
    assert original.on_invoke_tool is original_invoke


def test_wrap_tool_preserves_metadata() -> None:
    """The wrapped tool keeps name, description, and schema for the model."""
    original = _make_tool("custom_tool")

    wrapped = wrap_tool(original, _enforcer(_allow_policy_set("custom_tool")))

    assert wrapped.name == "custom_tool"
    assert wrapped.description == original.description
    assert wrapped.params_json_schema == original.params_json_schema


@pytest.mark.asyncio
async def test_wrapped_tool_returns_denial_string_when_policy_denies() -> None:
    """A deny-mode policy short-circuits to the policy_denied string — tool never runs."""
    calls: list[Any] = []
    wrapped = wrap_tool(_make_tool(calls=calls), _enforcer(_deny_policy_set()))

    result = await wrapped.on_invoke_tool(None, '{"text": "hi"}')

    assert isinstance(result, str)
    assert "policy_denied" in result
    assert "echo" in result
    assert calls == []


@pytest.mark.asyncio
async def test_wrapped_tool_returns_approval_string_when_policy_requires_approval() -> (
    None
):
    """approval_required is treated like denial for OpenAI — tool never runs, distinct marker."""
    calls: list[Any] = []
    wrapped = wrap_tool(
        _make_tool(calls=calls), _enforcer(_approval_required_policy_set())
    )

    result = await wrapped.on_invoke_tool(None, '{"text": "hi"}')

    assert "approval_required" in result
    assert "policy_denied" not in result
    assert calls == []


@pytest.mark.asyncio
async def test_wrapped_tool_invokes_original_when_policy_allows() -> None:
    """An allow-mode policy forwards to the original on_invoke_tool callable."""
    calls: list[Any] = []
    wrapped = wrap_tool(_make_tool(calls=calls), _enforcer(_allow_policy_set()))

    result = await wrapped.on_invoke_tool("ctx-sentinel", '{"text": "hi"}')

    assert result == 'invoked:{"text": "hi"}'
    assert calls == [{"ctx": "ctx-sentinel", "args": '{"text": "hi"}'}]


@pytest.mark.asyncio
async def test_wrapped_tool_handles_unparseable_arguments() -> None:
    """Junk argument payloads still go through the policy; a valid policy lets them run."""
    calls: list[Any] = []
    wrapped = wrap_tool(_make_tool(calls=calls), _enforcer(_allow_policy_set()))

    result = await wrapped.on_invoke_tool(None, "not-json")

    assert result == "invoked:not-json"
    assert calls and calls[0]["args"] == "not-json"


@pytest.mark.asyncio
async def test_original_tool_is_not_mutated_by_wrap_tool() -> None:
    """The original tool can still be invoked directly with its original behavior."""
    calls: list[Any] = []
    original = _make_tool(calls=calls)

    wrap_tool(original, _enforcer(_deny_policy_set()))

    result = await original.on_invoke_tool("ctx", '{"text": "hi"}')
    assert result == 'invoked:{"text": "hi"}'
    assert len(calls) == 1


def test_wrap_tools_returns_distinct_list_of_copies() -> None:
    """wrap_tools returns a fresh list of fresh wrapped copies."""
    originals = [_make_tool("a"), _make_tool("b")]
    policy_set = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {"a": {"mode": "allow"}, "b": {"mode": "allow"}},
                }
            )
        }
    )

    wrapped = wrap_tools(originals, _enforcer(policy_set))

    assert wrapped is not originals
    assert len(wrapped) == 2
    for original_tool, wrapped_tool in zip(originals, wrapped):
        assert wrapped_tool is not original_tool
        assert wrapped_tool.name == original_tool.name


@pytest.mark.asyncio
async def test_wrap_tools_isolates_policy_decisions_per_tool() -> None:
    """Each wrapped tool follows its own per-name decision under the same enforcer."""
    originals = [_make_tool("tool_a"), _make_tool("tool_b")]
    policy_set = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                {
                    "default_policy": {"mode": "deny"},
                    "tools": {
                        "tool_a": {"mode": "allow"},
                        "tool_b": {"mode": "deny"},
                    },
                }
            )
        }
    )
    [tool_a, tool_b] = wrap_tools(originals, _enforcer(policy_set))

    allowed = await tool_a.on_invoke_tool(None, '{"text": "x"}')
    denied = await tool_b.on_invoke_tool(None, '{"text": "x"}')

    assert allowed == 'invoked:{"text": "x"}'
    assert "policy_denied" in denied


# ---------------------------------------------------------------------------
# approval_handler on NEEDS_APPROVAL decisions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approval_handler_true_runs_original_tool() -> None:
    """An async handler that returns True lets the tool through."""
    calls: list[Any] = []
    seen_decisions: list[Any] = []

    async def approve(decision: Any) -> bool:
        seen_decisions.append(decision)
        return True

    wrapped = wrap_tool(
        _make_tool(calls=calls),
        _enforcer(_approval_required_policy_set()),
        approval_handler=approve,
    )

    result = await wrapped.on_invoke_tool("ctx", '{"text": "hi"}')

    assert result == 'invoked:{"text": "hi"}'
    assert len(calls) == 1
    assert len(seen_decisions) == 1
    assert seen_decisions[0].tool_name == "echo"


@pytest.mark.asyncio
async def test_approval_handler_false_returns_marker() -> None:
    """A handler that returns False falls back to the [approval_required] marker."""
    calls: list[Any] = []

    async def deny(_: Any) -> bool:
        return False

    wrapped = wrap_tool(
        _make_tool(calls=calls),
        _enforcer(_approval_required_policy_set()),
        approval_handler=deny,
    )

    result = await wrapped.on_invoke_tool("ctx", '{"text": "hi"}')

    assert "approval_required" in result
    assert calls == []


@pytest.mark.asyncio
async def test_bool_approval_handler_short_circuits() -> None:
    """approval_handler=True skips the callback and runs the tool."""
    calls: list[Any] = []
    wrapped = wrap_tool(
        _make_tool(calls=calls),
        _enforcer(_approval_required_policy_set()),
        approval_handler=True,
    )

    result = await wrapped.on_invoke_tool("ctx", '{"text": "hi"}')

    assert result == 'invoked:{"text": "hi"}'
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_approval_handler_not_called_on_plain_deny() -> None:
    """A plain deny never consults the approval handler."""
    calls_to_handler: list[Any] = []

    async def approve(decision: Any) -> bool:
        calls_to_handler.append(decision)
        return True

    wrapped = wrap_tool(
        _make_tool(),
        _enforcer(_deny_policy_set()),
        approval_handler=approve,
    )

    result = await wrapped.on_invoke_tool("ctx", '{"text": "hi"}')

    assert "policy_denied" in result
    assert calls_to_handler == []


@pytest.mark.asyncio
async def test_sync_approval_handler_is_accepted() -> None:
    """A plain sync callable is a valid handler too."""
    calls: list[Any] = []

    def approve(_: Any) -> bool:
        return True

    wrapped = wrap_tool(
        _make_tool(calls=calls),
        _enforcer(_approval_required_policy_set()),
        approval_handler=approve,
    )

    result = await wrapped.on_invoke_tool("ctx", '{"text": "hi"}')

    assert result == 'invoked:{"text": "hi"}'
    assert len(calls) == 1
