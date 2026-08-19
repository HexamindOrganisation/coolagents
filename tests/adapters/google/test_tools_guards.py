"""Guard (before/after guard) parity for the Google ADK adapter."""

from __future__ import annotations

from typing import Any

import pytest
from google.adk.tools.function_tool import FunctionTool

from hexgate.adapters.google.tools import wrap_tool
from hexgate.guards import after_tool, before_tool, build_pipeline
from hexgate.guards.types import Halt, Proceed
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _allow_enforcer(name: str = "echo") -> PolicyEnforcer:
    return PolicyEnforcer(
        PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                    {
                        "default_policy": {"mode": "deny"},
                        "tools": {name: {"mode": "allow"}},
                    }
                )
            }
        )
    )


def _make_tool(name: str = "echo", calls: list[Any] | None = None) -> FunctionTool:
    record = calls if calls is not None else []

    def echo(text: str) -> str:
        """Echo the input back."""
        record.append(text)
        return f"echo:{text}"

    echo.__name__ = name
    return FunctionTool(func=echo)


@pytest.mark.asyncio
async def test_before_guard_halt_blocks_and_reason_reaches_model() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [before_tool(lambda call: Halt(reason="remove the credential"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert "remove the credential" in result
    assert calls == []


@pytest.mark.asyncio
async def test_before_guard_rewrite_reaches_the_tool() -> None:
    calls: list[Any] = []
    pipe = build_pipeline([before_tool(lambda call: Proceed(args={"text": "CLEAN"}))])
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.run_async(args={"text": "dirty"}, tool_context=None)

    assert calls == ["CLEAN"]
    assert result == "echo:CLEAN"


@pytest.mark.asyncio
async def test_after_guard_halt_suppresses_a_result_that_ran() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [after_tool(lambda call, out: Halt(reason="output withheld"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.run_async(args={"text": "hi"}, tool_context=None)

    assert "output withheld" in result
    assert calls == ["hi"]  # the tool DID run; only the result is withheld
