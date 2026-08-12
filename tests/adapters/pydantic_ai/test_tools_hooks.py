"""Guard (before/after hook) parity for the pydantic_ai adapter.

pydantic_ai renders a block by *raising* ``ModelRetry``, so the halt reason
must arrive in the exception message.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic_ai.exceptions import ModelRetry
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai.tools import wrap_tool
from hexgate.hooks import after_tool, before_tool, build_pipeline
from hexgate.hooks.types import Halt, Proceed
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


def _make_tool(name: str = "echo", calls: list[Any] | None = None) -> Tool:
    record = calls if calls is not None else []

    def echo(text: str) -> str:
        """Echo the input back."""
        record.append(text)
        return f"echo:{text}"

    return Tool(echo, name=name)


@pytest.mark.asyncio
async def test_before_guard_halt_raises_model_retry_with_reason() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [before_tool(lambda call: Halt(reason="remove the credential"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    with pytest.raises(ModelRetry, match="remove the credential"):
        await wrapped.function_schema.call({"text": "hi"}, None)
    assert calls == []


@pytest.mark.asyncio
async def test_before_guard_rewrite_reaches_the_tool() -> None:
    calls: list[Any] = []
    pipe = build_pipeline([before_tool(lambda call: Proceed(args={"text": "CLEAN"}))])
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.function_schema.call({"text": "dirty"}, None)

    assert calls == ["CLEAN"]
    assert result == "echo:CLEAN"


@pytest.mark.asyncio
async def test_after_guard_halt_raises_after_the_tool_ran() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [after_tool(lambda call, out: Halt(reason="output withheld"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    with pytest.raises(ModelRetry, match="output withheld"):
        await wrapped.function_schema.call({"text": "hi"}, None)
    assert calls == ["hi"]  # the tool DID run before the after-guard withheld it
