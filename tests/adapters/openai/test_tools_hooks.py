"""Guard (before/after hook) parity for the OpenAI Agents adapter.

The policy path is covered in test_tools.py; here we prove a `ToolPipeline`
routed through `run_guarded_async` runs before/after guards around the tool,
that a rewrite reaches the tool, and that a halt reason reaches the model.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents import FunctionTool

from hexgate.adapters.openai.tools import wrap_tool
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


def _make_tool(name: str = "echo", calls: list[Any] | None = None) -> FunctionTool:
    record = calls if calls is not None else []

    async def on_invoke(ctx: Any, raw_args: str) -> str:
        record.append(raw_args)
        return f"invoked:{raw_args}"

    return FunctionTool(
        name=name,
        description="echo",
        params_json_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
        },
        on_invoke_tool=on_invoke,
    )


@pytest.mark.asyncio
async def test_before_guard_halt_blocks_and_reason_reaches_model() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [before_tool(lambda call: Halt(reason="remove the credential"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.on_invoke_tool(None, '{"text": "hi"}')

    assert isinstance(result, str)
    assert "remove the credential" in result  # reason surfaced via as_error_message
    assert calls == []


@pytest.mark.asyncio
async def test_before_guard_rewrite_reaches_the_tool() -> None:
    calls: list[Any] = []
    pipe = build_pipeline([before_tool(lambda call: Proceed(args={"text": "CLEAN"}))])
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.on_invoke_tool(None, '{"text": "dirty"}')

    assert json.loads(calls[0]) == {"text": "CLEAN"}
    assert result == 'invoked:{"text": "CLEAN"}'


@pytest.mark.asyncio
async def test_no_guards_forwards_the_raw_payload_byte_for_byte() -> None:
    """With no guards, the model's payload is forwarded unchanged — no json
    round-trip that would reformat whitespace or turn 1e400 into Infinity."""
    calls: list[Any] = []
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=None)

    raw = '{"a":1, "big":1e400}'
    await wrapped.on_invoke_tool(None, raw)

    assert calls == [raw]  # verbatim, not '{"a": 1, "big": Infinity}'


@pytest.mark.asyncio
async def test_before_guard_nested_in_place_rewrite_reaches_the_tool() -> None:
    """A nested in-place mutation (the documented shallow residual) reaches the
    tool on OpenAI too, matching the Google/Pydantic adapters."""
    calls: list[Any] = []

    def redact(call: Any) -> None:
        call.args["meta"]["secret"] = "REDACTED"  # top-level proxy, nested dict mutable
        return None

    pipe = build_pipeline([before_tool(redact)])
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    await wrapped.on_invoke_tool(None, '{"text": "hi", "meta": {"secret": "AKIA"}}')

    assert json.loads(calls[0]) == {"text": "hi", "meta": {"secret": "REDACTED"}}


@pytest.mark.asyncio
async def test_before_guard_non_json_rewrite_raises_a_clear_error() -> None:
    """This adapter re-serializes rewritten args, so a guard producing a
    non-JSON value must name the cause, not surface an opaque json TypeError."""
    pipe = build_pipeline([before_tool(lambda call: Proceed(args={"text": {1, 2, 3}}))])
    wrapped = wrap_tool(_make_tool(), _allow_enforcer(), pipeline=pipe)

    with pytest.raises(TypeError, match="not JSON-serializable"):
        await wrapped.on_invoke_tool(None, '{"text": "hi"}')


@pytest.mark.asyncio
async def test_after_guard_halt_suppresses_a_result_that_ran() -> None:
    calls: list[Any] = []
    pipe = build_pipeline(
        [after_tool(lambda call, out: Halt(reason="output withheld"))]
    )
    wrapped = wrap_tool(_make_tool(calls=calls), _allow_enforcer(), pipeline=pipe)

    result = await wrapped.on_invoke_tool(None, '{"text": "hi"}')

    assert "output withheld" in result
    assert calls == ['{"text": "hi"}']  # the tool DID run; only the result is withheld
