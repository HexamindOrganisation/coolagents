"""End-to-end: guards wired through ``GuardedTool``.

The runner behavior itself is covered in ``tests/guards/test_runner.py``;
here we prove the LangChain seam actually threads before/after guards and arg
rewrites around a real tool invocation, and that guards work with no enforcer.
"""

from __future__ import annotations

import pytest
from langchain_core.tools import BaseTool, tool

from hexgate.adapters.langchain.tools import GuardedTool
from hexgate.guards import after_tool, before_tool, build_pipeline
from hexgate.guards.types import Halt, Proceed, ToolCall, ToolOutcome
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _allow_enforcer(tool_name: str = "echo") -> PolicyEnforcer:
    return PolicyEnforcer(
        PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy.model_validate(
                    {
                        "default_policy": {"mode": "deny"},
                        "tools": {tool_name: {"mode": "allow"}},
                    }
                )
            }
        )
    )


def _echo_tool() -> BaseTool:
    @tool("echo")
    async def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    return echo


@pytest.mark.asyncio
async def test_pre_rewrite_reaches_the_wrapped_tool() -> None:
    """A before-guard that rewrites args changes what the tool actually receives."""

    def uppercase(call: ToolCall) -> Proceed:
        return Proceed(args={**call.args, "text": call.args["text"].upper()})

    pipe = build_pipeline([before_tool(uppercase)])
    guarded = GuardedTool.wrap(_echo_tool(), enforcer=_allow_enforcer(), pipeline=pipe)

    assert await guarded._arun(text="hi") == "echo:HI"


@pytest.mark.asyncio
async def test_pre_halt_short_circuits_the_wrapped_tool() -> None:
    pipe = build_pipeline([before_tool(lambda call: Halt(reason="Refused by filter."))])
    guarded = GuardedTool.wrap(_echo_tool(), enforcer=_allow_enforcer(), pipeline=pipe)

    result = await guarded._arun(text="hi")
    assert result["ok"] is False
    assert result["error"]["message"] == "Refused by filter."


@pytest.mark.asyncio
async def test_post_halt_suppresses_the_tool_result() -> None:
    seen: list[ToolOutcome] = []

    def watch(call: ToolCall, out: ToolOutcome) -> Halt:
        seen.append(out)
        return Halt(reason="Result withheld.")

    pipe = build_pipeline([after_tool(watch)])
    guarded = GuardedTool.wrap(_echo_tool(), enforcer=_allow_enforcer(), pipeline=pipe)

    result = await guarded._arun(text="hi")
    assert result["ok"] is False
    assert seen[0].value == "echo:hi"  # the tool ran; the after-guard saw its output


@pytest.mark.asyncio
async def test_guards_run_without_an_enforcer() -> None:
    """Guards alone (no policy) still gate the call."""
    pipe = build_pipeline(
        [before_tool(lambda call: Halt(reason="no policy, still gated"))]
    )
    guarded = GuardedTool.wrap(_echo_tool(), pipeline=pipe)

    result = await guarded._arun(text="hi")
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_wrap_falls_pipeline_through_on_rewrap() -> None:
    pipe = build_pipeline([before_tool(lambda call: None)])
    once = GuardedTool.wrap(_echo_tool(), enforcer=_allow_enforcer(), pipeline=pipe)
    twice = GuardedTool.wrap(once, enforcer=_allow_enforcer())
    assert twice.pipeline is pipe


def test_sync_guard_rewrite() -> None:
    @tool("echo")
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    pipe = build_pipeline(
        [before_tool(lambda call: Proceed(args={"text": "rewritten"}))]
    )
    guarded = GuardedTool.wrap(echo, enforcer=_allow_enforcer(), pipeline=pipe)

    assert guarded._run(text="original") == "echo:rewritten"
