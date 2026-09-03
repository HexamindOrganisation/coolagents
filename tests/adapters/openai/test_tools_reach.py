"""Phase 1: top-edge agent-as-tool reach gating on the OpenAI adapter.

An ``Agent.as_tool()`` is a reach edge, not an ordinary tool. When the policy
declares reach, ``wrap_tool`` gates the call under ``agent.tool:<target>``
(closed-world, ``via``/constraints honored) instead of the tool name; without an
``agents`` block it keeps today's name-gating unchanged.
"""

from __future__ import annotations

from typing import Any

import pytest
from agents import FunctionTool
from agents.tool import ToolOrigin, ToolOriginType

from hexgate.adapters.openai import tools as tools_mod
from hexgate.adapters.openai.tools import _agent_tool_target, wrap_tool
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME

_SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
}


def _enforcer(spec: dict[str, Any]) -> PolicyEnforcer:
    return PolicyEnforcer(
        PolicySet({DEFAULT_ROLE_NAME: AgentPolicy.model_validate(spec)})
    )


def _agent_tool(
    target: str = "billing_bot",
    name: str = "billing",
    calls: list[Any] | None = None,
) -> FunctionTool:
    """A FunctionTool tagged the way ``Agent.as_tool()`` tags one — its origin
    points at ``target`` — but with a benign body we control (the real one would
    run the sub-agent through the SDK)."""
    record: list[Any] = calls if calls is not None else []

    async def on_invoke(ctx: Any, raw_args: str) -> str:
        record.append({"ctx": ctx, "args": raw_args})
        return f"ran-subagent:{raw_args}"

    return FunctionTool(
        name=name,
        description="consult the billing sub-agent",
        params_json_schema=_SCHEMA,
        on_invoke_tool=on_invoke,
        _tool_origin=ToolOrigin(type=ToolOriginType.AGENT_AS_TOOL, agent_name=target),
        _is_agent_tool=True,
    )


def _plain_tool(name: str = "echo") -> FunctionTool:
    async def on_invoke(ctx: Any, raw_args: str) -> str:
        return f"invoked:{raw_args}"

    return FunctionTool(
        name=name,
        description="echo",
        params_json_schema=_SCHEMA,
        on_invoke_tool=on_invoke,
    )


# --- detection --------------------------------------------------------------


def test_detects_agent_as_tool_target() -> None:
    assert _agent_tool_target(_agent_tool(target="billing_bot")) == "billing_bot"


def test_plain_tool_is_not_an_agent_tool() -> None:
    assert _agent_tool_target(_plain_tool()) is None


def test_detection_falls_back_when_sdk_cannot_expose_origin(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod, "_CAN_DETECT_AGENT_TOOLS", False)
    assert _agent_tool_target(_agent_tool()) is None


# --- reach-key gating (policy declares reach) -------------------------------


@pytest.mark.asyncio
async def test_agent_tool_allowed_when_reach_grants_tool_via() -> None:
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "agents": {"billing_bot": {"via": ["tool"], "mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert result == 'ran-subagent:{"query": "balance"}'
    assert calls  # the sub-agent body ran


@pytest.mark.asyncio
async def test_agent_tool_closed_world_denies_unlisted_target() -> None:
    """Reach is declared but this target isn't listed — closed-world denies, and
    the sub-agent never runs. The message names the bare target, not the key."""
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "agents": {"other_bot": {"via": ["tool"], "mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert calls == []
    assert "[policy_denied]" in result
    assert "billing_bot" in result
    assert "agent.tool" not in result  # no synthetic-key leak


@pytest.mark.asyncio
async def test_agent_tool_denied_when_target_listed_handoff_only() -> None:
    """Tool-reach is engaged (another target is ``via: tool``) and billing_bot is
    listed ``via: handoff`` only — reaching it *as a tool* closed-world denies."""
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "agents": {
                "billing_bot": {"via": ["handoff"], "mode": "allow"},
                "research_bot": {
                    "via": ["tool"],
                    "mode": "allow",
                },  # engages tool-reach
            },
        }
    )
    wrapped = wrap_tool(_agent_tool(calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert calls == []
    assert "[policy_denied]" in result
    assert "billing_bot" in result


@pytest.mark.asyncio
async def test_handoff_only_policy_does_not_engage_tool_reach() -> None:
    """A policy that declares only handoff reach must NOT closed-world-deny every
    agent-as-tool: with no ``via: tool`` target declared, as-tools fall back to
    name-gating (so a ``tools`` allow lets the call through)."""
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "agents": {"billing_bot": {"via": ["handoff"], "mode": "allow"}},
            "tools": {"billing": {"mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(name="billing", calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert result == 'ran-subagent:{"query": "balance"}'
    assert calls  # not silently denied


@pytest.mark.asyncio
async def test_name_scoped_guard_fires_on_as_tool_under_reach() -> None:
    """A guard scoped to the as-tool's function name still fires when reach is
    engaged — the reach key drives only the policy decision, not guard matching."""
    from hexgate.guards import before_tool, build_pipeline
    from hexgate.guards.types import Proceed

    seen: list[str] = []

    def watcher(call: Any) -> Proceed:
        seen.append(call.tool_name)
        return Proceed()

    pipe = build_pipeline([before_tool(watcher, tool_names="billing")])
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "agents": {"billing_bot": {"via": ["tool"], "mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(name="billing"), enforcer, pipeline=pipe)

    await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert seen == ["billing"]  # matched by tool name, not agent.tool:billing_bot


# --- name-gating fallback (no reach declared) — non-breaking -----------------


@pytest.mark.asyncio
async def test_agent_tool_name_gated_deny_without_reach_block() -> None:
    """No ``agents`` block → today's behavior: gated by the tool name, so a
    ``tools`` deny still blocks it (and no closed-world surprise fires)."""
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "tools": {"billing": {"mode": "deny"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(name="billing", calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert calls == []
    assert "[policy_denied]" in result
    assert "billing" in result  # named by tool name on the fallback path


@pytest.mark.asyncio
async def test_agent_tool_name_gated_allow_without_reach_block() -> None:
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            "tools": {"billing": {"mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(name="billing", calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert result == 'ran-subagent:{"query": "balance"}'
    assert calls


@pytest.mark.asyncio
async def test_falls_back_to_name_gating_when_sdk_undetectable(monkeypatch) -> None:
    """SDK too old to expose origins → the as-tool is treated as a plain tool
    (name-gated), even when the policy declares reach that would grant it."""
    monkeypatch.setattr(tools_mod, "_CAN_DETECT_AGENT_TOOLS", False)
    calls: list[Any] = []
    enforcer = _enforcer(
        {
            "default_policy": {"mode": "deny"},
            # reach would grant billing_bot, but detection is off, so the
            # tool-name 'billing' governs — and it is denied by default.
            "agents": {"billing_bot": {"via": ["tool"], "mode": "allow"}},
        }
    )
    wrapped = wrap_tool(_agent_tool(name="billing", calls=calls), enforcer)

    result = await wrapped.on_invoke_tool("ctx", '{"query": "balance"}')

    assert calls == []
    assert "[policy_denied]" in result
