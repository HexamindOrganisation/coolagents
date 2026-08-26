"""pydantic_ai adapter: resolve the platform policy, construct one
:class:`PolicyEnforcer`, and return a :class:`HexgatePydanticAgent`
proxy backed by a clone of the caller's ``Agent`` with policy-gated
tools.

Policy is resolved from the platform at wrap time (fail-loud on a 404 —
register the agent first with ``hexgate register``) and refreshed by the
proxy at the top of every run.
"""

from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import TYPE_CHECKING

from pydantic_ai import Agent
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai.agent import HexgatePydanticAgent
from hexgate.adapters.pydantic_ai.tools import wrap_tools
from hexgate.approvals import ApprovalHandler
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.guards.types import build_pipeline
from hexgate.security.agent_gate import warn_if_admission_unenforced
from hexgate.security.bans import resolve_ban_gate
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer

if TYPE_CHECKING:
    from hexgate.guards.types import Guard, GuardObserver


def _extract_tools(agent: Agent) -> list[Tool]:
    """Return Tool instances from ``agent._function_toolset`` (constructor
    args and ``@agent.tool``/``tool_plain`` decorators normalize there)."""
    toolset = getattr(agent, "_function_toolset", None)
    tools = getattr(toolset, "tools", None) if toolset is not None else None
    if tools is None:
        return []
    return list(tools.values())


def _clone_agent_with_tools(agent: Agent, wrapped_tools: list[Tool]) -> Agent:
    """Return a shallow copy of ``agent`` with ``wrapped_tools`` installed."""
    agent_copy = copy.copy(agent)
    agent_copy.instrument = True
    toolset = getattr(agent, "_function_toolset", None)
    if toolset is not None:
        toolset_copy = copy.copy(toolset)
        toolset_copy.tools = {t.name: t for t in wrapped_tools}
        agent_copy._function_toolset = toolset_copy
    return agent_copy


def wrap_pydantic_agent(
    *,
    agent: Agent,
    api_key: str | None = None,
    approval_handler: ApprovalHandler | None = None,
    guards: Sequence[Guard] | None = None,
    guard_observer: GuardObserver | None = None,
) -> HexgatePydanticAgent:
    """Wrap a pydantic_ai agent with Hexgate policy + observability.

    Returns a :class:`HexgatePydanticAgent` backed by a clone of the
    caller's ``agent``; the original is not mutated. The proxy takes
    ``hexgate_context`` per call; role resolves at call time from the active
    :class:`HexgateContext`. ``NEEDS_APPROVAL`` fires ``approval_handler`` (async
    ``fn(decision) -> bool`` or ``bool`` shorthand); a truthy return
    runs the tool, falsy or missing handler raises :class:`ModelRetry`
    with an ``[approval_required]`` marker. ``api_key`` falls back to
    ``HEXGATE_API_KEY``. The enforced policy is the platform's;
    unlisted tools are denied.
    """
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        raise ValueError(
            "No API key provided. Pass api_key= explicitly or set the HEXGATE_API_KEY environment variable."
        )

    agent_name = getattr(agent, "name", None) or "default"
    tools = _extract_tools(agent)

    # One client shared by the policy and ban resolvers — avoids a second
    # biscuit verify + JWKS round-trip per wrapped agent.
    client = HexgateClient(HexgateConfig.from_env(api_key=resolved_key))
    resolved = resolve_policy(agent_name, api_key=resolved_key, client=client)
    enforcer = build_enforcer(
        resolved.engine, agent_name=agent_name, api_key=resolved_key
    )
    warn_if_admission_unenforced(
        resolved.engine, framework="pydantic_ai", agent_name=agent_name
    )
    pipeline = build_pipeline(guards, observer=guard_observer)
    cloned_agent = _clone_agent_with_tools(
        agent,
        wrap_tools(
            tools, enforcer, approval_handler=approval_handler, pipeline=pipeline
        ),
    )

    return HexgatePydanticAgent(
        agent=cloned_agent,
        api_key=resolved_key,
        agent_name=agent_name,
        binding=PolicyBinding(enforcer, resolved.source),
        ban_gate=resolve_ban_gate(agent_name, api_key=resolved_key, client=client),
    )
