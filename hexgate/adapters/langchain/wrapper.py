"""BYO-graph entry point: retrofit a pre-built ``CompiledStateGraph`` with
Hexgate policy. Tools are mutated in place so the graph keeps its
references; the returned :class:`HexgateLangchainAgent` opens a HexgateContext
scope + Langfuse propagation per call. For the manifest-driven path,
use :func:`hexgate.enforce_policy` instead.

Policy is resolved from the platform at wrap time (fail-loud on a 404 —
register the agent first with ``hexgate register``) and refreshed by the
proxy at the top of every call.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph

from hexgate.adapters.langchain.agent import HexgateLangchainAgent
from hexgate.adapters.langchain.tools import install_enforcer_on_tools
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.config.env import resolve_api_key
from hexgate.guards.types import build_pipeline
from hexgate.security.bans import resolve_ban_gate
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer

if TYPE_CHECKING:
    from hexgate.guards.types import Guard, GuardObserver


def wrap_langchain_agent(
    *,
    agent: CompiledStateGraph,
    tools: list[BaseTool],
    api_key: str | None = None,
    guards: Sequence[Guard] | None = None,
    guard_observer: GuardObserver | None = None,
) -> HexgateLangchainAgent:
    """Wrap a pre-built LangGraph agent with Hexgate policy enforcement.

    Mutates ``tools`` in place so the graph keeps its references.
    The returned proxy takes ``hexgate_context`` per invocation; role resolves at
    call time from the active :class:`HexgateContext`. ``api_key`` falls back to
    ``HEXGATE_API_KEY``. ``NEEDS_APPROVAL`` outcomes render as structured
    errors — wire any host-side approval flow outside the SDK. ``guards`` is a flat
    list of guards authored with ``@before_tool`` / ``@after_tool``; they wrap each
    tool in place alongside the policy (``guard_observer`` receives their provenance
    events). The enforced policy is the platform's; unlisted tools are denied.
    """
    resolved_key = resolve_api_key(api_key)
    if not resolved_key:
        raise ValueError(
            "No API key provided. Pass api_key= explicitly or set the HEXGATE_API_KEY environment variable."
        )

    agent_name = getattr(agent, "name", "default")
    tool_names = [tool.name for tool in tools]

    # One client shared by the policy and ban resolvers — avoids a second
    # biscuit verify + JWKS round-trip per wrapped agent.
    client = HexgateClient(HexgateConfig.from_env(api_key=resolved_key))
    resolved = resolve_policy(agent_name, api_key=resolved_key, client=client)
    enforcer = build_enforcer(
        resolved.engine, agent_name=agent_name, api_key=resolved_key
    )
    pipeline = build_pipeline(guards, observer=guard_observer)
    install_enforcer_on_tools(tools, enforcer=enforcer, pipeline=pipeline)

    return HexgateLangchainAgent(
        agent=agent,
        api_key=resolved_key,
        agent_name=agent_name,
        tool_names=tool_names,
        binding=PolicyBinding(enforcer, resolved.source),
        ban_gate=resolve_ban_gate(agent_name, api_key=resolved_key, client=client),
    )
