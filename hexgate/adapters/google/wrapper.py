"""Google ADK adapter: resolve the platform policy, construct one
:class:`PolicyEnforcer`, and return a clone of the agent whose tools
are policy-gated. HexgateContext-agnostic at wrap time — role resolution happens
inside the enforcer via the :class:`HexgateContext` contextvar.

Policy is resolved from the platform at wrap time (fail-loud on a 404 —
register the agent first with ``hexgate register``); the returned binding
is what the runner refreshes per run.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from google.adk.agents import BaseAgent

from hexgate.adapters.google.tools import wrap_tools
from hexgate.approvals import ApprovalHandler
from hexgate.guards.types import build_pipeline
from hexgate.security.binding import PolicyBinding, resolve_policy
from hexgate.security.enforcer import build_enforcer

if TYPE_CHECKING:
    from hexgate.cloud.client import HexgateClient
    from hexgate.guards.types import Guard, GuardObserver


def wrap_google_agent(
    agent: BaseAgent,
    *,
    api_key: str,
    approval_handler: ApprovalHandler | None = None,
    client: HexgateClient | None = None,
    guards: Sequence[Guard] | None = None,
    guard_observer: GuardObserver | None = None,
) -> tuple[BaseAgent, PolicyBinding]:
    """Return a policy-gated clone of ``agent`` plus its refresh binding.

    Caller must open a :class:`HexgateContext` scope around the run.
    ``NEEDS_APPROVAL`` outcomes fire ``approval_handler`` (async
    ``fn(decision) -> bool`` or ``bool`` shorthand); a truthy return
    runs the tool, falsy or missing handler surfaces the
    ``[approval_required]``-prefixed string as tool result.
    ``[policy_denied]`` marks plain denials. Refresh the returned
    binding at run boundaries (``HexgateRunner`` does). Fail-loud: an
    unregistered agent (platform 404) raises — register it first with
    ``hexgate register``.
    """
    agent_name = getattr(agent, "name", "default")
    tools = list(getattr(agent, "tools", []) or [])

    resolved = resolve_policy(agent_name, api_key=api_key, client=client)
    enforcer = build_enforcer(resolved.engine, agent_name=agent_name, api_key=api_key)
    pipeline = build_pipeline(guards, observer=guard_observer)
    guarded_tools = wrap_tools(
        tools, enforcer, approval_handler=approval_handler, pipeline=pipeline
    )
    return (
        agent.model_copy(update={"tools": guarded_tools}),
        PolicyBinding(enforcer, resolved.source),
    )
