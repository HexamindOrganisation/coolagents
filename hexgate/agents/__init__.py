"""Public surface for the agents package — factory, policy enforcement, loaders."""

from hexgate.agents.factory import (
    create_agent,
    enforce_policy,
    invoke_agent,
    stream_agent,
    stream_agent_raw,
)
from hexgate.agents.loader import (
    clear_registered_agents,
    list_available_agents,
    list_local_agents,
    list_registered_agents,
    load_agent,
    load_hexgate_agent,
    load_local_agent,
    load_local_agent_policy,
    load_local_agent_spec,
    load_registered_agent,
    register_agent_factory,
    resolve_agent_source,
    resolve_tools,
    unregister_agent_factory,
)
from hexgate.agents.models import AgentSpec

__all__ = [
    "AgentSpec",
    "clear_registered_agents",
    "create_agent",
    "enforce_policy",
    "invoke_agent",
    "list_available_agents",
    "list_local_agents",
    "list_registered_agents",
    "load_agent",
    "load_hexgate_agent",
    "load_local_agent",
    "load_local_agent_policy",
    "load_local_agent_spec",
    "load_registered_agent",
    "register_agent_factory",
    "resolve_agent_source",
    "resolve_tools",
    "stream_agent",
    "stream_agent_raw",
    "unregister_agent_factory",
]
