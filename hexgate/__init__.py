"""Public package surface for hexgate."""

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
    load_registered_agent,
    register_agent,
    unregister_agent,
)
from hexgate.cli.register import AgentManifest, create_manifest
from hexgate.cloud import HexgateClient, HexgateConfig
from hexgate.runtime import LocalWorkspace, ToolUseContext, User, Workspace
from hexgate.security import AgentPolicy
from hexgate.tools import (
    agent_tool,
    bash,
    edit_file,
    glob,
    grep,
    read_file,
    write_file,
)

__all__ = [
    "AgentManifest",
    "AgentPolicy",
    "HexgateClient",
    "HexgateConfig",
    "LocalWorkspace",
    "ToolUseContext",
    "User",
    "Workspace",
    "agent_tool",
    "bash",
    "edit_file",
    "clear_registered_agents",
    "create_agent",
    "create_manifest",
    "enforce_policy",
    "glob",
    "grep",
    "invoke_agent",
    "list_available_agents",
    "list_local_agents",
    "list_registered_agents",
    "load_agent",
    "load_hexgate_agent",
    "load_local_agent",
    "load_registered_agent",
    "register_agent",
    "read_file",
    "stream_agent",
    "stream_agent_raw",
    "unregister_agent",
    "write_file",
]
