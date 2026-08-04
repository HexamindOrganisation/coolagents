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
    register_agent_factory,
    unregister_agent_factory,
)
from hexgate.cloud import HexgateClient, HexgateConfig
from hexgate.manifest import AgentManifest, create_manifest
from hexgate.runtime import HexgateContext, LocalWorkspace, ToolUseContext, Workspace
from hexgate.security import (
    AgentPolicy,
    C,
    PolicyBuilder,
    RolePolicyBuilder,
    assert_allows,
    assert_denies,
    assert_needs_approval,
)
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
    "C",
    "PolicyBuilder",
    "RolePolicyBuilder",
    "assert_allows",
    "assert_denies",
    "assert_needs_approval",
    "HexgateClient",
    "HexgateConfig",
    "HexgateContext",
    "LocalWorkspace",
    "ToolUseContext",
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
    "register_agent_factory",
    "read_file",
    "stream_agent",
    "stream_agent_raw",
    "unregister_agent_factory",
    "write_file",
]


def __getattr__(name: str) -> object:
    from hexgate.tools._relocated import RELOCATED_TOOLS, relocated_import_error

    if name in RELOCATED_TOOLS:
        raise relocated_import_error(name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
