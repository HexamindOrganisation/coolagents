"""Runtime-scoped context and workspace helpers."""

from hexgate.runtime.command_policy import (
    ALWAYS_REJECTED,
    FILE_OPS_COMMANDS,
    MINIMAL_COMMANDS,
    SHELL_BUILTINS,
    Allowed,
    CommandPolicyResult,
    Rejected,
    check_command,
)
from hexgate.runtime.context import (
    ContextAttributeValue,
    HexgateContext,
    ToolUseContext,
    get_current_context,
    get_current_tool_use_context,
    reset_current_tool_use_context,
    set_current_tool_use_context,
)
from hexgate.runtime.roles import (
    MAX_EVALUATED_ROLES,
    distinct_roles,
    resolve_role_set,
)
from hexgate.runtime.sandbox_runtime import build_sandbox_runtime_config
from hexgate.runtime.srt import (
    SrtUnavailableError,
    ensure_srt_available,
    find_srt,
    srt_version,
)
from hexgate.runtime.workspace import CommandResult, LocalWorkspace, Workspace

__all__ = [
    "ALWAYS_REJECTED",
    "Allowed",
    "CommandPolicyResult",
    "CommandResult",
    "FILE_OPS_COMMANDS",
    "LocalWorkspace",
    "MAX_EVALUATED_ROLES",
    "MINIMAL_COMMANDS",
    "Rejected",
    "SHELL_BUILTINS",
    "ContextAttributeValue",
    "HexgateContext",
    "SrtUnavailableError",
    "ToolUseContext",
    "Workspace",
    "build_sandbox_runtime_config",
    "check_command",
    "distinct_roles",
    "ensure_srt_available",
    "find_srt",
    "get_current_context",
    "get_current_tool_use_context",
    "reset_current_tool_use_context",
    "resolve_role_set",
    "set_current_tool_use_context",
    "srt_version",
]
