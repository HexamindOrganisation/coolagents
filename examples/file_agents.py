"""Register example code-defined agents built around file/search tools."""

from __future__ import annotations

from pathlib import Path

from hexgate import AgentPolicy, create_agent, enforce_policy, register_agent_factory
from hexgate.tools import edit_file, glob, grep, read_file, write_file


def _shared_policy() -> AgentPolicy:
    """Return a simple shared policy for example code agents."""
    return AgentPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"mode": "deny"},
            "tools": {
                "glob": {"mode": "allow"},
                "grep": {"mode": "allow"},
                "read_file": {"mode": "allow"},
                "write_file": {"mode": "allow"},
                "edit_file": {"mode": "allow"},
            },
        }
    )


def build_workspace_explorer(
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: dict[str, object] | None = None,
    model: str | None = None,
):
    """Build a code-defined workspace exploration agent without policy concerns."""
    _ = base_dir
    _ = user_id
    tools = [glob, grep, read_file]
    if extra_tools:
        tools.extend(tool for tool in extra_tools.values() if tool not in tools)
    return create_agent(
        model=model or "gpt-5.4",
        tools=tools,
        system_prompt=(
            "You explore codebases and workspaces carefully. "
            "Use glob to find files, grep to search through them, and read_file to inspect "
            "their contents before answering questions about structure or behavior. "
            "Do not propose edits unless the user explicitly asks."
        ),
        session_id=session_id,
        tags=tags or ["hexgate", "workspace-explorer"],
    )


def build_repo_editor(
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: dict[str, object] | None = None,
    model: str | None = None,
):
    """Build a code-defined repository editing agent with hosted policy enforcement."""
    _ = base_dir
    _ = user_id
    tools = [glob, grep, read_file, write_file, edit_file]
    if extra_tools:
        tools.extend(tool for tool in extra_tools.values() if tool not in tools)
    agent, handler = create_agent(
        model=model or "gpt-5.4",
        tools=tools,
        system_prompt=(
            "You are a careful coding assistant operating on the current workspace. "
            "Use glob and grep to navigate, read_file to inspect code, write_file to create "
            "new files, and edit_file for exact replacements. Prefer read-before-edit and "
            "make focused changes."
        ),
        session_id=session_id,
        tags=tags or ["hexgate", "repo-editor"],
    )
    return enforce_policy(agent, _shared_policy()), handler


register_agent_factory("workspace_explorer", build_workspace_explorer)
register_agent_factory("repo_editor", build_repo_editor)
