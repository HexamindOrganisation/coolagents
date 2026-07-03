"""Register example code-defined agents built around file tools plus bash."""

from __future__ import annotations

from pathlib import Path

from hexgate import AgentPolicy, create_agent, enforce_policy, register_agent_factory
from hexgate.runtime import LocalWorkspace
from hexgate.tools import bash, edit_file, glob, grep, read_file, write_file


def _coding_agent_policy() -> AgentPolicy:
    """Return a conservative policy for a coding-style workspace agent."""
    return AgentPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"mode": "deny"},
            "tools": {
                "glob": {"mode": "allow"},
                "grep": {"mode": "allow"},
                "read_file": {"mode": "allow"},
                "write_file": {"mode": "approval_required"},
                "edit_file": {"mode": "approval_required"},
                "bash": {"mode": "approval_required"},
            },
        }
    )


def _build_repo_workspace(base_dir: str | Path | None) -> LocalWorkspace:
    """Build a tightly-scoped sandbox workspace for the repo operator."""
    root = Path(base_dir).expanduser().resolve() if base_dir else Path.cwd()
    return LocalWorkspace(
        root_dir=root,
        # Block the agent from writing common secrets even via bash.
        deny_write_paths=[
            ".env",
            ".env.local",
            ".env.production",
            "secrets/",
            ".git/config",
            ".git/credentials",
        ],
        # Allow bash to reach pypi for `pip install` flows; lock everything else out.
        allowed_domains=[
            "pypi.org",
            "*.pypi.org",
            "files.pythonhosted.org",
        ],
        # Pass a few env knobs the agent's tooling commonly expects.
        extra_env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        },
    )


def build_repo_operator(
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: dict[str, object] | None = None,
    model: str | None = None,
):
    """Build a coding-style agent that can inspect, edit, and run commands carefully."""
    _ = user_id
    tools = [glob, grep, read_file, write_file, edit_file, bash]
    if extra_tools:
        tools.extend(tool for tool in extra_tools.values() if tool not in tools)

    workspace = _build_repo_workspace(base_dir)

    agent, handler = create_agent(
        model=model or "gpt-5.4",
        tools=tools,
        system_prompt=(
            "You are a careful coding assistant operating inside the current workspace. "
            "Use glob and grep to navigate, read_file to inspect code, write_file and "
            "edit_file for focused edits, and bash when command output will help you "
            "verify or explore. Prefer read-before-edit, explain risky actions briefly, "
            "and use bash sparingly when file tools are enough."
        ),
        session_id=session_id,
        tags=tags or ["hexgate", "repo-operator"],
        workspace=workspace,
    )
    return enforce_policy(agent, _coding_agent_policy()), handler


register_agent_factory("repo_operator", build_repo_operator)
