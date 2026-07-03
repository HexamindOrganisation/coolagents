"""Register example code-defined research agents with approval-gated writes."""

from __future__ import annotations

import sys
from pathlib import Path

from hexgate import AgentPolicy, create_agent, enforce_policy, register_agent
from hexgate.tools import edit_file, glob, grep, read_file, write_file

# web_search / fetch are vendor-bound demo tools that ship in examples/, not the
# SDK core. Anchor the import to this file's dir so it resolves however the
# script is launched (`python examples/research_agents.py` or `--use`).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tools.fetch import fetch  # noqa: E402
from tools.websearch import web_search  # noqa: E402


def _update_researcher_policy() -> AgentPolicy:
    """Return the policy for a research agent that can inspect freely but must ask to write."""
    return AgentPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"mode": "deny"},
            "tools": {
                "web_search": {"mode": "allow"},
                "fetch": {"mode": "allow"},
                "glob": {"mode": "allow"},
                "grep": {"mode": "allow"},
                "read_file": {"mode": "allow"},
                "write_file": {
                    "mode": "approval_required",
                    "file_scope": {"allowed_paths": ["research_notes/*.md"]},
                },
                "edit_file": {
                    "mode": "approval_required",
                    "file_scope": {"allowed_paths": ["research_notes/*.md"]},
                },
            },
        }
    )


def build_update_researcher(
    *,
    base_dir: str | Path | None = None,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
    extra_tools: dict[str, object] | None = None,
    model: str | None = None,
):
    """Build a research-first agent that can gather sources and update local files carefully."""
    _ = base_dir
    _ = user_id
    tools = [web_search, fetch, glob, grep, read_file, write_file, edit_file]
    if extra_tools:
        tools.extend(tool for tool in extra_tools.values() if tool not in tools)

    agent, handler = create_agent(
        model=model or "gpt-5.4",
        tools=tools,
        system_prompt=(
            "You are an update researcher. Start with web_search and fetch to gather fresh "
            "information, then inspect local files with glob, grep, and read_file before "
            "proposing or applying updates. Prepare careful, source-backed changes and use "
            "write_file and edit_file only when an update is truly needed."
        ),
        session_id=session_id,
        tags=tags or ["hexgate", "update-researcher"],
    )
    return enforce_policy(agent, _update_researcher_policy()), handler


register_agent("update_researcher", build_update_researcher)
