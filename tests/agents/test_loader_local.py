"""Tests for local project agent discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hexgate.agents import loader


def _write_agent_dir(agent_dir: Path, *, name: str) -> None:
    """Create a tiny local agent directory for loader tests."""
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "agent.yaml").write_text(
        "\n".join(
            [
                f"name: {name}",
                "model: gpt-5.4",
                "system_prompt: system.md",
                "tools:",
                "  - read_file",
                "policy: policy.yaml",
            ]
        ),
        encoding="utf-8",
    )
    (agent_dir / "policy.yaml").write_text(
        "\n".join(
            [
                "version: 1",
                "default_policy:",
                "  mode: deny",
                "tools:",
                "  read_file:",
                "    mode: allow",
            ]
        ),
        encoding="utf-8",
    )
    (agent_dir / "system.md").write_text(
        "You are a local test agent.", encoding="utf-8"
    )


def test_list_local_agents_reads_root_level_agent_dirs(tmp_path: Path) -> None:
    """Discover local agents defined directly under the project root."""
    _write_agent_dir(tmp_path / "example_agent", name="example_agent")

    assert loader.list_local_agents(tmp_path) == ["example_agent"]


def test_list_local_agents_reads_agents_subdirectory(tmp_path: Path) -> None:
    """Discover local agents defined under ./agents."""
    _write_agent_dir(tmp_path / "agents" / "project_agent", name="project_agent")

    assert loader.list_local_agents(tmp_path) == ["project_agent"]


def test_resolve_agent_source_resolves_local(tmp_path: Path) -> None:
    """Resolve an on-disk agent dir to the ``local`` source."""
    _write_agent_dir(tmp_path / "example_agent", name="example_agent")

    assert loader.resolve_agent_source("example_agent", tmp_path) == "local"


def test_resolve_tools_raises_for_unknown_tools() -> None:
    """Fail clearly when a referenced tool id is unknown."""
    with pytest.raises(KeyError, match='Unknown tool "missing_tool"'):
        loader.resolve_tools(["missing_tool"])


def test_resolve_tools_hints_migration_for_relocated_tools() -> None:
    """A relocated tool (web_search/fetch/refund_order) points at extra_tools."""
    with pytest.raises(KeyError, match="extra_tools"):
        loader.resolve_tools(["web_search"])


def test_load_local_agent_resolves_spec_into_create_agent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Instantiate a local agent by wiring prompt, tools, and policy."""
    _write_agent_dir(tmp_path / "example_agent", name="example_agent")
    captured: dict[str, Any] = {}
    captured_policy: dict[str, Any] = {}

    def fake_create_agent(**kwargs: Any) -> tuple[str, str]:
        """Capture loader kwargs and return fake instances."""
        captured.update(kwargs)
        return "agent-instance", "handler-instance"

    def fake_enforce_policy(
        tools: list[Any],
        policy: Any,
        *,
        approval_handler: Any = None,
        decision_observer: Any = None,
    ) -> list[Any]:
        """Capture policy application while leaving tools unchanged."""
        captured_policy["policy"] = policy
        captured_policy["approval_handler"] = approval_handler
        captured_policy["decision_observer"] = decision_observer
        return tools

    monkeypatch.setattr(loader, "create_agent", fake_create_agent)
    monkeypatch.setattr(loader, "enforce_policy", fake_enforce_policy)

    agent, handler = loader.load_local_agent("example_agent", base_dir=tmp_path)

    assert (agent, handler) == ("agent-instance", "handler-instance")
    assert captured["name"] == "example_agent"
    assert [tool.name for tool in captured["tools"]] == ["read_file"]
    assert "local test agent" in captured["system_prompt"]
    assert captured_policy["policy"].tools["read_file"].mode == "allow"
