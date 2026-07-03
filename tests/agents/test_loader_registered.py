"""Tests for registered code-defined agents."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hexgate.agents import loader


@pytest.fixture(autouse=True)
def clear_registry() -> None:
    """Reset the code agent registry around each test."""
    loader.clear_registered_agents()


def test_list_registered_agents_tracks_registered_ids() -> None:
    """List code-defined agents after registration."""

    def factory(**_kwargs: Any) -> tuple[str, str]:
        """Return fake runtime pieces."""
        return "agent", "handler"

    loader.register_agent_factory("code_agent", factory)

    assert loader.list_registered_agents() == ["code_agent"]


def test_resolve_agent_source_resolves_registered_when_no_local(
    tmp_path: Path,
) -> None:
    """Resolve registered agents when no local agent shadows the id."""

    def factory(**_kwargs: Any) -> tuple[str, str]:
        """Return fake runtime pieces."""
        return "agent", "handler"

    loader.register_agent_factory("code_agent", factory)

    assert loader.resolve_agent_source("code_agent", tmp_path) == "registered"


def test_load_registered_agent_passes_runtime_overrides_through() -> None:
    """Load a code-defined agent through the shared loader API."""
    captured: dict[str, Any] = {}

    def factory(**kwargs: Any) -> tuple[str, str]:
        """Capture the loader kwargs and return fake instances."""
        captured.update(kwargs)
        return "agent-instance", "handler-instance"

    loader.register_agent_factory("code_agent", factory)

    agent, handler = loader.load_agent(
        "code_agent",
        model="openai:gpt-5.4",
        session_id="s-1",
        tags=["hexgate"],
    )

    assert (agent, handler) == ("agent-instance", "handler-instance")
    assert captured["model"] == "openai:gpt-5.4"
    assert captured["session_id"] == "s-1"
    assert captured["tags"] == ["hexgate"]


def test_list_available_agents_includes_registered_ids() -> None:
    """Merge registered code agents into the available agent view."""

    def factory(**_kwargs: Any) -> tuple[str, str]:
        """Return fake runtime pieces."""
        return "agent", "handler"

    loader.register_agent_factory("code_agent", factory)

    assert "code_agent" in loader.list_available_agents()
