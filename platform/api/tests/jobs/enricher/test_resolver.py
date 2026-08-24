"""resolver.py — per-poll agent_version_id resolution."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from hexgate_api.jobs.enricher import resolver


@pytest.fixture
def stub_lookups(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Replace the session factory and the lookup; record every call."""
    calls: list[tuple[str, str]] = []

    @asynccontextmanager
    async def _fake_session_factory():
        yield object()

    async def _fake_lookup(_session, project_id: str, agent_name: str) -> str:
        calls.append((project_id, agent_name))
        return "" if agent_name == "ghost" else f"ver_{agent_name}"

    monkeypatch.setattr(resolver, "async_session_factory", _fake_session_factory)
    monkeypatch.setattr(resolver, "get_latest_agent_version_id", _fake_lookup)
    return calls


async def test_resolve_versions_happy_path(stub_lookups) -> None:
    versions = await resolver.resolve_versions({("p1", "researcher"), ("p2", "coder")})
    assert versions == {
        ("p1", "researcher"): "ver_researcher",
        ("p2", "coder"): "ver_coder",
    }


async def test_when_agent_is_unknown_then_empty_string(stub_lookups) -> None:
    versions = await resolver.resolve_versions({("p1", "ghost")})
    assert versions == {("p1", "ghost"): ""}


async def test_resolve_versions_queries_each_pair_once(stub_lookups) -> None:
    await resolver.resolve_versions({("p1", "a"), ("p1", "b"), ("p2", "a")})
    assert len(stub_lookups) == 3
    assert len(set(stub_lookups)) == 3


async def test_when_there_are_no_pairs_then_no_session_is_opened(stub_lookups) -> None:
    assert await resolver.resolve_versions(set()) == {}
    assert stub_lookups == []
