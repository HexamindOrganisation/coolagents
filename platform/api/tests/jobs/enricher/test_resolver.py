"""resolver.py — per-poll agent_version_id resolution."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from hexgate_api.jobs.enricher import resolver


class _FakeSession:
    """Answers the agents query with a pre-registered list; counts execs."""

    def __init__(self, agents: list[SimpleNamespace]) -> None:
        self.agents = agents
        self.execs = 0

    async def exec(self, _stmt):
        self.execs += 1
        return SimpleNamespace(all=lambda: self.agents)


@pytest.fixture
def stub_store(monkeypatch: pytest.MonkeyPatch):
    """A fake session factory over registered agents, plus a stubbed
    versions-map lookup; returns (factory, session, map_calls)."""
    map_calls: list[list[str]] = []

    def _make(agents: list[SimpleNamespace]):
        session = _FakeSession(agents)

        @asynccontextmanager
        async def _factory():
            yield session

        async def _fake_versions_map(_session, agent_ids: list[str]):
            map_calls.append(agent_ids)
            # Every registered agent has one version, ver_<agent_id>.
            return {
                agent_id: SimpleNamespace(id=f"ver_{agent_id}")
                for agent_id in agent_ids
            }

        monkeypatch.setattr(
            resolver, "get_latest_agent_versions_map", _fake_versions_map
        )
        return _factory, session, map_calls

    return _make


def _agent(agent_id: str, project_id: str, name: str) -> SimpleNamespace:
    return SimpleNamespace(id=agent_id, project_id=project_id, name=name)


async def test_resolve_versions_happy_path(stub_store) -> None:
    factory, _session, _map_calls = stub_store(
        [_agent("a1", "p1", "researcher"), _agent("a2", "p2", "coder")]
    )
    versions = await resolver.resolve_versions(
        {("p1", "researcher"), ("p2", "coder")}, session_factory=factory
    )
    assert versions == {
        ("p1", "researcher"): "ver_a1",
        ("p2", "coder"): "ver_a2",
    }


async def test_when_agent_is_unknown_then_empty_string(stub_store) -> None:
    factory, _session, _map_calls = stub_store([])
    versions = await resolver.resolve_versions(
        {("p1", "ghost")}, session_factory=factory
    )
    assert versions == {("p1", "ghost"): ""}


async def test_resolve_versions_issues_two_queries_regardless_of_pairs(
    stub_store,
) -> None:
    factory, session, map_calls = stub_store(
        [_agent("a1", "p1", "a"), _agent("a2", "p1", "b"), _agent("a3", "p2", "a")]
    )
    await resolver.resolve_versions(
        {("p1", "a"), ("p1", "b"), ("p2", "a")}, session_factory=factory
    )
    assert session.execs == 1  # one agents lookup
    assert map_calls == [["a1", "a2", "a3"]]  # one batched versions lookup


async def test_when_there_are_no_pairs_then_no_session_is_opened(stub_store) -> None:
    factory, session, _map_calls = stub_store([])
    assert await resolver.resolve_versions(set(), session_factory=factory) == {}
    assert session.execs == 0
