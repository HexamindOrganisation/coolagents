"""Behavioural companion to ``test_run_scope_coverage``.

Where those assert a ``run_scope(`` call exists, these assert what it does when an
adapter runs: one run id per invocation, a fresh one next time, none when the run
was refused, none on the entry points that bypass the wrapper.

Uses the langchain proxy since it needs no framework fixture — a recording graph
stand-in runs in the same context a guarded tool would.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Iterator

import pytest

from hexgate.adapters.langchain.agent import HexgateLangchainAgent
from hexgate.runtime import HexgateContext
from hexgate.runtime.run_facts import DETACHED, get_run_facts
from hexgate.security.bans import BanEntry, BanGate, BanSet
from hexgate.security.errors import AgentBannedError

_AGENT_NAME = "run-scope-probe"


def _context() -> HexgateContext:
    return HexgateContext(user_id="u-1", session_id="s-1", user_roles=["developer"])


class _FactsRecordingGraph:
    """Stands in for the compiled graph, capturing the facts it ran under — what a
    guarded tool would see, since the body runs inside the proxy's scope."""

    name = "facts-recording-graph"

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str]] = []

    def _capture(self, method: str) -> None:
        facts = get_run_facts()
        self.seen.append((method, facts.id, facts.agent))

    @property
    def run_ids(self) -> list[str]:
        return [run_id for _, run_id, _ in self.seen]

    def invoke(self, payload: dict[str, Any], config: Any, **_: Any) -> dict[str, Any]:
        self._capture("invoke")
        return {"messages": ["ok"]}

    async def ainvoke(
        self, payload: dict[str, Any], config: Any, **_: Any
    ) -> dict[str, Any]:
        self._capture("ainvoke")
        return {"messages": ["ok"]}

    def stream(
        self, payload: dict[str, Any], config: Any, **_: Any
    ) -> Iterator[dict[str, Any]]:
        self._capture("stream")
        yield {"chunk": 1}
        self._capture("stream")
        yield {"chunk": 2}

    async def astream(
        self, payload: dict[str, Any], config: Any, **_: Any
    ) -> AsyncIterator[dict[str, Any]]:
        self._capture("astream")
        yield {"chunk": 1}
        self._capture("astream")
        yield {"chunk": 2}

    def batch(self, payloads: list[dict[str, Any]], **_: Any) -> list[dict[str, Any]]:
        """Reached through ``__getattr__`` — deliberately unwrapped."""
        self._capture("batch")
        return [{"messages": ["ok"]}]


def _proxy(graph: _FactsRecordingGraph, ban_gate: BanGate | None = None):
    return HexgateLangchainAgent(
        agent=graph,
        api_key="k",
        tool_names=[],
        agent_name=_AGENT_NAME,
        ban_gate=ban_gate,
    )


def _banning_gate() -> BanGate:
    entry = BanEntry(
        ban_id="b1",
        ban_type="agent",
        target_agent_name=_AGENT_NAME,
        target_user_id=None,
        reason="disabled",
    )
    return BanGate(_AGENT_NAME, _StaticBanSource(BanSet({_AGENT_NAME: entry}, {})))


class _StaticBanSource:
    def __init__(self, bans: BanSet) -> None:
        self._bans = bans

    def fetch(self) -> BanSet:
        return self._bans


def test_sync_invocation_runs_under_a_named_run() -> None:
    graph = _FactsRecordingGraph()
    _proxy(graph).invoke({"messages": []}, hexgate_context=_context())

    ((method, run_id, agent),) = graph.seen
    assert method == "invoke"
    assert run_id  # a real id, not the detached ""
    assert agent == _AGENT_NAME


@pytest.mark.asyncio
async def test_async_invocation_runs_under_a_named_run() -> None:
    graph = _FactsRecordingGraph()
    await _proxy(graph).ainvoke({"messages": []}, hexgate_context=_context())

    assert graph.seen[0][0] == "ainvoke"
    assert graph.run_ids[0]


def test_each_invocation_gets_a_distinct_run_id() -> None:
    """Catches a scope opened once at construction instead of per call."""
    graph = _FactsRecordingGraph()
    proxy = _proxy(graph)

    proxy.invoke({"messages": []}, hexgate_context=_context())
    proxy.invoke({"messages": []}, hexgate_context=_context())

    first, second = graph.run_ids
    assert first and second
    assert first != second


def test_streaming_keeps_one_run_across_chunks() -> None:
    """One run across every chunk; a per-chunk id would reset a cap mid-stream."""
    graph = _FactsRecordingGraph()
    list(_proxy(graph).stream({"messages": []}, hexgate_context=_context()))

    assert len(graph.run_ids) == 2
    assert len(set(graph.run_ids)) == 1
    assert graph.run_ids[0]


@pytest.mark.asyncio
async def test_async_streaming_keeps_one_run_across_chunks() -> None:
    graph = _FactsRecordingGraph()
    proxy = _proxy(graph)
    async for _ in proxy.astream({"messages": []}, hexgate_context=_context()):
        pass

    assert len(set(graph.run_ids)) == 1
    assert graph.run_ids[0]


def test_scope_closes_after_the_invocation() -> None:
    graph = _FactsRecordingGraph()
    _proxy(graph).invoke({"messages": []}, hexgate_context=_context())
    assert get_run_facts() is DETACHED


def test_ban_refusal_opens_no_scope() -> None:
    """A refused invocation is not a run: nothing runs, no facts are minted."""
    graph = _FactsRecordingGraph()
    proxy = _proxy(graph, ban_gate=_banning_gate())

    with pytest.raises(AgentBannedError):
        proxy.invoke({"messages": []}, hexgate_context=_context())

    assert graph.seen == []
    assert get_run_facts() is DETACHED


def test_bypassed_methods_run_detached() -> None:
    """``batch`` reaches the graph through ``__getattr__``, so it gets neither the
    ban gate nor a scope. Pinned so the bypass stays known."""
    graph = _FactsRecordingGraph()
    _proxy(graph).batch([{"messages": []}])

    ((method, run_id, agent),) = graph.seen
    assert method == "batch"
    assert run_id == ""  # DETACHED
    assert agent == ""
