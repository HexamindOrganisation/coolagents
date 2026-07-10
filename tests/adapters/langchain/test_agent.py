"""Tests for the HexgateLangchainAgent proxy."""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Iterator
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, LLMResult

from hexgate.adapters.langchain.agent import HexgateLangchainAgent
from hexgate.adapters.langchain.usage import HexgateUsageCallbackHandler
from hexgate.runtime import User
from hexgate.runtime.context import get_current_user
from hexgate.security.bans import BanEntry, BanGate, BanSet
from hexgate.security.errors import AgentBannedError
from hexgate.tracing import usage as usage_mod


def _user() -> User:
    """Build a minimal User for invocation tests."""
    return User(user_id="u-1", session_id="s-1", role="developer")


class _StaticBanSource:
    """A BanSource that always returns a fixed BanSet (no network)."""

    def __init__(self, bans: BanSet) -> None:
        self._bans = bans

    def fetch(self) -> BanSet:
        return self._bans


def _agent_ban_gate(agent_name: str, banned: str | None = None) -> BanGate:
    """Gate for ``agent_name`` whose source bans ``banned`` (default: itself;
    pass a different value for passthrough tests)."""
    banned = banned or agent_name
    entry = BanEntry(
        ban_id="b1",
        ban_type="agent",
        target_agent_name=banned,
        target_user_id=None,
        reason="disabled",
    )
    return BanGate(agent_name, _StaticBanSource(BanSet({banned: entry}, {})))


class _RecordingGraph:
    """Capture the active User and config seen by each invocation method."""

    name = "recording-graph"

    def __init__(self) -> None:
        self.invoke_calls: list[dict[str, Any]] = []
        self.ainvoke_calls: list[dict[str, Any]] = []
        self.stream_calls: list[dict[str, Any]] = []
        self.astream_calls: list[dict[str, Any]] = []
        self.astream_events_calls: list[dict[str, Any]] = []

    def _snapshot(self, payload: dict[str, Any], config: Any) -> dict[str, Any]:
        """Capture the active User plus call arguments."""
        return {
            "user": get_current_user(),
            "input": payload,
            "config": config,
        }

    def invoke(
        self, payload: dict[str, Any], config: Any, **_kwargs: Any
    ) -> dict[str, Any]:
        """Record sync invocation arguments."""
        self.invoke_calls.append(self._snapshot(payload, config))
        return {"messages": ["sync-ok"]}

    async def ainvoke(
        self, payload: dict[str, Any], config: Any, **_kwargs: Any
    ) -> dict[str, Any]:
        """Record async invocation arguments."""
        self.ainvoke_calls.append(self._snapshot(payload, config))
        return {"messages": ["async-ok"]}

    def stream(
        self, payload: dict[str, Any], config: Any, **_kwargs: Any
    ) -> Iterator[dict[str, Any]]:
        """Yield two chunks while exposing the active User via capture."""
        self.stream_calls.append(self._snapshot(payload, config))
        yield {"chunk": 1}
        yield {"chunk": 2}

    async def astream(
        self, payload: dict[str, Any], config: Any, **_kwargs: Any
    ) -> AsyncIterator[dict[str, Any]]:
        """Async-yield two chunks."""
        self.astream_calls.append(self._snapshot(payload, config))
        yield {"chunk": 1}
        yield {"chunk": 2}

    async def astream_events(
        self,
        payload: dict[str, Any],
        config: Any = None,
        *,
        version: str = "v2",
        **_kwargs: Any,
    ) -> AsyncIterator[dict[str, Any]]:
        """Async-yield two events, also recording the requested version.

        Mirrors langgraph's real signature — ``config`` positional, ``version``
        keyword-only — so forwarding ``version`` positionally (the original
        bug) would bind it to ``config`` and fail this test."""
        snapshot = self._snapshot(payload, config)
        snapshot["version"] = version
        self.astream_events_calls.append(snapshot)
        yield {"event": "start"}
        yield {"event": "end"}

    def some_attribute(self) -> str:
        """Arbitrary attribute used to verify __getattr__ delegation."""
        return "delegated"


# ---------------------------------------------------------------------------
# Callbacks plumbing
# ---------------------------------------------------------------------------


def test_with_callbacks_appends_handlers_to_empty_config() -> None:
    proxy = HexgateLangchainAgent(agent=_RecordingGraph(), api_key="k", tool_names=[])

    merged = proxy._with_callbacks(None)

    assert proxy._callback_handler in merged["callbacks"]
    assert proxy._usage_handler in merged["callbacks"]
    assert len(merged["callbacks"]) == 2


def test_with_callbacks_preserves_existing_callbacks() -> None:
    proxy = HexgateLangchainAgent(agent=_RecordingGraph(), api_key="k", tool_names=[])
    sentinel = object()

    merged = proxy._with_callbacks({"callbacks": [sentinel]})

    assert merged["callbacks"][0] is sentinel
    assert merged["callbacks"][1] is proxy._callback_handler
    assert merged["callbacks"][2] is proxy._usage_handler


def test_with_callbacks_does_not_double_register_handlers() -> None:
    proxy = HexgateLangchainAgent(agent=_RecordingGraph(), api_key="k", tool_names=[])

    merged_once = proxy._with_callbacks(None)
    merged_twice = proxy._with_callbacks(merged_once)

    assert merged_twice["callbacks"].count(proxy._callback_handler) == 1
    assert merged_twice["callbacks"].count(proxy._usage_handler) == 1


# ---------------------------------------------------------------------------
# User scope binding per invocation method
# ---------------------------------------------------------------------------


def test_invoke_opens_user_scope_and_delegates() -> None:
    """The active User contextvar is live during the wrapped invoke."""
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])
    user = _user()

    assert get_current_user() is None

    result = proxy.invoke({"input": "hi"}, user=user)

    assert result == {"messages": ["sync-ok"]}
    [call] = graph.invoke_calls
    assert call["user"] is user
    assert call["input"] == {"input": "hi"}
    assert proxy._callback_handler in call["config"]["callbacks"]
    # Scope unwound after the call.
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_ainvoke_opens_user_scope_and_delegates() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])
    user = _user()

    result = await proxy.ainvoke({"input": "hi"}, user=user)

    assert result == {"messages": ["async-ok"]}
    [call] = graph.ainvoke_calls
    assert call["user"] is user
    assert proxy._callback_handler in call["config"]["callbacks"]
    assert get_current_user() is None


def test_stream_opens_user_scope_and_yields_chunks() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])
    user = _user()

    chunks = list(proxy.stream({"input": "hi"}, user=user))

    assert chunks == [{"chunk": 1}, {"chunk": 2}]
    [call] = graph.stream_calls
    assert call["user"] is user
    assert proxy._callback_handler in call["config"]["callbacks"]
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_astream_opens_user_scope_and_yields_chunks() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])
    user = _user()

    chunks = [chunk async for chunk in proxy.astream({"input": "hi"}, user=user)]

    assert chunks == [{"chunk": 1}, {"chunk": 2}]
    [call] = graph.astream_calls
    assert call["user"] is user
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_astream_events_forwards_version_and_opens_scope() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])
    user = _user()

    events = [
        evt
        async for evt in proxy.astream_events({"input": "hi"}, version="v2", user=user)
    ]

    assert events == [{"event": "start"}, {"event": "end"}]
    [call] = graph.astream_events_calls
    assert call["version"] == "v2"
    assert call["config"] is not None  # version did not leak into the config slot
    assert call["user"] is user
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_astream_events_defaults_version_to_v2() -> None:
    """version is keyword-only with a 'v2' default, mirroring base langchain."""
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=["echo"])

    _ = [evt async for evt in proxy.astream_events({"input": "hi"}, user=_user())]

    [call] = graph.astream_events_calls
    assert call["version"] == "v2"


def test_user_scope_is_unwound_when_invoke_raises() -> None:
    """The contextvar unwinds even when the wrapped agent raises."""

    class BoomGraph:
        name = "boom"

        def invoke(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

    proxy = HexgateLangchainAgent(agent=BoomGraph(), api_key="k", tool_names=[])

    with pytest.raises(RuntimeError, match="boom"):
        proxy.invoke({"input": "hi"}, user=_user())

    assert get_current_user() is None


# ---------------------------------------------------------------------------
# Kill-switch ban gate
# ---------------------------------------------------------------------------


def test_invoke_refused_before_graph_runs_when_banned() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(
        agent=graph,
        api_key="k",
        tool_names=["echo"],
        ban_gate=_agent_ban_gate(graph.name),
    )

    with pytest.raises(AgentBannedError) as exc:
        proxy.invoke({"input": "hi"}, user=_user())

    assert exc.value.code == "agent_banned"
    assert graph.invoke_calls == []  # graph never ran
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_astream_raises_before_first_chunk_when_banned() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(
        agent=graph,
        api_key="k",
        tool_names=["echo"],
        ban_gate=_agent_ban_gate(graph.name),
    )

    agen = proxy.astream({"input": "hi"}, user=_user())
    with pytest.raises(AgentBannedError):
        await agen.__anext__()
    assert graph.astream_calls == []  # no chunk yielded


def test_not_banned_passes_through() -> None:
    """A gate that bans a different agent must not block this one."""
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(
        agent=graph,
        api_key="k",
        tool_names=["echo"],
        ban_gate=_agent_ban_gate(graph.name, banned="some-other-agent"),
    )

    result = proxy.invoke({"input": "hi"}, user=_user())

    assert result == {"messages": ["sync-ok"]}
    assert len(graph.invoke_calls) == 1


# ---------------------------------------------------------------------------
# __getattr__ delegation
# ---------------------------------------------------------------------------


def test_proxy_delegates_unknown_attributes_to_wrapped_agent() -> None:
    graph = _RecordingGraph()
    proxy = HexgateLangchainAgent(agent=graph, api_key="k", tool_names=[])

    assert proxy.some_attribute() == "delegated"
    assert proxy.name == "recording-graph"


# ---------------------------------------------------------------------------
# Usage handler: User contextvar survives into on_llm_end
# ---------------------------------------------------------------------------


class _FakeSender:
    """Stand in for the AuditSender the usage handler emits through."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


def _fake_llm_result(input_tokens: int = 10, output_tokens: int = 20) -> LLMResult:
    message = AIMessage(
        content="hi",
        usage_metadata={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
    )
    return LLMResult(
        generations=[[ChatGeneration(message=message)]],
        llm_output={"model_name": "gpt-4o"},
    )


class _CallbackFiringGraph:
    """Fires on_llm_end on every HexgateUsageCallbackHandler in the config,
    the way LangGraph fires it on real chat-model completion — from inside
    the same call, not a detached task."""

    name = "graph"

    async def _afire(self, config: Any) -> None:
        for handler in (config or {}).get("callbacks", []):
            if isinstance(handler, HexgateUsageCallbackHandler):
                await handler.on_llm_end(_fake_llm_result(), run_id=uuid4())

    def invoke(self, input: dict, config: Any = None, **kwargs: Any) -> dict:
        asyncio.run(self._afire(config))
        return {"ok": True}

    async def ainvoke(self, input: dict, config: Any = None, **kwargs: Any) -> dict:
        await self._afire(config)
        return {"ok": True}


@pytest.mark.asyncio
async def test_usage_handler_context_propagates_through_ainvoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_current_user() must still resolve inside on_llm_end, called from
    wherever LangGraph actually invokes it within the ainvoke call tree —
    the User scope opened around _agent.ainvoke must still be live there."""
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )
    proxy = HexgateLangchainAgent(
        agent=_CallbackFiringGraph(), api_key="k", agent_name="my-agent", tool_names=[]
    )
    user = _user()

    await proxy.ainvoke({"input": "hi"}, user=user)

    [event] = fake_sender.events
    assert event.agent_name == "my-agent"
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
    assert event.input_tokens == 10
    assert event.output_tokens == 20


def test_usage_handler_context_propagates_through_sync_invoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same guarantee on the sync path (user.sync_scope())."""
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )
    proxy = HexgateLangchainAgent(
        agent=_CallbackFiringGraph(), api_key="k", agent_name="my-agent", tool_names=[]
    )

    proxy.invoke({"input": "hi"}, user=_user())

    [event] = fake_sender.events
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
