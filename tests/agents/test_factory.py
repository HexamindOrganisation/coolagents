"""Tests for agent factory helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from hexgate.agents import factory


class FakeAgent:
    """Provide a tiny async agent for factory tests."""

    def __init__(self) -> None:
        """Initialize call tracking for the fake agent."""
        self.ainvoke_calls: list[dict[str, Any]] = []
        self.astream_event_calls: list[dict[str, Any]] = []

    async def ainvoke(
        self, payload: dict[str, Any], config: dict[str, Any]
    ) -> dict[str, Any]:
        """Record an invoke call and return a fake response."""
        self.ainvoke_calls.append({"payload": payload, "config": config})
        return {"messages": ["ok"]}

    async def astream_events(
        self,
        payload: dict[str, Any],
        config: dict[str, Any],
        *,
        version: str,
    ):
        """Yield two fake raw LangChain stream events."""
        self.astream_event_calls.append(
            {"payload": payload, "config": config, "version": version}
        )
        yield {"event": "one"}
        yield {"event": "two"}


class FakeRequest(BaseModel):
    """Provide a tiny Pydantic request model for agent input tests."""

    messages: list[object]
    thread_id: str | None = None


def test_load_system_prompt_returns_default_inline_prompt() -> None:
    """The default prompt is an inline string, returned as-is."""
    prompt = factory.load_system_prompt(factory.DEFAULT_SYSTEM_PROMPT)

    assert "helpful assistant" in prompt
    assert "tool" in prompt


def test_load_system_prompt_accepts_inline_text() -> None:
    """Return inline prompt text unchanged."""
    prompt = factory.load_system_prompt("You are a direct assistant.")

    assert prompt == "You are a direct assistant."


def test_load_system_prompt_resolves_relative_prompt_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Load prompt contents from a relative file path when requested."""
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("Prompt from file.", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    prompt = factory.load_system_prompt("prompt.txt")

    assert prompt == "Prompt from file."


def test_normalize_input_wraps_plain_query() -> None:
    """Wrap a plain query string into LangChain message state."""
    payload = factory.normalize_input("hello")

    assert payload == {"messages": [{"role": "user", "content": "hello"}]}


def test_normalize_input_preserves_mapping_state() -> None:
    """Leave mapping-based state payloads unchanged."""
    payload = factory.normalize_input(
        {"messages": [{"role": "user", "content": "hello"}], "thread_id": "t-1"}
    )

    assert payload == {
        "messages": [{"role": "user", "content": "hello"}],
        "thread_id": "t-1",
    }


def test_normalize_input_wraps_message_lists() -> None:
    """Treat a top-level message list as LangChain messages state."""
    payload = factory.normalize_input([("user", "hello"), ("assistant", "hi")])

    assert payload == {"messages": [("user", "hello"), ("assistant", "hi")]}


def test_normalize_input_supports_pydantic_models() -> None:
    """Accept a Pydantic request model as agent input."""
    payload = factory.normalize_input(
        FakeRequest(messages=[{"role": "user", "content": "hello"}], thread_id="t-1")
    )

    assert payload == {
        "messages": [{"role": "user", "content": "hello"}],
        "thread_id": "t-1",
    }


def test_extract_input_text_prefers_query_field() -> None:
    """Use an explicit query field when one is present."""
    query = factory.extract_input_text(
        {"query": "hello", "messages": [{"role": "user", "content": "ignored"}]}
    )

    assert query == "hello"


def test_extract_input_text_reads_last_user_message() -> None:
    """Pull the last user message from a message list."""
    query = factory.extract_input_text(
        [
            {"role": "assistant", "content": "hi"},
            {"role": "user", "content": "latest ai news"},
        ]
    )

    assert query == "latest ai news"


def test_create_agent_wires_tools_and_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    """Create the LangChain agent with the expected tools and prompt."""
    calls: dict[str, Any] = {}
    custom_tools = ["tool-one", "tool-two"]

    def fake_create_langchain_agent(**kwargs: Any) -> str:
        """Capture the agent creation kwargs."""
        calls["agent_kwargs"] = kwargs
        return "agent-instance"

    def fake_get_langfuse_handler(**kwargs: Any) -> str:
        """Capture the handler creation kwargs."""
        calls["handler_kwargs"] = kwargs
        return "handler-instance"

    monkeypatch.setattr(factory, "create_langchain_agent", fake_create_langchain_agent)
    monkeypatch.setattr(factory, "get_langfuse_handler", fake_get_langfuse_handler)

    agent, handler = factory.create_agent(
        model="openai:gpt-5.4",
        tools=custom_tools,
        session_id="session-1",
        user_id="user-1",
        tags=["hexgate", "linkup", "openai:gpt-5.4"],
    )

    assert agent._graph == "agent-instance"
    assert handler == "handler-instance"
    assert agent.tools == custom_tools
    assert calls["agent_kwargs"]["model"] == "openai:gpt-5.4"
    assert calls["agent_kwargs"]["tools"] == custom_tools
    assert "helpful assistant" in calls["agent_kwargs"]["system_prompt"]
    assert calls["handler_kwargs"] == {
        "session_id": "session-1",
        "user_id": "user-1",
        "tags": ["hexgate", "linkup", "openai:gpt-5.4"],
    }


@pytest.mark.asyncio
async def test_invoke_agent_passes_messages_and_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invoke the agent with the expected message payload."""
    fake_agent = FakeAgent()
    monkeypatch.setattr(
        factory,
        "get_langfuse_runnable_config",
        lambda handler: {"callbacks": [handler]},
    )

    result = await factory.invoke_agent(fake_agent, "handler", "hello")

    assert result == {"messages": ["ok"]}
    assert fake_agent.ainvoke_calls == [
        {
            "payload": {"messages": [{"role": "user", "content": "hello"}]},
            "config": {"callbacks": ["handler"]},
        }
    ]


@pytest.mark.asyncio
async def test_invoke_agent_accepts_mapping_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass through full mapping state when invoking the agent."""
    fake_agent = FakeAgent()
    monkeypatch.setattr(
        factory,
        "get_langfuse_runnable_config",
        lambda handler: {"callbacks": [handler]},
    )

    result = await factory.invoke_agent(
        fake_agent,
        "handler",
        {"messages": [{"role": "user", "content": "hello"}], "thread_id": "t-1"},
    )

    assert result == {"messages": ["ok"]}
    assert fake_agent.ainvoke_calls == [
        {
            "payload": {
                "messages": [{"role": "user", "content": "hello"}],
                "thread_id": "t-1",
            },
            "config": {"callbacks": ["handler"]},
        }
    ]


@pytest.mark.asyncio
async def test_stream_agent_raw_uses_astream_events_v2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stream raw agent events through LangChain's event stream API."""
    fake_agent = FakeAgent()
    monkeypatch.setattr(
        factory,
        "get_langfuse_runnable_config",
        lambda handler: {"callbacks": [handler]},
    )
    monkeypatch.setattr(factory, "new_root_run_id", lambda: "run-123")

    events = [
        event
        async for event in factory.stream_agent_raw(fake_agent, "handler", "hello")
    ]

    assert events == [{"event": "one"}, {"event": "two"}]
    assert fake_agent.astream_event_calls == [
        {
            "payload": {"messages": [{"role": "user", "content": "hello"}]},
            "config": {"callbacks": ["handler"], "run_id": "run-123"},
            "version": "v2",
        }
    ]


@pytest.mark.asyncio
async def test_stream_agent_raw_accepts_message_lists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wrap a top-level message list before calling LangChain streaming."""
    fake_agent = FakeAgent()
    monkeypatch.setattr(
        factory,
        "get_langfuse_runnable_config",
        lambda handler: {"callbacks": [handler]},
    )
    monkeypatch.setattr(factory, "new_root_run_id", lambda: "run-123")

    events = [
        event
        async for event in factory.stream_agent_raw(
            fake_agent, "handler", [{"role": "user", "content": "hello"}]
        )
    ]

    assert events == [{"event": "one"}, {"event": "two"}]
    assert fake_agent.astream_event_calls == [
        {
            "payload": {"messages": [{"role": "user", "content": "hello"}]},
            "config": {"callbacks": ["handler"], "run_id": "run-123"},
            "version": "v2",
        }
    ]


@pytest.mark.asyncio
async def test_stream_agent_normalizes_raw_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normalize raw LangChain events into app-level stream events."""

    async def fake_stream_agent_raw(agent: Any, handler: Any, agent_input: object):
        """Yield a small fake raw event sequence."""
        assert agent == "agent"
        assert handler == "handler"
        assert agent_input == [{"role": "user", "content": "hello"}]
        yield {"event": "one"}
        yield {"event": "two"}

    async def fake_normalize(raw_events: Any, *, query: str):
        """Yield normalized events from the fake raw stream."""
        assert query == "hello"
        collected = [event async for event in raw_events]
        assert collected == [{"event": "one"}, {"event": "two"}]
        yield {"normalized": 1}
        yield {"normalized": 2}

    monkeypatch.setattr(factory, "stream_agent_raw", fake_stream_agent_raw)
    monkeypatch.setattr(factory, "normalize_langchain_events", fake_normalize)

    events = [
        event
        async for event in factory.stream_agent(
            "agent",
            "handler",
            [{"role": "user", "content": "hello"}],
        )
    ]

    assert events == [{"normalized": 1}, {"normalized": 2}]


# ---------------------------------------------------------------------------
# HexgateAgent kill-switch ban gate
# ---------------------------------------------------------------------------


def _ban_gate(agent_name: str, banned: str | None = None):
    """A gate for ``agent_name`` whose source bans ``banned`` (default: itself)."""
    from hexgate.security.bans import BanEntry, BanGate, BanSet

    banned = banned or agent_name
    entry = BanEntry("b1", "agent", banned, None, "disabled")

    class _Src:
        def fetch(self) -> BanSet:
            return BanSet({banned: entry}, {})

    return BanGate(agent_name, _Src())


def _agent_with_gate(graph: FakeAgent, gate) -> factory.HexgateAgent:
    return factory.HexgateAgent(
        graph=graph, model="m", tools=[], system_prompt=None, name="bot", ban_gate=gate
    )


@pytest.mark.asyncio
async def test_hexgate_agent_ainvoke_refused_before_graph_when_banned() -> None:
    from hexgate.runtime import User
    from hexgate.security.errors import AgentBannedError

    graph = FakeAgent()
    agent = _agent_with_gate(graph, _ban_gate("bot"))

    async with User(user_id="u1"):
        with pytest.raises(AgentBannedError) as exc:
            await agent.ainvoke({}, {})

    assert exc.value.code == "agent_banned"
    assert graph.ainvoke_calls == []  # graph never ran


@pytest.mark.asyncio
async def test_hexgate_agent_astream_raises_before_first_event_when_banned() -> None:
    from hexgate.runtime import User
    from hexgate.security.errors import AgentBannedError

    graph = FakeAgent()
    agent = _agent_with_gate(graph, _ban_gate("bot"))

    async with User(user_id="u1"):
        with pytest.raises(AgentBannedError):
            async for _ in agent.astream_events({}, {}, version="v2"):
                pass

    assert graph.astream_event_calls == []


@pytest.mark.asyncio
async def test_hexgate_agent_not_banned_passes_through() -> None:
    from hexgate.runtime import User

    graph = FakeAgent()
    agent = _agent_with_gate(graph, _ban_gate("bot", banned="someone-else"))

    async with User(user_id="u1"):
        result = await agent.ainvoke({}, {})

    assert result == {"messages": ["ok"]}
    assert len(graph.ainvoke_calls) == 1


@pytest.mark.asyncio
async def test_hexgate_agent_no_gate_runs() -> None:
    graph = FakeAgent()
    agent = factory.HexgateAgent(
        graph=graph, model="m", tools=[], system_prompt=None, name="bot"
    )

    assert await agent.ainvoke({}, {}) == {"messages": ["ok"]}
