"""Tests for the HexgatePydanticAgent proxy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

import pytest
from pydantic_ai.usage import RunUsage

from hexgate.adapters.pydantic_ai.agent import HexgatePydanticAgent
from hexgate.runtime import User
from hexgate.runtime.context import get_current_user
from hexgate.security.bans import BanEntry, BanGate, BanSet
from hexgate.security.errors import AgentBannedError
from hexgate.tracing import usage as tracing_usage_mod


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


class _FakeResult:
    """Minimal stand-in for AgentRunResult/StreamedRunResult/AgentRun —
    exposes .usage()/.response so emit_run_usage() doesn't blow up on the
    test double; .value carries what the old plain-string fixtures used to
    return."""

    def __init__(self, value: str) -> None:
        self.value = value
        self.response = None

    def usage(self) -> RunUsage:
        return RunUsage(input_tokens=10, output_tokens=20)


class _RecordingAgent:
    """Capture the active User and call args seen by each Agent method."""

    name = "recording-agent"
    model = "test-model"

    def __init__(self) -> None:
        self.run_calls: list[dict[str, Any]] = []
        self.run_sync_calls: list[dict[str, Any]] = []
        self.run_stream_calls: list[dict[str, Any]] = []
        self.iter_calls: list[dict[str, Any]] = []

    def _snapshot(
        self, args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        """Capture the active User plus call arguments."""
        return {
            "user": get_current_user(),
            "args": args,
            "kwargs": kwargs,
        }

    async def run(self, *args: Any, **kwargs: Any) -> _FakeResult:
        """Record async-run arguments."""
        self.run_calls.append(self._snapshot(args, kwargs))
        return _FakeResult("run-ok")

    def run_sync(self, *args: Any, **kwargs: Any) -> _FakeResult:
        """Record sync-run arguments."""
        self.run_sync_calls.append(self._snapshot(args, kwargs))
        return _FakeResult("run-sync-ok")

    @asynccontextmanager
    async def run_stream(self, *args: Any, **kwargs: Any) -> AsyncIterator[_FakeResult]:
        """Async-context yield while capturing the active User."""
        self.run_stream_calls.append(self._snapshot(args, kwargs))
        yield _FakeResult("stream-result")

    @asynccontextmanager
    async def iter(self, *args: Any, **kwargs: Any) -> AsyncIterator[_FakeResult]:
        """Async-context yield used by graph iteration."""
        self.iter_calls.append(self._snapshot(args, kwargs))
        yield _FakeResult("iter-result")

    def some_attribute(self) -> str:
        """Expose an arbitrary attribute used to verify __getattr__ delegation."""
        return "delegated"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_constructor_calls_setup_observability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The proxy must instrument all pydantic_ai Agents at construction."""
    calls: list[bool] = []

    def fake_instrument_all() -> None:
        calls.append(True)

    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", fake_instrument_all
    )

    HexgatePydanticAgent(
        agent=_RecordingAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )

    assert calls == [True]


def test_constructor_stores_inputs() -> None:
    """The proxy keeps the agent, api key, agent name, and tool names verbatim."""
    inner = _RecordingAgent()

    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="api-123",
        agent_name="custom-name",
    )

    assert proxy._agent is inner
    assert proxy._api_key == "api-123"
    assert proxy._agent_name == "custom-name"


# ---------------------------------------------------------------------------
# User scope binding per invocation method
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_opens_user_scope_and_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )
    user = _user()

    assert get_current_user() is None

    result = await proxy.run("hello", user=user)

    assert result.value == "run-ok"
    [call] = inner.run_calls
    assert call["user"] is user
    assert call["args"] == ("hello",)
    assert get_current_user() is None


def test_run_sync_opens_user_scope_and_delegates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )
    user = _user()

    result = proxy.run_sync("hello", user=user)

    assert result.value == "run-sync-ok"
    [call] = inner.run_sync_calls
    assert call["user"] is user
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_run_stream_opens_user_scope_and_yields_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )
    user = _user()

    async with proxy.run_stream("hello", user=user) as result:
        assert result.value == "stream-result"
        # Scope is live during the body.
        assert get_current_user() is user

    [call] = inner.run_stream_calls
    assert call["user"] is user
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_iter_opens_user_scope_and_yields_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )
    user = _user()

    async with proxy.iter("hello", user=user) as run:
        assert run.value == "iter-result"
        assert get_current_user() is user

    [call] = inner.iter_calls
    assert call["user"] is user
    assert get_current_user() is None


def test_user_scope_is_unwound_when_run_sync_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The contextvar unwinds even when the wrapped agent raises."""
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    class BoomAgent:
        def run_sync(self, *_args: Any, **_kwargs: Any) -> str:
            raise RuntimeError("boom")

    proxy = HexgatePydanticAgent(
        agent=BoomAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="boom",
    )

    with pytest.raises(RuntimeError, match="boom"):
        proxy.run_sync("hi", user=_user())

    assert get_current_user() is None


# ---------------------------------------------------------------------------
# Kill-switch ban gate
# ---------------------------------------------------------------------------


def _banned_proxy(
    monkeypatch: pytest.MonkeyPatch, agent: _RecordingAgent
) -> HexgatePydanticAgent:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )
    return HexgatePydanticAgent(
        agent=agent,  # type: ignore[arg-type]
        api_key="k",
        agent_name=agent.name,
        ban_gate=_agent_ban_gate(agent.name),
    )


@pytest.mark.asyncio
async def test_run_refused_before_agent_runs_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner = _RecordingAgent()
    proxy = _banned_proxy(monkeypatch, inner)

    with pytest.raises(AgentBannedError) as exc:
        await proxy.run("hi", user=_user())

    assert exc.value.code == "agent_banned"
    assert inner.run_calls == []
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_run_stream_raises_before_first_chunk_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner = _RecordingAgent()
    proxy = _banned_proxy(monkeypatch, inner)

    with pytest.raises(AgentBannedError):
        async with proxy.run_stream("hi", user=_user()) as _r:
            pass
    assert inner.run_stream_calls == []


@pytest.mark.asyncio
async def test_not_banned_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )
    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name=inner.name,
        ban_gate=_agent_ban_gate(inner.name, banned="some-other-agent"),
    )

    result = await proxy.run("hi", user=_user())

    assert result.value == "run-ok"
    assert len(inner.run_calls) == 1


# ---------------------------------------------------------------------------
# __getattr__ delegation
# ---------------------------------------------------------------------------


def test_proxy_delegates_unknown_attributes_to_wrapped_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )

    inner = _RecordingAgent()
    proxy = HexgatePydanticAgent(
        agent=inner,  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )

    assert proxy.some_attribute() == "delegated"
    assert proxy.name == "recording-agent"


# ---------------------------------------------------------------------------
# Per-run policy refresh (phase 7)
# ---------------------------------------------------------------------------


class _CountingBinding:
    def __init__(self) -> None:
        self.refreshes = 0

    def refresh(self) -> None:
        self.refreshes += 1

    async def refresh_async(self) -> None:
        self.refreshes += 1


def _proxy_with_counting_binding() -> tuple[HexgatePydanticAgent, _CountingBinding]:
    binding = _CountingBinding()
    proxy = HexgatePydanticAgent(
        agent=_RecordingAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
        binding=binding,  # type: ignore[arg-type]
    )
    return proxy, binding


@pytest.mark.asyncio
async def test_run_refreshes_binding_per_call() -> None:
    proxy, binding = _proxy_with_counting_binding()

    await proxy.run("one", user=_user())
    await proxy.run("two", user=_user())

    assert binding.refreshes == 2


def test_run_sync_refreshes_binding_per_call() -> None:
    proxy, binding = _proxy_with_counting_binding()

    proxy.run_sync("one", user=_user())

    assert binding.refreshes == 1


@pytest.mark.asyncio
async def test_run_stream_refreshes_binding_per_call() -> None:
    proxy, binding = _proxy_with_counting_binding()

    async with proxy.run_stream("one", user=_user()) as result:
        assert result.value == "stream-result"

    assert binding.refreshes == 1


@pytest.mark.asyncio
async def test_iter_refreshes_binding_per_call() -> None:
    proxy, binding = _proxy_with_counting_binding()

    async with proxy.iter("one", user=_user()):
        pass

    assert binding.refreshes == 1


def test_proxy_without_binding_runs_fine() -> None:
    """Back-compat: a binding-less proxy (direct construction) still works."""
    proxy = HexgatePydanticAgent(
        agent=_RecordingAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="recording-agent",
    )

    assert proxy.run_sync("one", user=_user()).value == "run-sync-ok"


# ---------------------------------------------------------------------------
# emit_run_usage: User contextvar survives to the emit call site
# ---------------------------------------------------------------------------


class _FakeSender:
    """Stand in for the AuditSender emit_run_usage emits through."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_usage_emit_context_propagates_through_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_current_user() must still resolve when emit_run_usage fires —
    it's called from inside the User scope opened around run(), before
    that scope unwinds."""
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        tracing_usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    proxy = HexgatePydanticAgent(
        agent=_RecordingAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="my-agent",
    )
    user = _user()

    await proxy.run("hello", user=user)

    [event] = fake_sender.events
    assert event.agent_name == "my-agent"
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
    assert event.input_tokens == 10
    assert event.output_tokens == 20


@pytest.mark.asyncio
async def test_usage_emit_context_propagates_through_run_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same guarantee for run_stream, where the emit fires after the
    caller's block resumes control, right before the User scope exits."""
    monkeypatch.setattr(
        "hexgate.adapters.pydantic_ai.agent.Agent.instrument_all", lambda: None
    )
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        tracing_usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    proxy = HexgatePydanticAgent(
        agent=_RecordingAgent(),  # type: ignore[arg-type]
        api_key="k",
        agent_name="my-agent",
    )
    user = _user()

    async with proxy.run_stream("hello", user=user) as result:
        assert result.value == "stream-result"
        assert fake_sender.events == []  # not emitted until the block exits

    [event] = fake_sender.events
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
