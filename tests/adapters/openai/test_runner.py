"""Tests for the HexgateRunner that wraps the OpenAI Agents Runner."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, AsyncIterator

import pytest
from agents import Agent, FunctionTool, RunHooks
from agents.items import ModelResponse
from agents.usage import Usage

from hexgate.adapters.openai import runner as runner_mod
from hexgate.adapters.openai.runner import (
    HexgateRunner,
    _CompositeRunHooks,
    _HexgateReachHooks,
)
from hexgate.adapters.openai.usage import HexgateUsageHooks
from hexgate.runtime import HexgateContext
from hexgate.runtime.context import get_current_context
from hexgate.security import AgentPolicy, BaseToolPolicy, PolicySet, ResolvedPolicy
from hexgate.security.bans import BanEntry, BanGate, BanSet
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.errors import AgentBannedError
from hexgate.tracing import usage as tracing_usage_mod
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


class _StaticBanSource:
    """A BanSource returning a fixed BanSet (no network)."""

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


@pytest.fixture(autouse=True)
def _stub_resolve(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stub the platform resolve seam — runner tests are about lifecycle,
    not policy resolution (covered by binding tests). Returns the list of
    resolved agent names so tests can assert on the binding cache."""
    resolved_names: list[str] = []

    def fake_resolve(
        name: str, *, api_key: str, client: object = None
    ) -> ResolvedPolicy:
        resolved_names.append(name)
        engine = PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy(
                    tools={"echo": BaseToolPolicy(mode="allow")}
                )
            }
        )
        return ResolvedPolicy(engine, None)

    monkeypatch.setattr(runner_mod, "resolve_policy", fake_resolve)
    # Neutralize the ban gate for lifecycle tests; ban tests inject one
    # directly into runner._ban_gates, bypassing this.
    monkeypatch.setattr(runner_mod, "resolve_ban_gate", lambda *a, **k: None)
    return resolved_names


def _user() -> HexgateContext:
    """Build a minimal HexgateContext for runner tests."""
    return HexgateContext(user_id="u-1", session_id="s-1", user_roles=["developer"])


def _make_tool(name: str = "echo") -> FunctionTool:
    """Build a minimal FunctionTool for runner tests."""

    async def on_invoke(_ctx: Any, raw_args: str) -> str:
        return f"invoked:{raw_args}"

    return FunctionTool(
        name=name,
        description=f"{name} tool",
        params_json_schema={"type": "object"},
        on_invoke_tool=on_invoke,
    )


def _make_agent(name: str = "my-agent") -> Agent:
    """Build a minimal Agent fixture for runner tests."""
    return Agent(name=name, tools=[_make_tool("echo")])


def _silence_observability(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Replace heavy observability dependencies with no-op stubs."""
    counts = {"setup": 0, "instrument": 0, "get_client": 0}

    def fake_setup(self: Any) -> None:
        counts["setup"] += 1

    monkeypatch.setattr(HexgateRunner, "_setup_observability", fake_setup)
    return counts


class _FakeStreamingResult:
    """Stand in for a RunResultStreaming with a swappable stream_events callable."""

    def __init__(self) -> None:
        """Initialize with a baseline stream_events that yields two events."""

        async def baseline() -> AsyncIterator[dict[str, str]]:
            yield {"event": "first"}
            yield {"event": "second"}

        self.stream_events = baseline


def test_constructor_uses_explicit_api_key() -> None:
    """An explicit api_key argument is stored verbatim."""
    runner = HexgateRunner(api_key="explicit-key")

    assert runner.api_key == "explicit-key"


def test_run_hooks_rejects_a_guard_list_with_a_clear_error() -> None:
    """A Hexgate guard list passed to run(hooks=) — the agents SDK RunHooks slot,
    not the constructor's guards= — is rejected at the seam with a message that
    points at the mistake, not deep in a lifecycle callback."""
    runner = HexgateRunner(api_key="k")

    with pytest.raises(TypeError, match="guards go on the constructor"):
        runner._merge_hooks([lambda call: None])


def test_constructor_falls_back_to_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve the API key from HEXGATE_API_KEY when no explicit key is given."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")

    runner = HexgateRunner()

    assert runner.api_key == "from-env"


def test_constructor_prefers_explicit_api_key_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit api_key argument wins when both sources are populated."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")

    runner = HexgateRunner(api_key="explicit")

    assert runner.api_key == "explicit"


def test_constructor_raises_when_no_api_key_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject construction when neither argument nor env var supplies a key."""
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="HEXGATE_API_KEY is not set"):
        HexgateRunner()


@pytest.mark.asyncio
async def test_run_wraps_agent_opens_user_scope_and_calls_runner_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() wraps the agent, opens the HexgateContext scope, and forwards to Runner.run."""
    setup_counts = _silence_observability(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(starting_agent: Agent, input: Any, **kwargs: Any) -> str:
        captured["agent"] = starting_agent
        captured["input"] = input
        captured["kwargs"] = kwargs
        captured["active_user"] = get_current_context()
        return "run-result"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    runner = HexgateRunner(api_key="k")
    agent = _make_agent()
    context = _user()

    result = await runner.run(agent, "hello", hexgate_context=context)

    assert result == "run-result"
    assert setup_counts["setup"] == 1
    assert captured["agent"] is not agent
    assert captured["agent"].name == agent.name
    assert captured["input"] == "hello"
    assert captured["kwargs"]["run_config"] is None
    hooks = captured["kwargs"]["hooks"]
    assert isinstance(hooks, _CompositeRunHooks)
    assert any(isinstance(h, HexgateUsageHooks) for h in hooks._hooks)
    assert any(isinstance(h, _HexgateReachHooks) for h in hooks._hooks)
    # HexgateContext scope was live for the duration of Runner.run.
    assert captured["active_user"] is context
    # Scope unwound on exit — no leak.
    assert get_current_context() is None


def test_run_sync_opens_user_scope_and_calls_runner_run_sync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_sync() opens the HexgateContext scope via sync_scope and forwards to Runner.run_sync."""
    setup_counts = _silence_observability(monkeypatch)
    captured: dict[str, Any] = {}

    def fake_run_sync(starting_agent: Agent, input: Any, **kwargs: Any) -> str:
        captured["agent"] = starting_agent
        captured["input"] = input
        captured["kwargs"] = kwargs
        captured["active_user"] = get_current_context()
        return "run-sync-result"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_sync", staticmethod(fake_run_sync)
    )

    runner = HexgateRunner(api_key="k")
    agent = _make_agent()
    context = _user()

    result = runner.run_sync(agent, "hello", hexgate_context=context)

    assert result == "run-sync-result"
    assert setup_counts["setup"] == 1
    assert captured["agent"] is not agent
    assert captured["input"] == "hello"
    assert captured["active_user"] is context
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_run_streamed_wraps_stream_events_to_re_enter_scope_and_propagation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_streamed swaps stream_events for a wrapper that re-enters HexgateContext + propagation."""
    _silence_observability(monkeypatch)

    fake_result = _FakeStreamingResult()
    captured: dict[str, Any] = {}

    def fake_run_streamed(
        starting_agent: Agent, input: Any, **kwargs: Any
    ) -> _FakeStreamingResult:
        captured["agent"] = starting_agent
        captured["input"] = input
        captured["kwargs"] = kwargs
        return fake_result

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    propagate_calls: list[dict[str, Any]] = []

    @contextmanager
    def fake_propagate_attributes(**kwargs: Any) -> Any:
        propagate_calls.append(kwargs)
        yield

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.propagate_attributes",
        fake_propagate_attributes,
    )

    runner = HexgateRunner(api_key="k")
    agent = _make_agent()
    context = _user()

    result = runner.run_streamed(agent, "hello", hexgate_context=context)

    assert result is fake_result
    assert captured["agent"].name == agent.name
    assert len(propagate_calls) == 1
    assert propagate_calls[0]["user_id"] == "u-1"
    assert propagate_calls[0]["session_id"] == "s-1"
    assert propagate_calls[0]["metadata"] == {"user_roles": "developer"}
    assert propagate_calls[0]["tags"] == ["openai.runner.run.my-agent"]

    events = [event async for event in result.stream_events()]
    assert events == [{"event": "first"}, {"event": "second"}]
    assert len(propagate_calls) == 2


@pytest.mark.asyncio
async def test_run_streamed_opens_user_scope_around_run_streamed_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The HexgateContext must be active when Runner.run_streamed spawns its loop task —
    that task snapshots contextvars at creation, where tools later resolve it."""
    _silence_observability(monkeypatch)

    captured: dict[str, Any] = {}

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStreamingResult:
        captured["active_user"] = get_current_context()
        return _FakeStreamingResult()

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    runner = HexgateRunner(api_key="k")
    context = _user()

    runner.run_streamed(_make_agent(), "hello", hexgate_context=context)

    assert captured["active_user"] is context
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_run_propagates_user_identity_to_langfuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() enters propagate_attributes with user identity and an agent-tagged scope."""
    _silence_observability(monkeypatch)

    async def fake_run(*_args: Any, **_kwargs: Any) -> str:
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    propagate_calls: list[dict[str, Any]] = []

    @contextmanager
    def fake_propagate_attributes(**kwargs: Any) -> Any:
        propagate_calls.append(kwargs)
        yield

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.propagate_attributes",
        fake_propagate_attributes,
    )

    runner = HexgateRunner(api_key="k")

    await runner.run(_make_agent("custom-name"), "hi", hexgate_context=_user())

    [call] = propagate_calls
    assert call["tags"] == ["openai.runner.run.custom-name"]
    assert call["user_id"] == "u-1"
    assert call["session_id"] == "s-1"
    assert call["metadata"] == {"user_roles": "developer"}


# ---------------------------------------------------------------------------
# Kill-switch ban gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_refused_before_runner_run_when_banned(
    monkeypatch: pytest.MonkeyPatch, _stub_resolve: list[str]
) -> None:
    _silence_observability(monkeypatch)
    called: list[str] = []

    async def fake_run(*_a: Any, **_kw: Any) -> str:
        called.append("run")
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    runner = HexgateRunner(api_key="k")
    runner._ban_gates["my-agent"] = _agent_ban_gate("my-agent")

    with pytest.raises(AgentBannedError) as exc:
        await runner.run(_make_agent("my-agent"), "hi", hexgate_context=_user())

    assert exc.value.code == "agent_banned"
    assert called == []  # Runner.run never reached
    assert get_current_context() is None


def test_run_streamed_refused_before_task_spawns_when_banned(
    monkeypatch: pytest.MonkeyPatch, _stub_resolve: list[str]
) -> None:
    """The gate refuses before Runner.run_streamed spawns its background task,
    so a banned stream never starts (no chunk)."""
    _silence_observability(monkeypatch)
    called: list[str] = []

    def fake_run_streamed(*_a: Any, **_kw: Any) -> _FakeStreamingResult:
        called.append("run_streamed")
        return _FakeStreamingResult()

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    runner = HexgateRunner(api_key="k")
    runner._ban_gates["my-agent"] = _agent_ban_gate("my-agent")

    with pytest.raises(AgentBannedError):
        runner.run_streamed(_make_agent("my-agent"), "hi", hexgate_context=_user())

    assert called == []  # background task never spawned


@pytest.mark.asyncio
async def test_not_banned_passes_through(
    monkeypatch: pytest.MonkeyPatch, _stub_resolve: list[str]
) -> None:
    _silence_observability(monkeypatch)

    async def fake_run(*_a: Any, **_kw: Any) -> str:
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    runner = HexgateRunner(api_key="k")
    runner._ban_gates["my-agent"] = _agent_ban_gate(
        "my-agent", banned="some-other-agent"
    )

    result = await runner.run(_make_agent("my-agent"), "hi", hexgate_context=_user())

    assert result == "ok"


# ---------------------------------------------------------------------------
# Binding cache + per-run refresh (phase 6)
# ---------------------------------------------------------------------------


class _CountingBinding:
    def __init__(self) -> None:
        self.refreshes = 0
        self.enforcer = PolicyEnforcer(
            PolicySet(
                {
                    DEFAULT_ROLE_NAME: AgentPolicy(
                        tools={"echo": BaseToolPolicy(mode="allow")}
                    )
                }
            ),
            agent_name="my-agent",
        )

    def refresh(self) -> None:
        self.refreshes += 1

    async def refresh_async(self) -> None:
        self.refreshes += 1


def _patch_runner_run(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_run(*_args: Any, **_kwargs: Any) -> str:
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )


@pytest.mark.asyncio
async def test_binding_is_cached_per_agent_name(
    monkeypatch: pytest.MonkeyPatch, _stub_resolve: list[str]
) -> None:
    """Same agent name across runs → one resolve; the ETag memory lives in
    the cached binding's source, not in a per-call construction."""
    _silence_observability(monkeypatch)
    _patch_runner_run(monkeypatch)

    runner = HexgateRunner(api_key="k")
    agent = _make_agent("my-agent")

    await runner.run(agent, "one", hexgate_context=_user())
    await runner.run(agent, "two", hexgate_context=_user())

    assert _stub_resolve == ["my-agent"]


@pytest.mark.asyncio
async def test_distinct_agent_names_get_distinct_bindings(
    monkeypatch: pytest.MonkeyPatch, _stub_resolve: list[str]
) -> None:
    _silence_observability(monkeypatch)
    _patch_runner_run(monkeypatch)

    runner = HexgateRunner(api_key="k")

    await runner.run(_make_agent("agent-a"), "x", hexgate_context=_user())
    await runner.run(_make_agent("agent-b"), "x", hexgate_context=_user())

    assert _stub_resolve == ["agent-a", "agent-b"]
    assert set(runner._bindings) == {"agent-a", "agent-b"}


def test_binding_for_normalises_none_agent_name_to_default(
    _stub_resolve: list[str],
) -> None:
    """A None agent name collapses to "default" rather than flowing through
    as the cache key / resolve label. Exercises _binding_for directly since
    the canonical Agent validates name as a string at construction."""
    runner = HexgateRunner(api_key="k")
    agent = SimpleNamespace(name=None, tools=[_make_tool("echo")])

    binding = runner._binding_for(agent)  # type: ignore[arg-type]

    assert _stub_resolve == ["default"]
    assert set(runner._bindings) == {"default"}
    assert None not in runner._bindings
    assert binding.enforcer.agent_name == "default"


@pytest.mark.asyncio
async def test_run_refreshes_cached_binding_per_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _silence_observability(monkeypatch)
    _patch_runner_run(monkeypatch)

    runner = HexgateRunner(api_key="k")
    binding = _CountingBinding()
    runner._bindings["my-agent"] = binding  # type: ignore[assignment]

    await runner.run(_make_agent("my-agent"), "one", hexgate_context=_user())
    await runner.run(_make_agent("my-agent"), "two", hexgate_context=_user())

    assert binding.refreshes == 2


def test_run_sync_refreshes_cached_binding_per_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _silence_observability(monkeypatch)

    def fake_run_sync(*_args: Any, **_kwargs: Any) -> str:
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_sync",
        staticmethod(fake_run_sync),
    )

    runner = HexgateRunner(api_key="k")
    binding = _CountingBinding()
    runner._bindings["my-agent"] = binding  # type: ignore[assignment]

    runner.run_sync(_make_agent("my-agent"), "one", hexgate_context=_user())

    assert binding.refreshes == 1


def test_run_streamed_refreshes_before_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refresh must land before Runner.run_streamed fixes the wrap —
    tools fire later during stream_events, against whatever the enforcer
    holds at setup."""
    _silence_observability(monkeypatch)

    order: list[str] = []

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStreamingResult:
        order.append("run_streamed")
        return _FakeStreamingResult()

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    class _OrderedBinding(_CountingBinding):
        def refresh(self) -> None:
            order.append("refresh")
            super().refresh()

    runner = HexgateRunner(api_key="k")
    binding = _OrderedBinding()
    runner._bindings["my-agent"] = binding  # type: ignore[assignment]

    runner.run_streamed(_make_agent("my-agent"), "hello", hexgate_context=_user())

    assert order == ["refresh", "run_streamed"]


@pytest.mark.asyncio
async def test_arun_streamed_refreshes_async_before_run_streamed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """arun_streamed (the serve path) awaits the async refresh before
    Runner.run_streamed — same security-relevant ordering as the sync path, but
    off the event loop so serve isn't blocked."""
    _silence_observability(monkeypatch)

    order: list[str] = []

    def fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStreamingResult:
        order.append("run_streamed")
        return _FakeStreamingResult()

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    class _OrderedBinding(_CountingBinding):
        async def refresh_async(self) -> None:
            order.append("refresh_async")
            await super().refresh_async()

    runner = HexgateRunner(api_key="k")
    runner._bindings["my-agent"] = _OrderedBinding()  # type: ignore[assignment]

    await runner.arun_streamed(
        _make_agent("my-agent"), "hello", hexgate_context=_user()
    )

    assert order == ["refresh_async", "run_streamed"]


@pytest.mark.asyncio
async def test_arun_streamed_refused_before_task_spawns_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ban gate is awaited (check_async) before Runner.run_streamed spawns
    its background task, so a banned stream never starts on the serve path."""
    _silence_observability(monkeypatch)
    called: list[str] = []

    def fake_run_streamed(*_a: Any, **_kw: Any) -> _FakeStreamingResult:
        called.append("run_streamed")
        return _FakeStreamingResult()

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run_streamed",
        staticmethod(fake_run_streamed),
    )

    runner = HexgateRunner(api_key="k")
    runner._ban_gates["my-agent"] = _agent_ban_gate("my-agent")

    with pytest.raises(AgentBannedError):
        await runner.arun_streamed(
            _make_agent("my-agent"), "hi", hexgate_context=_user()
        )

    assert called == []  # background task never spawned


# ---------------------------------------------------------------------------
# Usage hooks: merge behavior + HexgateContext contextvar survives into on_llm_end
# ---------------------------------------------------------------------------


class _FakeSender:
    """Stand in for the AuditSender the usage hook emits through."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class _RecordingHooks(RunHooks):
    """A caller-supplied hooks object that just counts on_llm_end calls."""

    def __init__(self) -> None:
        self.llm_end_calls = 0

    async def on_llm_end(self, context: Any, agent: Agent, response: Any) -> None:
        self.llm_end_calls += 1


def _fake_llm_response(
    input_tokens: int = 10, output_tokens: int = 20
) -> ModelResponse:
    return ModelResponse(
        output=[],
        usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens),
        response_id=None,
    )


@pytest.mark.asyncio
async def test_run_installs_usage_and_reach_hooks_when_caller_passes_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _silence_observability(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*_args: Any, **kwargs: Any) -> str:
        captured["hooks"] = kwargs["hooks"]
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    runner = HexgateRunner(api_key="k")
    await runner.run(_make_agent(), "hi", hexgate_context=_user())

    hooks = captured["hooks"]
    assert isinstance(hooks, _CompositeRunHooks)
    assert any(isinstance(h, HexgateUsageHooks) for h in hooks._hooks)
    assert any(isinstance(h, _HexgateReachHooks) for h in hooks._hooks)


@pytest.mark.asyncio
async def test_run_composes_caller_supplied_hooks_instead_of_clobbering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller-supplied hooks object must still fire — the usage hook is
    added alongside it, not swapped in over it."""
    _silence_observability(monkeypatch)
    captured: dict[str, Any] = {}

    async def fake_run(*_args: Any, **kwargs: Any) -> str:
        captured["hooks"] = kwargs["hooks"]
        await kwargs["hooks"].on_llm_end(object(), _make_agent(), _fake_llm_response())
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    caller_hooks = _RecordingHooks()
    runner = HexgateRunner(api_key="k")

    await runner.run(_make_agent(), "hi", hexgate_context=_user(), hooks=caller_hooks)

    assert captured["hooks"] is not caller_hooks  # composed, not passed through raw
    assert caller_hooks.llm_end_calls == 1  # still fired


@pytest.mark.asyncio
async def test_usage_hook_context_propagates_through_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_current_context() must still resolve inside on_llm_end, fired from
    wherever the real Runner invokes it within the run() call tree — the
    HexgateContext scope opened around Runner.run must still be live there."""
    _silence_observability(monkeypatch)
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        tracing_usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    async def fake_run(*_args: Any, **kwargs: Any) -> str:
        await kwargs["hooks"].on_llm_end(
            object(), _make_agent("my-agent"), _fake_llm_response()
        )
        return "ok"

    monkeypatch.setattr(
        "hexgate.adapters.openai.runner.Runner.run", staticmethod(fake_run)
    )

    runner = HexgateRunner(api_key="k")
    context = _user()

    await runner.run(_make_agent("my-agent"), "hi", hexgate_context=context)

    [event] = fake_sender.events
    assert event.agent_name == "my-agent"
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
    assert event.input_tokens == 10
    assert event.output_tokens == 20
