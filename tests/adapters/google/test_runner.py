"""Tests for the HexgateRunner that wraps the Google ADK Runner."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, AsyncIterator

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.sessions import InMemorySessionService
from google.adk.tools.function_tool import FunctionTool
from google.genai import types

from hexgate.adapters.google import runner as runner_mod
from hexgate.adapters.google import wrapper as wrapper_mod
from hexgate.adapters.google.runner import HexgateRunner
from hexgate.adapters.google.usage import HexgateUsagePlugin
from hexgate.runtime import User
from hexgate.runtime.context import get_current_user
from hexgate.security import AgentPolicy, BaseToolPolicy, PolicySet, ResolvedPolicy
from hexgate.security.bans import BanEntry, BanGate, BanSet
from hexgate.security.errors import AgentBannedError
from hexgate.security.policy_set import DEFAULT_ROLE_NAME
from hexgate.tracing import _senders as senders_mod
from hexgate.tracing import usage as tracing_usage_mod
from hexgate.tracing._senders import AuditSender


@contextmanager
def _registered_sender(key: tuple[str, str] = ("test-key", "/test-path")) -> Any:
    """Register a real AuditSender in the shared registry for the duration
    of a test, so drain_pending_tasks' pending_send_tasks() scoping can
    find a task tracked in it — evicted afterward since the registry is
    process-global state shared across the whole test session."""
    sender = AuditSender(endpoint="https://example.invalid/test-path", api_key="k")
    senders_mod._senders[key] = sender
    try:
        yield sender
    finally:
        del senders_mod._senders[key]


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
def _stub_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the platform resolve seam — runner tests are about lifecycle,
    not policy resolution (covered by test_wrapper.py / binding tests)."""

    def fake_resolve(
        name: str, *, api_key: str, client: object = None
    ) -> ResolvedPolicy:
        engine = PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy(
                    tools={"echo": BaseToolPolicy(mode="allow")}
                )
            }
        )
        return ResolvedPolicy(engine, None)

    monkeypatch.setattr(wrapper_mod, "resolve_policy", fake_resolve)
    # Neutralize the ban gate for lifecycle tests; ban tests override
    # runner._ban_gate directly, bypassing this.
    monkeypatch.setattr(runner_mod, "resolve_ban_gate", lambda *a, **k: None)


def _user() -> User:
    """Build a minimal User for runner tests."""
    return User(user_id="u-1", session_id="s-1", role="developer")


def _make_callable(name: str = "echo") -> Any:
    """Build a plain callable echo function."""

    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    echo.__name__ = name
    return echo


def _make_agent(name: str = "my_agent") -> LlmAgent:
    """Build a minimal ADK agent fixture for runner tests."""
    return LlmAgent(
        name=name,
        model="gemini-2.0-flash",
        tools=[FunctionTool(func=_make_callable("echo"))],
    )


def _silence_observability(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Replace heavy observability dependencies with no-op stubs."""
    counts = {"setup": 0}

    def fake_setup(self: Any) -> None:
        counts["setup"] += 1

    monkeypatch.setattr(HexgateRunner, "_setup_observability", fake_setup)
    return counts


class _FakeRunner:
    """Capture the construction args and yield events for run / run_async."""

    instances: list[_FakeRunner] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.run_calls: list[dict[str, Any]] = []
        self.run_async_calls: list[dict[str, Any]] = []
        # Capture which User was active at each call (verifies the scope is live).
        self.active_users: list[Any] = []
        _FakeRunner.instances.append(self)

    def run(self, **kwargs: Any) -> Any:
        """Yield two synthetic events while capturing the call kwargs."""
        self.run_calls.append(kwargs)
        self.active_users.append(get_current_user())
        yield {"event": "first"}
        yield {"event": "second"}

    async def run_async(self, **kwargs: Any) -> AsyncIterator[dict[str, str]]:
        """Async-yield two synthetic events while capturing the call kwargs."""
        self.run_async_calls.append(kwargs)
        self.active_users.append(get_current_user())
        yield {"event": "first"}
        yield {"event": "second"}


def _install_fake_runner(monkeypatch: pytest.MonkeyPatch) -> type[_FakeRunner]:
    """Patch the runner module's Runner symbol with the recording fake."""
    _FakeRunner.instances = []
    monkeypatch.setattr("hexgate.adapters.google.runner.Runner", _FakeRunner)
    return _FakeRunner


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


def test_constructor_uses_explicit_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """An explicit api_key argument is stored verbatim."""
    _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="explicit-key",
    )

    assert runner.api_key == "explicit-key"


def test_constructor_falls_back_to_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve the API key from HEXGATE_API_KEY when no explicit key is given."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")
    _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
    )

    assert runner.api_key == "from-env"


def test_constructor_prefers_explicit_api_key_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit api_key argument wins when both sources are populated."""
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")
    _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="explicit",
    )

    assert runner.api_key == "explicit"


def test_constructor_raises_when_no_api_key_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject construction when neither argument nor env var supplies a key."""
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="HEXGATE_API_KEY is not set"):
        HexgateRunner(
            agent=_make_agent(),
            app_name="app",
            session_service=InMemorySessionService(),
        )


def test_constructor_builds_underlying_runner_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Construction wraps the agent + builds the Runner exactly once."""
    fake = _install_fake_runner(monkeypatch)

    HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
        custom_kwarg="value",
    )

    [fake_runner] = fake.instances
    assert fake_runner.kwargs["custom_kwarg"] == "value"
    app = fake_runner.kwargs["app"]
    assert app.name == "app"
    # The wrapped agent is a clone, not the original.
    assert app.root_agent.name == "my_agent"


# ---------------------------------------------------------------------------
# run / run_async — User scope + delegation
# ---------------------------------------------------------------------------


def test_run_drives_run_async_inline_under_user_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() drives the underlying Runner.run_async inline (not ADK's threaded
    Runner.run, whose worker thread cannot see our scope) under a live User."""
    setup_counts = _silence_observability(monkeypatch)
    fake = _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="my_app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    user = _user()

    events = list(runner.run(new_message="hello", user=user))

    assert events == [{"event": "first"}, {"event": "second"}]
    assert setup_counts["setup"] == 1
    [fake_runner] = fake.instances
    # The threaded sync path is bypassed; the async path carries the scope.
    assert fake_runner.run_calls == []
    [run_call] = fake_runner.run_async_calls
    assert run_call == {
        "user_id": "u-1",
        "session_id": "s-1",
        "new_message": "hello",
    }
    # User scope was live during the underlying call.
    [active] = fake_runner.active_users
    assert active is user
    # Scope unwound after the call.
    assert get_current_user() is None


def test_run_drains_pending_tasks_before_closing_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The last turn's fire-and-forget audit-send task may still be in
    flight when the generator is exhausted — run()'s finally block must
    drain it via asyncio.gather before closing the loop, or the send is
    silently abandoned (the exact scenario runner.py's own comment on
    this describes)."""
    _silence_observability(monkeypatch)

    completed: list[bool] = []

    with _registered_sender() as sender:

        class _RunnerWithPendingTask(_FakeRunner):
            async def run_async(self, **kwargs: Any) -> AsyncIterator[dict[str, str]]:
                async def _slow_background_send() -> None:
                    # Long enough that it's still pending once the two yields
                    # below are exhausted and the generator is closed — the
                    # two synchronous __anext__() calls return almost
                    # instantly, nowhere near this sleep's duration.
                    await asyncio.sleep(0.05)
                    completed.append(True)

                task = asyncio.get_running_loop().create_task(_slow_background_send())
                sender._tasks.add(task)
                task.add_done_callback(sender._tasks.discard)
                async for event in super().run_async(**kwargs):
                    yield event

        _FakeRunner.instances = []
        monkeypatch.setattr(
            "hexgate.adapters.google.runner.Runner", _RunnerWithPendingTask
        )

        runner = HexgateRunner(
            agent=_make_agent(),
            app_name="my_app",
            session_service=InMemorySessionService(),
            api_key="k",
        )

        events = list(runner.run(new_message="hello", user=_user()))

        assert events == [{"event": "first"}, {"event": "second"}]
        # If run() had closed the loop without draining pending tasks first,
        # the background send would never have gotten the chance to finish.
        assert completed == [True]


def test_run_keeps_scope_visible_across_awaits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inline drive must keep the User visible across the agent loop's
    await points — where tools actually fire — not just at entry."""
    import asyncio

    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="my_app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    user = _user()
    seen: list[Any] = []

    async def run_async(**_kwargs: Any) -> Any:
        await asyncio.sleep(0)
        seen.append(get_current_user())  # post-await: a tool-call point
        yield {"event": "only"}

    runner._runner.run_async = run_async  # type: ignore[attr-defined]

    events = list(runner.run(new_message="hi", user=user))

    assert events == [{"event": "only"}]
    assert seen == [user]
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_run_async_opens_user_scope_and_yields_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_async() opens a User scope around the underlying Runner.run_async."""
    setup_counts = _silence_observability(monkeypatch)
    fake = _install_fake_runner(monkeypatch)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="my_app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    user = _user()

    events = [event async for event in runner.run_async(new_message="hello", user=user)]

    assert events == [{"event": "first"}, {"event": "second"}]
    assert setup_counts["setup"] == 1
    [fake_runner] = fake.instances
    [run_call] = fake_runner.run_async_calls
    assert run_call == {
        "user_id": "u-1",
        "session_id": "s-1",
        "new_message": "hello",
    }
    [active] = fake_runner.active_users
    assert active is user
    assert get_current_user() is None


# ---------------------------------------------------------------------------
# Langfuse propagation
# ---------------------------------------------------------------------------


def test_run_propagates_user_identity_to_langfuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run() enters propagate_attributes with user identity and an agent-tagged scope."""
    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)

    propagate_calls: list[dict[str, Any]] = []

    @contextmanager
    def fake_propagate_attributes(**kwargs: Any) -> Any:
        propagate_calls.append(kwargs)
        yield

    monkeypatch.setattr(
        "hexgate.adapters.google.runner.propagate_attributes",
        fake_propagate_attributes,
    )

    runner = HexgateRunner(
        agent=_make_agent("custom_agent"),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )

    list(runner.run(new_message="hi", user=_user()))

    [call] = propagate_calls
    assert call["tags"] == ["google.runner.run.custom_agent"]
    assert call["user_id"] == "u-1"
    assert call["session_id"] == "s-1"
    assert call["metadata"] == {"user_role": "developer"}


@pytest.mark.asyncio
async def test_run_async_propagates_user_identity_to_langfuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_async() also propagates the user identity for each invocation."""
    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)

    propagate_calls: list[dict[str, Any]] = []

    @contextmanager
    def fake_propagate_attributes(**kwargs: Any) -> Any:
        propagate_calls.append(kwargs)
        yield

    monkeypatch.setattr(
        "hexgate.adapters.google.runner.propagate_attributes",
        fake_propagate_attributes,
    )

    runner = HexgateRunner(
        agent=_make_agent("custom_agent"),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )

    async for _ in runner.run_async(new_message="hi", user=_user()):
        pass

    [call] = propagate_calls
    assert call["tags"] == ["google.runner.run.custom_agent"]
    assert call["user_id"] == "u-1"
    assert call["session_id"] == "s-1"


# ---------------------------------------------------------------------------
# Extra kwargs threading
# ---------------------------------------------------------------------------


def test_extra_kwargs_reach_underlying_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Extra kwargs given to the constructor reach the underlying Runner."""
    _silence_observability(monkeypatch)
    fake = _install_fake_runner(monkeypatch)

    HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
        custom_kwarg="value",
    )

    [fake_runner] = fake.instances
    assert fake_runner.kwargs["custom_kwarg"] == "value"


# ---------------------------------------------------------------------------
# Kill-switch ban gate
# ---------------------------------------------------------------------------


def _banned_runner(monkeypatch: pytest.MonkeyPatch) -> HexgateRunner:
    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)
    runner = HexgateRunner(
        agent=_make_agent("my_agent"),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    runner._ban_gate = _agent_ban_gate("my_agent")
    return runner


def test_run_refused_before_events_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _banned_runner(monkeypatch)

    with pytest.raises(AgentBannedError) as exc:
        list(runner.run(new_message="hi", user=_user()))

    assert exc.value.code == "agent_banned"
    [fake_runner] = _FakeRunner.instances
    assert fake_runner.run_async_calls == []  # underlying runner never driven
    assert get_current_user() is None


@pytest.mark.asyncio
async def test_run_async_refused_before_first_event_when_banned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = _banned_runner(monkeypatch)

    agen = runner.run_async(new_message="hi", user=_user())
    with pytest.raises(AgentBannedError):
        await agen.__anext__()

    [fake_runner] = _FakeRunner.instances
    assert fake_runner.run_async_calls == []


def test_not_banned_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)
    runner = HexgateRunner(
        agent=_make_agent("my_agent"),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    runner._ban_gate = _agent_ban_gate("my_agent", banned="some-other-agent")

    events = list(runner.run(new_message="hi", user=_user()))

    assert events == [{"event": "first"}, {"event": "second"}]


# ---------------------------------------------------------------------------
# Per-run policy refresh (phase 5)
# ---------------------------------------------------------------------------


class _CountingBinding:
    def __init__(self) -> None:
        self.refreshes = 0

    def refresh(self) -> None:
        self.refreshes += 1

    async def refresh_async(self) -> None:
        self.refreshes += 1


def _runner_with_counting_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[HexgateRunner, _CountingBinding]:
    _silence_observability(monkeypatch)
    _install_fake_runner(monkeypatch)
    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    binding = _CountingBinding()
    runner._binding = binding  # type: ignore[assignment]
    return runner, binding


def test_run_refreshes_binding_per_call(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every run() pulls the policy before any event is yielded."""
    runner, binding = _runner_with_counting_binding(monkeypatch)

    list(runner.run(new_message="hi", user=_user()))
    list(runner.run(new_message="hi again", user=_user()))

    assert binding.refreshes == 2


@pytest.mark.asyncio
async def test_run_async_refreshes_binding_per_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, binding = _runner_with_counting_binding(monkeypatch)

    async for _ in runner.run_async(new_message="hi", user=_user()):
        pass

    assert binding.refreshes == 1


def test_construction_does_not_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve at construction is the initial pull; refresh only fires at
    run boundaries (the binding is freshly seeded — first run is a 304)."""
    runner, binding = _runner_with_counting_binding(monkeypatch)

    assert binding.refreshes == 0


# ---------------------------------------------------------------------------
# Usage plugin: merge behavior + User contextvar survives into
# after_model_callback
# ---------------------------------------------------------------------------


class _FakeSender:
    """Stand in for the AuditSender the usage plugin emits through."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


def _fake_llm_response(
    prompt_tokens: int = 10, candidates_tokens: int = 20
) -> LlmResponse:
    return LlmResponse(
        model_version="gemini-2.0-flash",
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=prompt_tokens,
            candidates_token_count=candidates_tokens,
        ),
    )


class _PluginFiringRunner:
    """Stand-in Runner that fires after_model_callback on any
    HexgateUsagePlugin in its plugins kwarg, from inside run_async, the way
    real ADK fires it mid-run rather than from the test's own call stack."""

    instances: list[_PluginFiringRunner] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        _PluginFiringRunner.instances.append(self)

    async def run_async(self, **kwargs: Any) -> AsyncIterator[dict[str, str]]:
        app = self.kwargs.get("app")
        for plugin in app.plugins if app else []:
            if isinstance(plugin, HexgateUsagePlugin):
                await plugin.after_model_callback(
                    callback_context=SimpleNamespace(agent_name="my-agent"),
                    llm_response=_fake_llm_response(),
                )
        yield {"event": "done"}


def test_constructor_passes_a_usage_plugin_when_no_plugins_supplied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _install_fake_runner(monkeypatch)

    HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )

    [fake_runner] = fake.instances
    plugins = fake_runner.kwargs["app"].plugins
    assert len(plugins) == 1
    assert isinstance(plugins[0], HexgateUsagePlugin)


def test_constructor_preserves_caller_supplied_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller-supplied plugins list must still reach the Runner — the
    usage plugin is appended alongside it, not swapped in over it."""
    fake = _install_fake_runner(monkeypatch)
    custom_plugin = BasePlugin(name="custom")

    HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
        plugins=[custom_plugin],
    )

    [fake_runner] = fake.instances
    plugins = fake_runner.kwargs["app"].plugins
    assert custom_plugin in plugins
    assert any(isinstance(p, HexgateUsagePlugin) for p in plugins)
    assert len(plugins) == 2


@pytest.mark.asyncio
async def test_usage_plugin_context_propagates_through_run_async(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_current_user() must still resolve inside after_model_callback,
    fired from wherever ADK invokes it within the run_async call tree — the
    User scope opened around run_async must still be live there."""
    _silence_observability(monkeypatch)
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        tracing_usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )
    _PluginFiringRunner.instances = []
    monkeypatch.setattr("hexgate.adapters.google.runner.Runner", _PluginFiringRunner)

    runner = HexgateRunner(
        agent=_make_agent(),
        app_name="app",
        session_service=InMemorySessionService(),
        api_key="k",
    )
    user = _user()

    async for _ in runner.run_async(new_message=None, user=user):
        pass

    [event] = fake_sender.events
    assert event.agent_name == "my-agent"
    assert event.user_id == "u-1"
    assert event.session_id == "s-1"
    assert event.input_tokens == 10
    assert event.output_tokens == 20
