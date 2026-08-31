"""emit_llm_usage() — the single entry point every adapter's usage hook
calls into. Covers identity resolution from the HexgateContext contextvar and the
no-op path when no sender is configured; the sender itself is faked so no
real registry/network is touched (mirrors tests/tracing/test_tracing.py's
fake-double style)."""

from __future__ import annotations

from typing import Any

import pytest

from hexgate.runtime import HexgateContext
from hexgate.runtime.run_facts import run_scope
from hexgate.tracing import usage as usage_mod
from hexgate.tracing.usage import emit_llm_usage


class _FakeSender:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


def test_emit_llm_usage_is_a_noop_when_no_sender_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(usage_mod, "configure_usage_sender", lambda api_key=None: None)

    emit_llm_usage("agent", "gpt-4o", 10, 20, api_key="k")  # must not raise


def test_emit_llm_usage_sends_event_with_given_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    emit_llm_usage("my-agent", "gpt-4o", 10, 20, api_key="k")

    [event] = fake_sender.events
    assert event.agent_name == "my-agent"
    assert event.model == "gpt-4o"
    assert event.input_tokens == 10
    assert event.output_tokens == 20
    assert event.user_id == ""
    assert event.session_id == ""


async def test_emit_llm_usage_resolves_identity_from_active_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    async with HexgateContext(user_id="alice", session_id="sess-1", user_roles=["dev"]):
        emit_llm_usage("my-agent", "gpt-4o", 10, 20, api_key="k")

    [event] = fake_sender.events
    assert event.user_id == "alice"
    assert event.session_id == "sess-1"


def test_when_sender_emit_fails_then_emit_llm_usage_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every adapter's usage hook calls straight into this function from a
    framework callback that either re-raises on an unhandled exception
    (Google's PluginManager) or doesn't guard the call at all (OpenAI's
    run loop, Pydantic AI's inline call site) — a failure here must not
    fail the agent run whose usage it's reporting."""

    class _RaisingSender:
        def emit(self, event: Any) -> None:
            raise RuntimeError("boom")

    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: _RaisingSender()
    )

    emit_llm_usage("agent", "gpt-4o", 10, 20, api_key="k")  # must not raise


def test_emit_llm_usage_passes_api_key_to_configure_usage_sender(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str | None] = []

    def fake_configure(api_key: str | None = None) -> _FakeSender:
        captured.append(api_key)
        return _FakeSender()

    monkeypatch.setattr(usage_mod, "configure_usage_sender", fake_configure)

    emit_llm_usage("my-agent", "gpt-4o", 10, 20, api_key="explicit-key")

    assert captured == ["explicit-key"]


# ---------------------------------------------------------------------------
# run.* — the token budget, which must work with no platform attached
# ---------------------------------------------------------------------------


def test_records_tokens_without_a_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    """A token cap must work in local mode too — recording below the sender
    check would leave every token path at a permanent 0."""
    from hexgate.runtime.run_facts import run_scope

    monkeypatch.setattr(usage_mod, "configure_usage_sender", lambda api_key=None: None)

    with run_scope("a") as facts:
        emit_llm_usage("agent", "gpt-4o", 100, 20)

    namespace = facts.as_namespace("t")
    assert namespace["input_tokens"] == 100
    assert namespace["output_tokens"] == 20
    assert namespace["total_tokens"] == 120
    assert namespace["llm_calls"] == 1


def test_records_tokens_and_emits_when_a_sender_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hexgate.runtime.run_facts import run_scope

    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    with run_scope("a") as facts:
        emit_llm_usage("agent", "gpt-4o", 10, 20, api_key="k")

    assert len(fake_sender.events) == 1
    assert facts.as_namespace("t")["total_tokens"] == 30


def test_llm_calls_counts_requests_and_sums_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hexgate.runtime.run_facts import run_scope

    monkeypatch.setattr(usage_mod, "configure_usage_sender", lambda api_key=None: None)

    with run_scope("a") as facts:
        for _ in range(3):
            emit_llm_usage("agent", "gpt-4o", 100, 20)

    namespace = facts.as_namespace("t")
    assert namespace["llm_calls"] == 3
    assert namespace["total_tokens"] == 360
    assert namespace["total_tokens"] == (
        namespace["input_tokens"] + namespace["output_tokens"]
    )


def test_a_recorder_exception_does_not_break_the_run_or_the_emit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``emit_llm_usage`` never raises, so a RunFacts bug costs a token count,
    not the agent run — but the swallowed exception also aborts the emit."""
    from hexgate.runtime import run_facts as run_facts_mod
    from hexgate.runtime.run_facts import run_scope

    fake_sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: fake_sender
    )

    def boom(self: Any, input_tokens: int, output_tokens: int) -> None:
        raise RuntimeError("accounting bug")

    monkeypatch.setattr(run_facts_mod.RunFacts, "record_llm_usage", boom)

    with run_scope("a"):
        emit_llm_usage("agent", "gpt-4o", 10, 20, api_key="k")  # must not raise

    assert fake_sender.events == []  # the emit is lost too — accepted trade-off


def test_token_cap_trails_the_turn_that_exceeded_it() -> None:
    """Tokens are known only after the model responds, so a token constraint
    bounds prior turns: the cap fires on the *next* decision, not this one."""
    from hexgate.runtime.run_facts import run_scope
    from hexgate.security.enforcer import PolicyEnforcer
    from hexgate.security.models import AgentPolicy
    from hexgate.security.policy_set import PolicySet

    policy = AgentPolicy.model_validate(
        {"tools": {"t": {"mode": "allow", "constraints": ["run.total_tokens < 100"]}}}
    )
    enforcer = PolicyEnforcer(PolicySet({"default": policy}), agent_name="a")

    with run_scope("a"):
        # The turn's tool call is decided before its usage is reported...
        assert enforcer.decide("t", {}).allowed
        emit_llm_usage("a", "gpt-4o", 400, 0)
        # ...so the overshoot is only visible to the *next* decision.
        assert not enforcer.decide("t", {}).allowed


def test_emit_stamps_the_enclosing_run_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """llm_invocation rows join to the policy_decision rows of the same run, so
    the run_id has to reach the event, not just the counters."""
    sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: sender
    )

    with run_scope("agent") as facts:
        emit_llm_usage("agent", "gpt-4o", 10, 5)

    assert sender.events[0].run_id == facts.id
    assert sender.events[0].as_payload()["run_id"] == facts.id


def test_emit_outside_a_run_scope_sends_no_run_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: sender
    )

    emit_llm_usage("agent", "gpt-4o", 10, 5)

    assert sender.events[0].run_id == ""
    assert sender.events[0].as_payload()["run_id"] is None


def test_emit_attributes_tokens_and_the_run_id_to_the_same_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One get_run_facts() read, so the tokens and the run_id share an object."""
    sender = _FakeSender()
    monkeypatch.setattr(
        usage_mod, "configure_usage_sender", lambda api_key=None: sender
    )

    with run_scope("agent") as facts:
        emit_llm_usage("agent", "gpt-4o", 10, 5)

    assert facts.as_namespace("t")["total_tokens"] == 15
    assert sender.events[0].run_id == facts.id
