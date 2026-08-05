"""emit_llm_usage() — the single entry point every adapter's usage hook
calls into. Covers identity resolution from the HexgateContext contextvar and the
no-op path when no sender is configured; the sender itself is faked so no
real registry/network is touched (mirrors tests/tracing/test_tracing.py's
fake-double style)."""

from __future__ import annotations

from typing import Any

import pytest

from hexgate.runtime import HexgateContext
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
