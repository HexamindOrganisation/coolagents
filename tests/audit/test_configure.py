"""audit.configure() — thin wiring onto the shared sender registry.

Generic registry mechanics (idempotency, distinct-key isolation,
HEXGATE_LOCAL_MODE suppression) live in tests/tracing/test_senders.py —
this file only checks that audit.py wires the shared registry to the OTLP
endpoint.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import hexgate.audit as audit_mod
from hexgate.tracing import _senders


@pytest.fixture(autouse=True)
def _isolate_audit_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the shared sender registry + clear HEXGATE_* env between tests."""
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed = False
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv(_senders._LOCAL_MODE_ENV, raising=False)
    yield
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed = False


def test_returns_none_when_no_key_anywhere() -> None:
    assert audit_mod.configure() is None
    assert audit_mod.get_sender() is None


def test_explicit_api_key_uses_default_url() -> None:
    sender = audit_mod.configure("explicit_key")
    assert sender is not None
    assert sender._endpoint == "https://app.hexgate.ai/v1/traces"


def test_env_api_key_picked_up_when_not_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    sender = audit_mod.configure()
    assert sender is not None
    assert sender._endpoint == "https://app.hexgate.ai/v1/traces"


def test_explicit_api_key_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    sender = audit_mod.configure("explicit_key")
    assert sender._api_key == "explicit_key"


def test_env_base_url_respected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "https://prod.example.com/")
    sender = audit_mod.configure("k")
    assert sender._endpoint == "https://prod.example.com/v1/traces"


def test_explicit_base_url_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "https://env.example.com")
    sender = audit_mod.configure("k", "https://explicit.example.com")
    assert sender._endpoint == "https://explicit.example.com/v1/traces"


def test_get_sender_scoped_by_key() -> None:
    sender = audit_mod.configure("k1")
    assert audit_mod.get_sender("k1") is sender
    assert audit_mod.get_sender("k2") is None


def test_local_mode_suppresses_configure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Full HEXGATE_LOCAL_MODE truth-table coverage lives in
    tests/tracing/test_senders.py; this just confirms audit.configure()
    actually reaches the shared gate."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(_senders._LOCAL_MODE_ENV, "1")
    assert audit_mod.configure() is None
    assert audit_mod.get_sender("real_key") is None


async def test_shutdown_delegates_to_shared_registry() -> None:
    """audit.shutdown() drains the shared registry, not a private copy —
    covered end-to-end (with the usage.py side too) in
    tests/tracing/test_usage_configure.py."""
    audit_mod.configure("k1")
    await audit_mod.shutdown()
    assert _senders._senders == {}
