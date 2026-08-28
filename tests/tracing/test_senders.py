"""hexgate.tracing._senders — the shared per-api_key registry and the
HEXGATE_LOCAL_MODE gate, tested directly against the neutral module rather
than through hexgate.audit, hexgate.tracing.usage or hexgate.security.bans.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

import hexgate.tracing._senders as senders_mod


@pytest.fixture(autouse=True)
def _isolate_sender_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the sender registry + clear HEXGATE_* env between tests."""
    senders_mod._senders.clear()
    senders_mod._logged_local_mode_suppressed = False
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv("HEXGATE_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv(senders_mod._LOCAL_MODE_ENV, raising=False)
    yield
    for sender in senders_mod._senders.values():
        sender._provider.shutdown()
    senders_mod._senders.clear()
    senders_mod._logged_local_mode_suppressed = False


# ---------------------------------------------------------------------------
# get_or_create_sender() / get_sender() — generic registry mechanics
# ---------------------------------------------------------------------------


def test_returns_none_when_no_key_anywhere() -> None:
    assert senders_mod.get_or_create_sender() is None
    assert senders_mod.get_sender() is None


def test_idempotent_per_key_returns_same_sender() -> None:
    first = senders_mod.get_or_create_sender("k1")
    second = senders_mod.get_or_create_sender("k1")  # reuse
    assert first is second


def test_distinct_keys_get_distinct_senders() -> None:
    sender_a = senders_mod.get_or_create_sender("k1")
    sender_b = senders_mod.get_or_create_sender("k2")
    assert sender_a is not sender_b
    assert sender_a._api_key == "k1"
    assert sender_b._api_key == "k2"


def test_get_sender_scoped_by_key() -> None:
    sender = senders_mod.get_or_create_sender("k1")
    assert senders_mod.get_sender("k1") is sender
    assert senders_mod.get_sender("k2") is None


def test_env_api_key_and_url_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    monkeypatch.setenv("HEXGATE_API_URL", "https://prod.example.com/")
    sender = senders_mod.get_or_create_sender()
    assert sender is not None
    assert sender._api_key == "env_key"
    assert sender._endpoint == "https://prod.example.com/v1/traces"


def test_explicit_args_win_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    monkeypatch.setenv("HEXGATE_API_URL", "https://env.example.com")
    sender = senders_mod.get_or_create_sender(
        "explicit_key", "https://explicit.example.com"
    )
    assert sender._api_key == "explicit_key"
    assert sender._endpoint == "https://explicit.example.com/v1/traces"


def test_otlp_endpoint_env_wins_over_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Collector can live on its own host/port; the dedicated env var
    points there without touching where the control-plane API lives."""
    monkeypatch.setenv("HEXGATE_API_URL", "https://api.example.com")
    monkeypatch.setenv(
        "HEXGATE_OTLP_ENDPOINT", "https://otlp.example.com:4318/v1/traces"
    )
    sender = senders_mod.get_or_create_sender("k")
    assert sender._endpoint == "https://otlp.example.com:4318/v1/traces"


# ---------------------------------------------------------------------------
# HEXGATE_LOCAL_MODE gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_local_mode_env_suppresses(
    monkeypatch: pytest.MonkeyPatch, truthy: str
) -> None:
    """Any truthy value of HEXGATE_LOCAL_MODE makes get_or_create_sender()
    return None even when an api_key is in env."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, truthy)
    assert senders_mod.get_or_create_sender() is None
    assert senders_mod.get_sender("real_key") is None


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", ""])
def test_local_mode_falsy_does_not_suppress(
    monkeypatch: pytest.MonkeyPatch, falsy: str
) -> None:
    """Explicit falsy values behave as if unset — symmetry with the
    truthy parametrize prevents a future refactor from accidentally
    making `HEXGATE_LOCAL_MODE=0` count as 'on'."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, falsy)
    assert senders_mod.get_or_create_sender() is not None


def test_local_mode_explicit_key_arg_still_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate fires even when a caller passes an explicit api_key —
    adapter wrappers that do `configure(api_key=...)` post-bootstrap
    must respect local mode too."""
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    assert senders_mod.get_or_create_sender("explicit_key") is None


def test_local_mode_logs_suppression_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A single INFO line at the first suppression; further calls stay
    silent so a busy startup doesn't repeat itself."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    with caplog.at_level(logging.INFO, logger="hexgate.tracing._senders"):
        senders_mod.get_or_create_sender()
        senders_mod.get_or_create_sender()
        senders_mod.get_or_create_sender("other_key")
    suppressed = [r for r in caplog.records if "suppressed" in r.message]
    assert len(suppressed) == 1


def test_local_mode_silent_when_no_key_present(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No key + local mode is the OSS "I never set a key" case — no log
    line, because there's no surprise to disambiguate."""
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    with caplog.at_level(logging.INFO, logger="hexgate.tracing._senders"):
        senders_mod.get_or_create_sender()
    suppressed = [r for r in caplog.records if "suppressed" in r.message]
    assert suppressed == []


# ---------------------------------------------------------------------------
# shutdown() — closes every sender in one call
# ---------------------------------------------------------------------------


async def test_shutdown_closes_every_sender() -> None:
    sender_a = senders_mod.get_or_create_sender("k1")
    sender_b = senders_mod.get_or_create_sender("k2")
    await senders_mod.shutdown()
    assert senders_mod._senders == {}
    assert sender_a._closing is True
    assert sender_b._closing is True
