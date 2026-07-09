"""hexgate.tracing._senders — the shared (api_key, path) registry and the
HEXGATE_LOCAL_MODE gate, tested directly against the neutral module rather
than through hexgate.audit or hexgate.tracing.usage.

Moved here from tests/audit/test_configure.py under Design C: this is the
generic registry machinery both audit.py and usage.py import, not
decisions-specific behavior — see Specs/token_counts.md for the full
writeup.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

import hexgate.tracing._senders as senders_mod

_DECISIONS_PATH = "/v1/audit/decisions"
_USAGE_PATH = "/v1/audit/llm-invocations"


@pytest.fixture(autouse=True)
def _isolate_sender_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the sender registry + clear HEXGATE_* env between tests."""
    senders_mod._senders.clear()
    senders_mod._logged_local_mode_suppressed.clear()
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv(senders_mod._LOCAL_MODE_ENV, raising=False)
    yield
    senders_mod._senders.clear()
    senders_mod._logged_local_mode_suppressed.clear()


# ---------------------------------------------------------------------------
# get_or_create_sender() / get_sender() — generic registry mechanics
# ---------------------------------------------------------------------------


def test_returns_none_when_no_key_anywhere() -> None:
    assert senders_mod.get_or_create_sender(_DECISIONS_PATH) is None
    assert senders_mod.get_sender(_DECISIONS_PATH) is None


def test_idempotent_per_key_and_path_returns_same_sender() -> None:
    first = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")
    second = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")  # reuse
    assert first is second


def test_distinct_keys_get_distinct_senders() -> None:
    sender_a = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")
    sender_b = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k2")
    assert sender_a is not sender_b
    assert sender_a._client.headers["Authorization"] == "Bearer k1"
    assert sender_b._client.headers["Authorization"] == "Bearer k2"


def test_same_key_distinct_paths_get_distinct_senders() -> None:
    """The whole point of the (api_key, path) composite key: one
    HEXGATE_API_KEY covers both decisions and LLM usage for the same
    project, but each event type needs its own live connection to its own
    endpoint — see Specs/token_counts.md."""
    decisions_sender = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")
    usage_sender = senders_mod.get_or_create_sender(_USAGE_PATH, "k1")
    assert decisions_sender is not usage_sender
    assert decisions_sender._endpoint.endswith(_DECISIONS_PATH)
    assert usage_sender._endpoint.endswith(_USAGE_PATH)
    # Same bearer token, different connections.
    assert (
        decisions_sender._client.headers["Authorization"]
        == usage_sender._client.headers["Authorization"]
        == "Bearer k1"
    )


def test_get_sender_scoped_by_key_and_path() -> None:
    sender = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")
    assert senders_mod.get_sender(_DECISIONS_PATH, "k1") is sender
    assert senders_mod.get_sender(_DECISIONS_PATH, "k2") is None
    assert senders_mod.get_sender(_USAGE_PATH, "k1") is None  # different path


def test_env_api_key_and_url_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    monkeypatch.setenv("HEXGATE_API_URL", "https://prod.example.com/")
    sender = senders_mod.get_or_create_sender(_DECISIONS_PATH)
    assert sender is not None
    assert sender._endpoint == f"https://prod.example.com{_DECISIONS_PATH}"


def test_explicit_args_win_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "env_key")
    monkeypatch.setenv("HEXGATE_API_URL", "https://env.example.com")
    sender = senders_mod.get_or_create_sender(
        _DECISIONS_PATH, "explicit_key", "https://explicit.example.com"
    )
    assert sender._client.headers["Authorization"] == "Bearer explicit_key"
    assert sender._endpoint == f"https://explicit.example.com{_DECISIONS_PATH}"


# ---------------------------------------------------------------------------
# HEXGATE_LOCAL_MODE gate — shared by every path through this registry
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_local_mode_env_suppresses_every_path(
    monkeypatch: pytest.MonkeyPatch, truthy: str
) -> None:
    """Any truthy value of HEXGATE_LOCAL_MODE makes get_or_create_sender()
    return None even when an api_key is in env — for every path sharing
    this registry, not just decisions."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, truthy)
    assert senders_mod.get_or_create_sender(_DECISIONS_PATH) is None
    assert senders_mod.get_or_create_sender(_USAGE_PATH) is None
    assert senders_mod.get_sender(_DECISIONS_PATH, "real_key") is None


@pytest.mark.parametrize("falsy", ["0", "false", "no", "off", ""])
def test_local_mode_falsy_does_not_suppress(
    monkeypatch: pytest.MonkeyPatch, falsy: str
) -> None:
    """Explicit falsy values behave as if unset — symmetry with the
    truthy parametrize prevents a future refactor from accidentally
    making `HEXGATE_LOCAL_MODE=0` count as 'on'."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, falsy)
    sender = senders_mod.get_or_create_sender(_DECISIONS_PATH)
    assert sender is not None


def test_local_mode_explicit_key_arg_still_suppressed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gate fires even when a caller passes an explicit api_key —
    adapter wrappers that do `configure(api_key=...)` post-bootstrap
    must respect local mode too."""
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    assert senders_mod.get_or_create_sender(_DECISIONS_PATH, "explicit_key") is None


def test_local_mode_logs_suppression_once_per_path(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A single INFO line at the first suppression per path; further calls
    for the same path stay silent so a busy startup doesn't repeat itself.
    A different path (decisions vs. usage) gets its own first notice."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    with caplog.at_level(logging.INFO, logger="hexgate.tracing._senders"):
        senders_mod.get_or_create_sender(_DECISIONS_PATH)
        senders_mod.get_or_create_sender(_DECISIONS_PATH)
        senders_mod.get_or_create_sender(_DECISIONS_PATH)
        senders_mod.get_or_create_sender(_USAGE_PATH)
    suppressed = [r for r in caplog.records if "suppressed" in r.message]
    assert len(suppressed) == 2  # one for decisions, one for usage
    assert any(_DECISIONS_PATH in r.message for r in suppressed)
    assert any(_USAGE_PATH in r.message for r in suppressed)


def test_local_mode_silent_when_no_key_present(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No key + local mode is the OSS "I never set a key" case — no log
    line, because there's no surprise to disambiguate."""
    monkeypatch.setenv(senders_mod._LOCAL_MODE_ENV, "1")
    with caplog.at_level(logging.INFO, logger="hexgate.tracing._senders"):
        senders_mod.get_or_create_sender(_DECISIONS_PATH)
    suppressed = [r for r in caplog.records if "suppressed" in r.message]
    assert suppressed == []


# ---------------------------------------------------------------------------
# shutdown() — drains every path in one call
# ---------------------------------------------------------------------------


async def test_shutdown_drains_every_path_for_a_key() -> None:
    decisions_sender = senders_mod.get_or_create_sender(_DECISIONS_PATH, "k1")
    usage_sender = senders_mod.get_or_create_sender(_USAGE_PATH, "k1")
    await senders_mod.shutdown()
    assert senders_mod._senders == {}
    assert decisions_sender._closing is True
    assert usage_sender._closing is True
