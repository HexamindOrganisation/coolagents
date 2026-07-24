"""usage.configure_usage_sender() — thin wiring onto the shared sender
registry, mirroring tests/audit/test_configure.py.

Generic registry mechanics live in tests/tracing/test_senders.py — this file
only checks that usage.py wires the shared registry to the right endpoint
(/v1/audit/llm-invocations), and that it truly shares the registry (and the
HEXGATE_LOCAL_MODE gate) with hexgate.audit rather than duplicating it.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

import hexgate.audit as audit_mod
import hexgate.tracing.usage as usage_mod
from hexgate.tracing import _senders


@pytest.fixture(autouse=True)
def _isolate_sender_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset the shared sender registry + clear HEXGATE_* env between tests."""
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv(_senders._LOCAL_MODE_ENV, raising=False)
    yield
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()


def test_returns_none_when_no_key_anywhere() -> None:
    assert usage_mod.configure_usage_sender() is None
    assert usage_mod.get_usage_sender() is None


def test_wires_to_llm_invocations_endpoint() -> None:
    sender = usage_mod.configure_usage_sender("k")
    assert sender is not None
    assert sender._endpoint == "https://app.hexgate.ai/v1/audit/llm-invocations"


def test_get_usage_sender_scoped_by_key() -> None:
    sender = usage_mod.configure_usage_sender("k1")
    assert usage_mod.get_usage_sender("k1") is sender
    assert usage_mod.get_usage_sender("k2") is None


def test_same_key_gets_distinct_sender_from_audit() -> None:
    """The one HEXGATE_API_KEY that covers a project's decisions also
    covers its LLM usage, but each event type gets its own live sender."""
    decisions_sender = audit_mod.configure("k1")
    usage_sender = usage_mod.configure_usage_sender("k1")
    assert decisions_sender is not usage_sender
    assert decisions_sender._endpoint.endswith("/v1/audit/decisions")
    assert usage_sender._endpoint.endswith("/v1/audit/llm-invocations")


def test_local_mode_suppresses_usage_sender_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """usage.py shares audit.py's HEXGATE_LOCAL_MODE gate via the shared
    registry — no separate copy of the check."""
    monkeypatch.setenv("HEXGATE_API_KEY", "real_key")
    monkeypatch.setenv(_senders._LOCAL_MODE_ENV, "1")
    assert usage_mod.configure_usage_sender() is None


async def test_either_modules_shutdown_drains_both() -> None:
    """A single shutdown() call — from either module — drains both event
    types' senders, per the Design C decision."""
    audit_mod.configure("k1")
    usage_mod.configure_usage_sender("k1")
    await usage_mod.shutdown()
    assert _senders._senders == {}
