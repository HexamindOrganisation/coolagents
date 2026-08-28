"""End-to-end audit emission against a live Collector → Redpanda → enricher
→ ClickHouse pipeline.

Requires: the platform stack running (`make clickhouse-up`, the Collector,
Redpanda and the enricher job — see platform/README), `HEXGATE_API_KEY` set
to a token minted via the dashboard, and `HEXGATE_OTLP_ENDPOINT` pointing at
the Collector's OTLP/HTTP receiver (default `http://localhost:4318/v1/traces`).

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import logging
import os

import pytest

import hexgate.audit as audit_mod
from hexgate.audit import AuditEvent
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing import _senders, semconv

pytestmark = pytest.mark.integration

OTLP_ENDPOINT = os.environ.get(
    "HEXGATE_OTLP_ENDPOINT", "http://localhost:4318/v1/traces"
)
TOKEN = os.environ.get("HEXGATE_API_KEY")


def _need_token() -> None:
    if not TOKEN:
        pytest.skip("HEXGATE_API_KEY not set; mint a token via the dashboard")


def _event() -> AuditEvent:
    # Multi-role on purpose: the only place the role fields meet a live
    # platform. (``role`` is a property over ``user_roles``, not an argument.)
    d = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="integration_agent",
        tool_name="read_file",
        user_roles=("analyst", "billing"),
        reason="integration test",
    )
    return AuditEvent(decision=d, user_id="u_test", session_id="s_test")


async def test_sender_exports_end_to_end_without_errors(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Drives the full SDK path: configure → emit → flush. The OTLP exporter
    reports transport/auth failures as ERROR log lines rather than raising,
    so a clean flush plus a silent exporter logger is the acceptance check."""
    _need_token()
    monkeypatch.setenv("HEXGATE_OTLP_ENDPOINT", OTLP_ENDPOINT)
    _senders._senders.clear()  # reset for a clean configure
    ev = _event()
    assert ev.span_attributes()[semconv.USER_ROLES] == ["analyst", "billing"]
    sender = audit_mod.configure(TOKEN)
    assert sender is not None
    with caplog.at_level(logging.WARNING, logger="opentelemetry"):
        try:
            sender.emit(ev)
        finally:
            await audit_mod.shutdown()
    assert caplog.records == [], [r.getMessage() for r in caplog.records]
