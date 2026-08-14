"""End-to-end audit emission against a live platform + ClickHouse.

Requires: `make clickhouse-up` and `make platform-api` running, and
`HEXGATE_API_KEY` set to a token minted via the dashboard.

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import asyncio
import os

import httpx
import pytest

import hexgate.audit as audit_mod
from hexgate.audit import AuditEvent
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing import _senders

pytestmark = pytest.mark.integration

PLATFORM_URL = os.environ.get("HEXGATE_API_URL", "http://localhost:8000").rstrip("/")
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


async def test_wire_format_accepted_by_platform() -> None:
    """Manual POST proves the SDK wire format matches the platform body model."""
    _need_token()
    ev = _event()
    payload = ev.as_payload()
    # A platform predating these keys ignores them (no extra="forbid").
    assert payload["user_roles"] == ["analyst", "billing"]
    assert payload["role"] == "analyst"
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.post(
            f"{PLATFORM_URL}/v1/audit/decisions",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=payload,
        )
    assert response.status_code == 202, f"{response.status_code}: {response.text}"
    assert response.json()["event_id"] == str(ev.event_id)


async def test_sender_emits_end_to_end_without_errors() -> None:
    """Drives the full SDK path: configure → emit → drain. Confirms no raised exceptions."""
    _need_token()
    _senders._senders.clear()  # reset for a clean configure
    sender = audit_mod.configure(TOKEN, PLATFORM_URL)
    try:
        sender.emit(_event())
        results = await asyncio.gather(*sender._tasks, return_exceptions=True)  # type: ignore[attr-defined]
        for r in results:
            assert not isinstance(r, BaseException), f"task raised: {r}"
    finally:
        await audit_mod.shutdown()
