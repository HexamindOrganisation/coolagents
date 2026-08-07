"""PolicyEnforcer emission paths into the audit sender."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from hexgate.audit import AuditEvent
from hexgate.tracing import _senders
from hexgate.runtime.context import HexgateContext
from hexgate.security.decision import DecisionOutcome, Verdict
from hexgate.security.enforcer import PolicyEnforcer


class _StubEngine:
    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict:
        return Verdict(outcome=DecisionOutcome.DENY, reason="stub")


class _CapturingSender:
    """Duck-typed stand-in for AuditSender — only needs emit() for these tests."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


@pytest.fixture(autouse=True)
def _reset_audit_senders() -> None:
    _senders._senders.clear()
    yield
    _senders._senders.clear()


def test_no_sender_means_no_emit() -> None:
    enforcer = PolicyEnforcer(_StubEngine(), agent_name="r")  # no audit_sender
    decision = enforcer.decide("read_file", {"path": "/x"})
    assert decision.outcome is DecisionOutcome.DENY


def test_sender_no_user_emits_with_empty_envelope() -> None:
    sender = _CapturingSender()
    PolicyEnforcer(_StubEngine(), agent_name="r", audit_sender=sender).decide(
        "read_file", {}
    )
    assert len(sender.events) == 1
    assert sender.events[0].user_id == ""
    assert sender.events[0].session_id == ""


async def test_sender_with_user_populates_envelope_from_user() -> None:
    sender = _CapturingSender()
    enforcer = PolicyEnforcer(_StubEngine(), agent_name="r", audit_sender=sender)
    async with HexgateContext(
        user_id="alice", user_roles=["analyst"], session_id="sess_42"
    ):
        decision = enforcer.decide("read_file", {})
    ev = sender.events[0]
    assert decision.role == "analyst"  # role propagates from HexgateContext to Decision
    assert ev.user_id == "alice"
    assert ev.session_id == "sess_42"
    assert ev.decision is decision  # same Decision instance wrapped


def test_caller_mutation_after_decide_does_not_alter_audit_snapshot() -> None:
    """Audit must snapshot arguments at decision time — nested mutations
    by the caller after decide() returns must not leak into the event."""
    sender = _CapturingSender()
    enforcer = PolicyEnforcer(_StubEngine(), agent_name="r", audit_sender=sender)
    args = {"config": {"mode": "safe"}, "items": ["a"]}
    enforcer.decide("read_file", args)
    args["config"]["mode"] = "mutated"
    args["items"].append("b")
    snapshot = sender.events[0].decision.arguments
    assert snapshot == {"config": {"mode": "safe"}, "items": ["a"]}


async def test_user_session_id_none_normalizes_to_empty_string() -> None:
    sender = _CapturingSender()
    enforcer = PolicyEnforcer(_StubEngine(), agent_name="r", audit_sender=sender)
    async with HexgateContext(
        user_id="bob", user_roles=["reader"]
    ):  # session_id defaults to None
        enforcer.decide("read_file", {})
    ev = sender.events[0]
    assert ev.user_id == "bob"
    assert ev.session_id == ""
