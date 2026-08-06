"""PolicyEnforcer.decide → injected ``decision_observer`` paths.

Sibling to ``test_enforcer_audit.py``: same shape (stub engine, capturing
observer), different slot. The observer is the local-process hook —
``hexgate chat`` injects one to render denies in the REPL; metrics /
debuggers would slot in the same way.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import pytest

from hexgate.runtime.context import HexgateContext
from hexgate.security.decision import Decision, DecisionOutcome, Verdict
from hexgate.security.enforcer import PolicyEnforcer


class _StubEngine:
    """Returns the verdict it was constructed with; ignores inputs."""

    def __init__(self, verdict: Verdict) -> None:
        self._verdict = verdict

    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict:
        return self._verdict


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_observer_called_with_full_decision() -> None:
    """A configured observer receives the same Decision instance the
    enforcer returns to the caller — same object, not a copy."""
    captured: list[Decision] = []
    engine = _StubEngine(Verdict(outcome=DecisionOutcome.DENY, reason="stubbed deny"))
    enforcer = PolicyEnforcer(engine, agent_name="r", decision_observer=captured.append)

    returned = enforcer.decide("read_file", {"path": "/x"})

    assert len(captured) == 1
    assert captured[0] is returned
    assert captured[0].outcome is DecisionOutcome.DENY
    assert captured[0].reason == "stubbed deny"
    assert captured[0].tool_name == "read_file"


def test_observer_sees_all_three_outcomes() -> None:
    """Observer fires on allow / deny / needs_approval alike — filtering
    by outcome is the *caller's* job (the chat REPL mutes allows, but
    metrics collectors might count them)."""
    captured: list[Decision] = []
    for outcome in (
        DecisionOutcome.ALLOW,
        DecisionOutcome.DENY,
        DecisionOutcome.NEEDS_APPROVAL,
    ):
        engine = _StubEngine(Verdict(outcome=outcome, reason=f"{outcome.value}"))
        enforcer = PolicyEnforcer(
            engine, agent_name="r", decision_observer=captured.append
        )
        enforcer.decide("read_file", {})

    assert [d.outcome for d in captured] == [
        DecisionOutcome.ALLOW,
        DecisionOutcome.DENY,
        DecisionOutcome.NEEDS_APPROVAL,
    ]


async def test_observer_sees_role_and_args_from_user_scope() -> None:
    """The Decision the observer sees carries role from the active HexgateContext
    scope and the (deep-copied) arguments snapshot from the call site."""
    captured: list[Decision] = []
    engine = _StubEngine(Verdict(outcome=DecisionOutcome.DENY))
    enforcer = PolicyEnforcer(engine, agent_name="r", decision_observer=captured.append)
    async with HexgateContext(user_id="alice", user_roles=["analyst"]):
        enforcer.decide("read_file", {"path": "/etc/passwd"})

    assert captured[0].role == "analyst"
    assert captured[0].arguments == {"path": "/etc/passwd"}


# ---------------------------------------------------------------------------
# Isolation — a broken observer must not break enforcement
# ---------------------------------------------------------------------------


def test_observer_exception_does_not_break_decide(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Audit is observational; enforcement is authoritative. A buggy
    observer (chat-panel render bug, third-party subscriber raising)
    must not turn a clean DENY into an exception the agent sees."""

    def boom(_decision: Decision) -> None:
        raise RuntimeError("intentional")

    engine = _StubEngine(Verdict(outcome=DecisionOutcome.DENY, reason="x"))
    enforcer = PolicyEnforcer(engine, agent_name="r", decision_observer=boom)

    with caplog.at_level(logging.ERROR, logger="hexgate.security.enforcer"):
        decision = enforcer.decide("read_file", {})

    assert decision.outcome is DecisionOutcome.DENY
    assert any("decision_observer raised" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# No observer = no call
# ---------------------------------------------------------------------------


def test_no_observer_means_no_call() -> None:
    """Default ``decision_observer=None`` keeps the branch silent. Sanity
    check that the optional-injection shape works the same way the
    audit_sender slot does."""
    engine = _StubEngine(Verdict(outcome=DecisionOutcome.ALLOW))
    enforcer = PolicyEnforcer(engine, agent_name="r")
    # No assertion needed — if a missing observer raised on .decide(),
    # this would throw.
    assert enforcer.decide("read_file", {}).outcome is DecisionOutcome.ALLOW


# ---------------------------------------------------------------------------
# Two-slot independence: audit + observer
# ---------------------------------------------------------------------------


class _StubSender:
    """Duck-typed AuditSender — just records what got emitted."""

    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


def test_audit_and_observer_both_fire_independently() -> None:
    """Same Decision goes to both slots; they don't interact. A future
    refactor that 'shares' a code path between the two would break the
    'either can be on or off independently' contract."""
    captured: list[Decision] = []
    sender = _StubSender()
    engine = _StubEngine(Verdict(outcome=DecisionOutcome.DENY))
    enforcer = PolicyEnforcer(
        engine,
        agent_name="r",
        audit_sender=sender,  # type: ignore[arg-type]
        decision_observer=captured.append,
    )

    enforcer.decide("read_file", {})

    assert len(captured) == 1
    assert len(sender.events) == 1
    # Both saw the same Decision; the AuditEvent wraps it.
    assert sender.events[0].decision is captured[0]
