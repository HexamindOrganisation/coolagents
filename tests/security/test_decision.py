"""Tests for :class:`Decision` rendering (``as_error_payload`` / ``as_error_message``).

These rendering helpers used to be duplicated as private ``_render_decision``
functions across every adapter. They now live as methods on :class:`Decision`
itself, so this single test file covers all adapters at once.
"""

from __future__ import annotations

from hexgate.security.decision import Decision, DecisionOutcome


def _deny_decision() -> Decision:
    return Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="support-bot",
        tool_name="read_file",
        role="support",
        reason='Policy denied tool "read_file"',
        error_type="policy_denied",
    )


def _approval_decision() -> Decision:
    return Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name="support-bot",
        tool_name="write_file",
        reason='Policy requires approval for tool "write_file"',
        error_type="approval_required",
        arguments={"path": "/tmp/x"},
    )


# ---------------------------------------------------------------------------
# as_error_message — string rendering for OpenAI/Google/pydantic_ai adapters
# ---------------------------------------------------------------------------


def test_as_error_message_for_deny_uses_policy_denied_marker() -> None:
    msg = _deny_decision().as_error_message()

    assert msg.startswith("[policy_denied]")
    assert "read_file" in msg
    assert "denied by the agent policy" in msg
    assert "not executed" in msg


def test_as_error_message_for_needs_approval_uses_distinct_marker() -> None:
    msg = _approval_decision().as_error_message()

    assert msg.startswith("[approval_required]")
    assert "write_file" in msg
    assert "requires human approval" in msg
    assert "not executed" in msg


def test_as_error_message_uses_error_type_as_marker_when_set() -> None:
    """The bracketed prefix is ``decision.error_type`` so the LLM can pattern-match."""
    deny_msg = _deny_decision().as_error_message()
    approval_msg = _approval_decision().as_error_message()

    assert deny_msg.startswith("[policy_denied]")
    assert approval_msg.startswith("[approval_required]")
    # Markers must not overlap so the LLM can disambiguate.
    assert "[approval_required]" not in deny_msg
    assert "[policy_denied]" not in approval_msg


def test_as_error_message_falls_back_to_outcome_value_when_no_error_type() -> None:
    """Without an explicit ``error_type`` the outcome name is used as the marker."""
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="tool",
        reason="...",
    )

    assert decision.as_error_message().startswith("[deny]")


# ---------------------------------------------------------------------------
# as_error_payload — dict rendering for LangChain GuardedTool
# ---------------------------------------------------------------------------


def test_as_error_payload_includes_required_fields() -> None:
    payload = _deny_decision().as_error_payload()

    assert payload == {
        "type": "policy_denied",
        "message": 'Policy denied tool "read_file"',
        "tool_name": "read_file",
        "agent_name": "support-bot",
        "retryable": False,
        "role": "support",
    }


def test_as_error_payload_omits_role_when_none() -> None:
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="tool",
        reason="...",
        error_type="policy_denied",
    )

    assert "role" not in decision.as_error_payload()


def test_as_error_payload_includes_hint_when_set() -> None:
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="read_file",
        reason="path denied",
        error_type="policy_denied",
        hint={"allowed_paths": ["docs/**"]},
    )

    payload = decision.as_error_payload()

    assert payload["hint"] == {"allowed_paths": ["docs/**"]}


def test_as_error_payload_includes_violations_when_set() -> None:
    """WASM constraint violations reach the LLM as a structured list."""
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="refund",
        reason='Policy denied tool "refund": args.amount <= 100',
        error_type="policy_denied",
        violations=("args.amount <= 100",),
    )

    payload = decision.as_error_payload()

    assert payload["violations"] == ["args.amount <= 100"]


def test_as_error_payload_omits_violations_when_empty() -> None:
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="tool",
        reason="...",
        error_type="policy_denied",
    )

    assert "violations" not in decision.as_error_payload()


def test_as_error_payload_does_not_leak_arguments_to_the_llm() -> None:
    """``arguments`` is for host-side approval handlers, not the LLM payload."""
    payload = _approval_decision().as_error_payload()

    assert "arguments" not in payload


def test_from_verdict_carries_attribute_snapshot() -> None:
    """The attribute bag the decision was evaluated against is stamped on the
    Decision so in-process observers can see what drove a ctx.*-gated outcome."""
    from hexgate.security.decision import Verdict

    decision = Decision.from_verdict(
        Verdict(outcome=DecisionOutcome.ALLOW),
        agent_name="a",
        tool_name="refund",
        attributes={"department": "finance"},
    )
    assert decision.attributes == {"department": "finance"}


def test_as_error_payload_does_not_leak_attributes_to_the_llm() -> None:
    """``attributes`` is host-side context, never surfaced to the model."""
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="a",
        tool_name="refund",
        attributes={"department": "finance", "clearance_level": 3},
    )
    assert "attributes" not in decision.as_error_payload()
