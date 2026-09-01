"""Tests for :mod:`hexgate.security.decision` — rendering + the multi-role fold.

:class:`Decision`'s renderers are shared by every adapter, so this one file
covers them all. :func:`combine_role_verdicts` is pure, so it is pinned with a
stub evaluator rather than an engine.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from hexgate.runtime.roles import MAX_EVALUATED_ROLES
from hexgate.security.decision import (
    Decision,
    DecisionOutcome,
    Verdict,
    combine_role_verdicts,
)


def _deny_decision() -> Decision:
    return Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="support-bot",
        tool_name="read_file",
        user_roles=("support",),
        # No deciding_role: a deny means no role granted the call.
        reason='Policy denied tool "read_file"',
        error_type="policy_denied",
    )


def _approval_decision() -> Decision:
    return Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name="support-bot",
        tool_name="write_file",
        user_roles=("support",),
        deciding_role="support",
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


def test_as_error_message_separates_the_reason_as_its_own_clause() -> None:
    """The reason is introduced with a colon and terminated, so a guard's
    lowercase imperative does not run into the closing sentence."""
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="send",
        reason="remove the credential",
        error_type="guard_denied",
    )

    msg = decision.as_error_message()
    assert ": remove the credential. The tool was not executed." in msg
    assert "credential The" not in msg  # no run-on into the closing sentence


def test_as_error_message_does_not_double_terminate_a_punctuated_reason() -> None:
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="send",
        reason="Blocked by a policy guard.",
        error_type="guard_denied",
    )

    assert "policy guard.. " not in decision.as_error_message()
    assert "policy guard. The tool was not executed." in decision.as_error_message()


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
    }


def test_as_error_payload_role_is_the_deciding_role_on_approval() -> None:
    """``role`` is the granting role, not the caller's first."""
    payload = Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name="agent",
        tool_name="refund",
        user_roles=("support", "billing"),
        deciding_role="billing",
        error_type="approval_required",
    ).as_error_payload()

    assert payload["role"] == "billing"


def test_as_error_payload_omits_role_on_deny() -> None:
    """A deny has no granting role, so naming one would misdirect the model."""
    decision = Decision(
        outcome=DecisionOutcome.DENY,
        agent_name="agent",
        tool_name="tool",
        user_roles=("support", "billing"),
        reason="...",
        error_type="policy_denied",
    )

    assert "role" not in decision.as_error_payload()


def test_as_error_payload_never_leaks_the_role_list_to_the_llm() -> None:
    """The caller's other roles are withheld, like attributes."""
    payload = Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name="agent",
        tool_name="refund",
        user_roles=("support", "billing"),
        deciding_role="billing",
    ).as_error_payload()

    assert "user_roles" not in payload
    assert "roles" not in payload


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


# ---------------------------------------------------------------------------
# combine_role_verdicts — the permissive union. ``_engine`` maps role -> outcome
# so each case reads as a truth table.
# ---------------------------------------------------------------------------


def _engine(
    table: dict[str | None, Verdict],
) -> tuple[Callable[[str | None], Verdict], list[str | None]]:
    """A canned per-role evaluator plus the roles it was asked about."""
    seen: list[str | None] = []

    def evaluate(role: str | None) -> Verdict:
        seen.append(role)
        return table[role]

    return evaluate, seen


_ALLOW = Verdict(outcome=DecisionOutcome.ALLOW)


def _deny(reason: str = "nope", **kwargs: object) -> Verdict:
    return Verdict(outcome=DecisionOutcome.DENY, reason=reason, **kwargs)  # type: ignore[arg-type]


def _approval(reason: str = "needs a human") -> Verdict:
    return Verdict(outcome=DecisionOutcome.NEEDS_APPROVAL, reason=reason)


def test_combine_allow_plus_deny_allows() -> None:
    evaluate, _ = _engine({"a": _ALLOW, "b": _deny()})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding == "a"


def test_combine_deny_plus_allow_allows_regardless_of_order() -> None:
    """Outcome is order-independent; the credited role is not."""
    evaluate, _ = _engine({"a": _deny(), "b": _ALLOW})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding == "b"


def test_combine_approval_plus_deny_needs_approval() -> None:
    evaluate, _ = _engine({"a": _deny(), "b": _approval()})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.NEEDS_APPROVAL
    assert deciding == "b"


def test_combine_allow_beats_needs_approval() -> None:
    """D2: approval is NOT sticky. One role granting outright removes another
    role's gate. A reader assuming the opposite lands here."""
    evaluate, _ = _engine({"a": _approval(), "b": _ALLOW})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding == "b"


def test_combine_short_circuits_on_the_first_allow() -> None:
    """The common case costs one engine invocation."""
    evaluate, seen = _engine({"a": _ALLOW, "b": _deny(), "c": _deny()})

    combine_role_verdicts(["a", "b", "c"], evaluate)

    assert seen == ["a"]


def test_combine_reports_the_first_allowing_role_not_the_last() -> None:
    evaluate, _ = _engine({"a": _deny(), "b": _ALLOW, "c": _ALLOW})

    _, deciding = combine_role_verdicts(["a", "b", "c"], evaluate)

    assert deciding == "b"


def test_combine_all_deny_denies_with_no_deciding_role() -> None:
    evaluate, seen = _engine({"a": _deny("a said no"), "b": _deny("b said no")})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.DENY
    assert deciding is None
    assert seen == ["a", "b"]  # no short-circuit: every role is asked


def test_combine_single_role_returns_the_verdict_verbatim() -> None:
    """D12: a one-role caller matches evaluating that role alone."""
    original = _deny('Policy denied tool "refund"', violations=("args.amount <= 100",))
    evaluate, _ = _engine({"billing": original})

    verdict, deciding = combine_role_verdicts(["billing"], evaluate)

    assert verdict is original
    assert deciding is None


def test_combine_identical_denials_collapse_to_one_verbatim() -> None:
    """Roles sharing a policy must not repeat the message once per role."""
    original = _deny('Policy denied tool "refund"')
    evaluate, _ = _engine({"a": original, "b": original})

    verdict, _ = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict is original


def test_combine_differing_denials_name_every_role_and_union_violations() -> None:
    evaluate, _ = _engine(
        {
            "billing": _deny("amount too high", violations=("args.amount <= 100",)),
            "support": _deny("wrong currency", violations=("args.currency == 'USD'",)),
        }
    )

    verdict, _ = combine_role_verdicts(["billing", "support"], evaluate)

    assert verdict.outcome is DecisionOutcome.DENY
    assert "billing" in verdict.reason and "support" in verdict.reason
    assert "amount too high" in verdict.reason
    assert "wrong currency" in verdict.reason
    assert verdict.violations == ("args.amount <= 100", "args.currency == 'USD'")


def test_combine_dedups_violations_shared_across_roles() -> None:
    evaluate, _ = _engine(
        {
            "a": _deny("a", violations=("args.amount <= 100",)),
            "b": _deny("b", violations=("args.amount <= 100", "args.x == 1")),
        }
    )

    verdict, _ = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.violations == ("args.amount <= 100", "args.x == 1")


def test_combine_keeps_a_unanimous_hint_and_drops_conflicting_ones() -> None:
    """A hint promises the scope the caller may stay within; two scopes cannot
    merge into one true statement."""
    same = {"allowed_paths": ["docs/**"]}
    evaluate, _ = _engine(
        {"a": _deny("a", hint=same), "b": _deny("b", hint=dict(same))}
    )
    verdict, _ = combine_role_verdicts(["a", "b"], evaluate)
    assert verdict.hint == same

    evaluate, _ = _engine(
        {
            "a": _deny("a", hint={"allowed_paths": ["docs/**"]}),
            "b": _deny("b", hint={"allowed_paths": ["src/**"]}),
        }
    )
    verdict, _ = combine_role_verdicts(["a", "b"], evaluate)
    assert verdict.hint is None


def test_combine_bounds_a_merged_reason_to_the_platform_cap() -> None:
    """Over DecisionEvent.reason's 4096-char limit the platform rejects the
    whole audit event."""
    from hexgate.security.decision import _MAX_REASON_CHARS

    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES)]
    table = {role: _deny(f"{role}: " + "x" * 400) for role in roles}
    evaluate, _ = _engine(table)

    verdict, _ = combine_role_verdicts(roles, evaluate)

    assert len(verdict.reason) <= _MAX_REASON_CHARS
    assert "more roles" in verdict.reason  # truncation is disclosed, not hidden


def test_combine_none_role_evaluates_the_default_policy() -> None:
    """The enforcer passes [None] for no roles, never an empty list."""
    evaluate, seen = _engine({None: _ALLOW})

    verdict, deciding = combine_role_verdicts([None], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding is None
    assert seen == [None]


def test_combine_rejects_an_empty_role_list() -> None:
    """Evaluating nothing would fail open."""
    evaluate, _ = _engine({})

    with pytest.raises(ValueError, match="at least one role"):
        combine_role_verdicts([], evaluate)
