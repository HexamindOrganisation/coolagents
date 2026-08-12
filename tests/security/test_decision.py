"""Tests for :mod:`hexgate.security.decision` — rendering + the multi-role fold.

Two halves, both engine-free:

* :class:`Decision` rendering (``as_error_payload`` / ``as_error_message``).
  These helpers used to be duplicated as private ``_render_decision`` functions
  across every adapter; they now live on :class:`Decision`, so this one file
  covers all adapters at once.
* :func:`combine_role_verdicts`, the permissive union over a caller's roles.
  Pure, so it is pinned here with a stub evaluator rather than through an engine.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from hexgate.security.decision import (
    Decision,
    DecisionOutcome,
    Verdict,
    combine_role_verdicts,
)
from hexgate.security.enforcer import MAX_EVALUATED_ROLES


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
    """``role`` names the role that would grant the call, not the caller's first."""
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
    """A deny has no deciding role — no role granted the call, so naming one
    (e.g. the caller's first) would misdirect the model."""
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
    """The caller's other roles are withheld, same minimisation as attributes."""
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
# combine_role_verdicts — the permissive union over a caller's roles
#
# Pure fold over Verdicts: no engine, no context, no enforcer. The stub
# ``_engine`` below maps role -> outcome so each case reads as a truth table.
# ---------------------------------------------------------------------------


def _engine(
    table: dict[str | None, Verdict],
) -> tuple[Callable[[str | None], Verdict], list[str | None]]:
    """A canned per-role evaluator plus the list of roles it was asked about."""
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
    """Outcome is order-independent; only which role gets the credit is not."""
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
    """D2, the locked precedence: approval is NOT sticky.

    One role granting unconditional access removes the approval gate another
    role would have imposed. A reader who assumes the opposite (any role needing
    approval forces approval) should land on this assertion — that reading is
    restrictive and contradicts the permissive union.
    """
    evaluate, _ = _engine({"a": _approval(), "b": _ALLOW})

    verdict, deciding = combine_role_verdicts(["a", "b"], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding == "b"


def test_combine_short_circuits_on_the_first_allow() -> None:
    """The common case costs one engine invocation, not one per role."""
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
    """D12: a one-role caller is byte-identical to evaluating that role alone."""
    original = _deny('Policy denied tool "refund"', violations=("args.amount <= 100",))
    evaluate, _ = _engine({"billing": original})

    verdict, deciding = combine_role_verdicts(["billing"], evaluate)

    assert verdict is original
    assert deciding is None


def test_combine_identical_denials_collapse_to_one_verbatim() -> None:
    """The common multi-role deny: every role resolves to the same policy, so
    the message must not repeat itself once per role."""
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
    """A file-scope hint promises the scope the caller may stay within, so two
    different scopes cannot be merged into one true statement."""
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
    """An unbounded merge would exceed DecisionEvent.reason's 4096-char limit
    and the platform would reject the whole audit event."""
    from hexgate.security.decision import _MAX_REASON_CHARS

    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES)]
    table = {role: _deny(f"{role}: " + "x" * 400) for role in roles}
    evaluate, _ = _engine(table)

    verdict, _ = combine_role_verdicts(roles, evaluate)

    assert len(verdict.reason) <= _MAX_REASON_CHARS
    assert "more roles" in verdict.reason  # truncation is disclosed, not hidden


def test_combine_none_role_evaluates_the_default_policy() -> None:
    """The no-roles case: the enforcer passes [None], never an empty list."""
    evaluate, seen = _engine({None: _ALLOW})

    verdict, deciding = combine_role_verdicts([None], evaluate)

    assert verdict.outcome is DecisionOutcome.ALLOW
    assert deciding is None
    assert seen == [None]


def test_combine_rejects_an_empty_role_list() -> None:
    """Evaluating nothing would fail open — the loudest possible bug."""
    evaluate, _ = _engine({})

    with pytest.raises(ValueError, match="at least one role"):
        combine_role_verdicts([], evaluate)
