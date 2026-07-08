"""Return-based core behind the ``authorize_tool_call*`` wrappers.

:func:`evaluate_tool_call` answers the same question as
:func:`authorize_tool_call` but returns a :class:`Verdict` instead of
raising, and carries structured detail (a file-scope ``hint``) the raise
path can't. The wrapper's exception contract is covered by
``test_security.py``; here we pin the verdict shapes directly.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hexgate.security import (
    AgentPolicy,
    DecisionOutcome,
    Verdict,
    evaluate_tool_call,
)


def _policy(spec: dict) -> AgentPolicy:
    return AgentPolicy.model_validate(spec)


def test_evaluate_allows_explicit_tool() -> None:
    verdict = evaluate_tool_call(
        _policy(
            {
                "default_policy": {"mode": "deny"},
                "tools": {"web_search": {"mode": "allow"}},
            }
        ),
        "web_search",
    )
    assert verdict == Verdict(outcome=DecisionOutcome.ALLOW)
    assert verdict.allowed


def test_evaluate_denies_by_default() -> None:
    verdict = evaluate_tool_call(_policy({"default_policy": {"mode": "deny"}}), "fetch")
    assert verdict.outcome is DecisionOutcome.DENY
    assert verdict.reason == 'Policy denied tool "fetch"'
    assert not verdict.allowed


def test_evaluate_needs_approval() -> None:
    verdict = evaluate_tool_call(
        _policy({"tools": {"write_file": {"mode": "approval_required"}}}),
        "write_file",
    )
    assert verdict.outcome is DecisionOutcome.NEEDS_APPROVAL


def test_evaluate_failed_constraint_denies_with_reason() -> None:
    verdict = evaluate_tool_call(
        _policy(
            {
                "tools": {
                    "refund": {"mode": "allow", "constraints": ["args.amount <= 100"]}
                }
            }
        ),
        "refund",
        {"amount": 200},
    )
    assert verdict.outcome is DecisionOutcome.DENY
    assert "constraint failed" in verdict.reason


def test_evaluate_out_of_scope_path_denies_with_hint() -> None:
    """The win over the raise path: a path denial carries a structured hint."""
    verdict = evaluate_tool_call(
        _policy(
            {
                "default_policy": {"mode": "deny"},
                "tools": {
                    "read_file": {
                        "mode": "allow",
                        "file_scope": {"allowed_paths": ["docs/**"]},
                    }
                },
            }
        ),
        "read_file",
        {"file_path": "notes/todo.md"},
    )
    assert verdict.outcome is DecisionOutcome.DENY
    assert "requested path" in verdict.reason
    assert verdict.hint is not None


def test_malformed_constraint_rejected_at_load() -> None:
    """A bad constraint is a config error, not a denial — the model-level
    grammar validator now rejects it at policy load, before any tool call."""
    with pytest.raises(ValidationError):
        _policy(
            {"tools": {"refund": {"mode": "allow", "constraints": ["args.amount <="]}}}
        )
