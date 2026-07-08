"""Tests for policy document schema validation (``security/models.py``).

Focus: the ``constraints`` field_validator that parses every constraint at
``model_validate`` time, so a malformed expression fails at policy load rather
than lazily at the first matching tool call.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hexgate.security.models import AgentPolicy, BaseToolPolicy, FileToolPolicy


def test_valid_constraints_load() -> None:
    policy = BaseToolPolicy(
        mode="allow",
        constraints=["args.amount <= 500", 'args.currency == "USD"'],
    )
    assert policy.constraints == ["args.amount <= 500", 'args.currency == "USD"']


def test_malformed_constraint_rejected_at_load() -> None:
    # ``=<`` is not a valid operator — must fail at construction, not at call time.
    with pytest.raises(ValidationError):
        BaseToolPolicy(mode="allow", constraints=["args.amount =< 500"])


def test_malformed_constraint_rejected_via_model_validate() -> None:
    with pytest.raises(ValidationError):
        AgentPolicy.model_validate(
            {
                "version": 1,
                "default_policy": {"mode": "deny"},
                "tools": {
                    "refund_order": {"mode": "allow", "constraints": ["nonsense"]}
                },
            }
        )


def test_file_tool_policy_inherits_validator() -> None:
    # FileToolPolicy subclasses BaseToolPolicy, so the validator applies too.
    with pytest.raises(ValidationError):
        FileToolPolicy(mode="allow", constraints=["args.path in"])


def test_empty_constraints_ok() -> None:
    assert BaseToolPolicy(mode="allow").constraints == []


def test_valid_full_policy_document() -> None:
    policy = AgentPolicy.model_validate(
        {
            "version": 1,
            "default_policy": {"mode": "deny"},
            "tools": {
                "web_search": {"mode": "allow"},
                "refund_order": {
                    "mode": "allow",
                    "constraints": ["args.amount <= 500", 'args.currency == "USD"'],
                },
            },
        }
    )
    assert policy.tools["refund_order"].constraints[0] == "args.amount <= 500"
