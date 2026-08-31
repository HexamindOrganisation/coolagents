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


# --- policy-level constraints ----------------------------------------------


def test_policy_level_constraints_are_grammar_checked_at_load() -> None:
    """Same rule as a tool's list, via the shared ``_parse_all`` helper."""
    with pytest.raises(ValidationError):
        AgentPolicy(constraints=["args.amount =< 500"])


def test_policy_level_constraints_default_to_empty_and_unset() -> None:
    """``linker._reject_unsupported_module_fields`` keys on
    ``model_fields_set``, so an unset field must not register as authored."""
    policy = AgentPolicy()

    assert policy.constraints == []
    assert "constraints" not in policy.model_fields_set


def test_policy_level_constraints_are_not_folded_into_effective_tools() -> None:
    """``get_tool_policy`` returns ``effective_tools``; folding a role-wide list
    into a tool's own would make that return value a lie."""
    policy = AgentPolicy(
        constraints=["run.tool_calls < 3"],
        tools={"read_file": BaseToolPolicy(mode="allow")},
    )

    assert policy.effective_tools["read_file"].constraints == []
