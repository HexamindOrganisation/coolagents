"""Load-time validation of ``run.*`` references.

Each rule guards a failure that would otherwise deny (or, for the list rule,
silently pass) at runtime with no hint of the real cause. Registries are
injected rather than read from ``run_facts`` so the list rule is testable
before any list-valued path is registered.
"""

from __future__ import annotations

import pytest

from hexgate.security.models import AgentPolicy
from hexgate.security.policy_set import (
    DEFAULT_ROLE_NAME,
    PolicySet,
    PolicySetError,
    _validate_run_refs,
)

_LIST_PATHS = frozenset({"tools_used"})
_SCALAR_PATHS = frozenset({"id", "agent", "elapsed_seconds", "tool_calls"})
_ROLE = "member"


def _policy(*constraints: str, tool: str = "refund") -> AgentPolicy:
    return AgentPolicy.model_validate(
        {"tools": {tool: {"mode": "allow", "constraints": list(constraints)}}}
    )


def _default_policy(*constraints: str) -> AgentPolicy:
    return AgentPolicy.model_validate(
        {"default_policy": {"mode": "allow", "constraints": list(constraints)}}
    )


def _validate(*constraints: str, policy: AgentPolicy | None = None) -> None:
    _validate_run_refs(
        {_ROLE: policy if policy is not None else _policy(*constraints)},
        scalar_paths=_SCALAR_PATHS,
        list_paths=_LIST_PATHS,
    )


# ---------------------------------------------------------------------------
# Rule A — unknown path
# ---------------------------------------------------------------------------


def test_unknown_run_path_is_rejected() -> None:
    """Without this rule, a typo like ``run.tool_call`` (singular) would
    resolve to missing and deny every call forever."""
    with pytest.raises(PolicySetError) as exc:
        _validate("run.tool_call < 5")

    message = str(exc.value)
    assert "tool_call" in message
    assert "unknown run.* path" in message
    assert "tool_calls" in message  # the registry, so the fix is visible
    assert "Upgrade the SDK or fix the path" in message


def test_known_run_paths_are_accepted() -> None:
    _validate(
        "run.tool_calls < 20", 'run.agent == "billing"', "run.elapsed_seconds < 300"
    )


def test_run_refs_are_validated_on_the_default_policy_too() -> None:
    with pytest.raises(PolicySetError, match="unknown run.* path"):
        _validate(policy=_default_policy("run.nope < 5"))


def test_a_policy_without_run_refs_is_unaffected() -> None:
    _validate("args.amount <= 50", 'ctx.department == "finance"', 'role == "admin"')


# ---------------------------------------------------------------------------
# Rule B — wrong depth
# ---------------------------------------------------------------------------


def test_deeper_run_path_is_rejected() -> None:
    """``run.id.value`` passes Rule A (``id`` is registered) but walks into a
    string and misses."""
    with pytest.raises(PolicySetError) as exc:
        _validate('run.id.value == "x"')

    assert "exactly two segments" in str(exc.value)
    assert "id.value" in str(exc.value)


def test_bare_run_is_a_parse_error_not_a_ref() -> None:
    """Rule B only checks depth 2+; this pins that a bare ``run`` never
    reaches it."""
    from hexgate.security.constraints import ConstraintParseError, parse_constraint

    with pytest.raises(ConstraintParseError, match="bare identifier"):
        parse_constraint('run == "x"')


# ---------------------------------------------------------------------------
# Rule C — a list-valued path where a scalar belongs
# ---------------------------------------------------------------------------

_LEGAL_LIST_SHAPES = [
    "count(run.tools_used) <= 6",
    'any(run.tools_used, . == "shell")',
    'every(run.tools_used, . != "shell")',
    'run.tools_used == ["shell"]',
    'run.tools_used != ["shell"]',
]

_ILLEGAL_LIST_SHAPES = [
    'run.tools_used not in ["shell"]',
    'run.tools_used in ["shell"]',
    "run.tools_used < 6",
    "run.tools_used <= 6",
    "run.tools_used > 6",
    "run.tools_used >= 6",
    "6 > run.tools_used",
]


@pytest.mark.parametrize("constraint", _LEGAL_LIST_SHAPES)
def test_legal_list_shapes_are_accepted(constraint: str) -> None:
    _validate(constraint)


@pytest.mark.parametrize("constraint", _ILLEGAL_LIST_SHAPES)
def test_illegal_list_shapes_are_rejected(constraint: str) -> None:
    with pytest.raises(PolicySetError, match="list-valued path"):
        _validate(constraint)


def test_not_in_message_names_the_silent_pass_and_the_fix() -> None:
    """``not in`` against a list-valued path evaluates True for every call —
    the message is the only signal the exclusion is a no-op."""
    with pytest.raises(PolicySetError) as exc:
        _validate('run.tools_used not in ["shell"]')

    message = str(exc.value)
    assert "silently passes" in message
    assert 'not any(run.tools_used, . == "<value>")' in message


def test_ordered_operator_message_names_the_silent_deny() -> None:
    with pytest.raises(PolicySetError) as exc:
        _validate("run.tools_used < 6")

    assert "silently fails every call" in str(exc.value)


def test_a_scalar_path_is_unaffected_by_the_list_rule() -> None:
    _validate("run.tool_calls < 20", "run.tool_calls in [1, 2]")


# ---------------------------------------------------------------------------
# Wiring — the check runs at PolicySet construction
# ---------------------------------------------------------------------------


def test_policy_set_construction_rejects_an_unknown_run_path() -> None:
    with pytest.raises(PolicySetError, match="unknown run.* path"):
        PolicySet({DEFAULT_ROLE_NAME: _policy("run.definitely_not_a_path < 5")})


def test_policy_set_construction_accepts_a_registered_run_path() -> None:
    PolicySet({DEFAULT_ROLE_NAME: _policy('run.agent == "billing"')})
