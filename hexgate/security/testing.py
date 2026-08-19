"""Assertion helpers for unit-testing policies.

Wrap the same evaluation path the SDK enforces with, so a policy authored in
code (or YAML) can be exercised in a pytest suite:

    from hexgate.security import PolicyBuilder, C, assert_allows, assert_denies

    policy = PolicyBuilder().allow("refund", when=[C("args.amount") <= 500]).build()
    assert_allows(policy, "refund", {"amount": 100})
    assert_denies(policy, "refund", {"amount": 999})

``policy`` may be an :class:`AgentPolicy` (single role) or a :class:`PolicySet`
(role-aware — pass ``role=``).
"""

from __future__ import annotations

from typing import Any

from hexgate.security.decision import DecisionOutcome
from hexgate.security.models import AgentPolicy
from hexgate.security.policy import evaluate_tool_call
from hexgate.security.policy_set import PolicySet

Policy = AgentPolicy | PolicySet


def _outcome(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None,
    role: str | None,
    attributes: dict[str, Any] | None,
) -> DecisionOutcome:
    if isinstance(policy, PolicySet):
        return policy.evaluate(
            role=role, tool=tool, args=args or {}, attributes=attributes
        ).outcome
    return evaluate_tool_call(
        policy, tool, args or {}, role=role, attributes=attributes
    ).outcome


def _check(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None,
    role: str | None,
    attributes: dict[str, Any] | None,
    expected: DecisionOutcome,
) -> None:
    actual = _outcome(policy, tool, args, role, attributes)
    if actual is not expected:
        scope = f"role={role!r} " if role is not None else ""
        raise AssertionError(
            f"expected {expected.value} for {scope}{tool}({args or {}}), "
            f"got {actual.value}"
        )


def assert_allows(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Assert the policy ALLOWS this call.

    ``attributes`` supplies the caller's ABAC bag for ``ctx.*`` constraints,
    mirroring what :class:`HexgateContext` carries at runtime."""
    _check(policy, tool, args, role, attributes, DecisionOutcome.ALLOW)


def assert_denies(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Assert the policy DENIES this call."""
    _check(policy, tool, args, role, attributes, DecisionOutcome.DENY)


def assert_needs_approval(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> None:
    """Assert the policy routes this call to approval."""
    _check(policy, tool, args, role, attributes, DecisionOutcome.NEEDS_APPROVAL)
