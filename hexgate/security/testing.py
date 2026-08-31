"""Assertion helpers for unit-testing policies.

Wrap the same evaluation path the SDK enforces with, so a policy authored in
code (or YAML) can be exercised in a pytest suite:

    from hexgate.security import PolicyBuilder, C, assert_allows, assert_denies

    policy = PolicyBuilder().allow("refund", when=[C("args.amount") <= 500]).build()
    assert_allows(policy, "refund", {"amount": 100})
    assert_denies(policy, "refund", {"amount": 999})

``policy`` may be an :class:`AgentPolicy` (single role) or a :class:`PolicySet`
(role-aware — pass ``role=``).

Assert a ``run.*`` cap by supplying the run's facts via :func:`run_namespace`:

    assert_denies(policy, "refund", run=run_namespace(tool_calls=20))
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from hexgate.runtime.run_facts import KNOWN_RUN_PATHS, RunFacts
from hexgate.security.decision import DecisionOutcome
from hexgate.security.models import AgentPolicy
from hexgate.security.policy import evaluate_tool_call
from hexgate.security.policy_set import PolicySet

Policy = AgentPolicy | PolicySet


def run_namespace(tool: str = "", **facts: Any) -> dict[str, Any]:
    """A ``run`` namespace with ``facts`` applied over a zeroed run.

    Raises on an unregistered keyword — a typo like ``tool_call=20`` would
    otherwise leave the real counter at 0 and the cap would never fire.
    """
    unknown = sorted(set(facts) - KNOWN_RUN_PATHS)
    if unknown:
        raise ValueError(
            f"unknown run.* path(s) {unknown} "
            f"(this build knows: {', '.join(sorted(KNOWN_RUN_PATHS))})"
        )
    return {**_zeroed_run(tool), **facts}


def _zeroed_run(tool: str) -> dict[str, Any]:
    """A freshly-started run — the default so an unset ``run.*`` cap reads
    zero instead of failing closed."""
    return RunFacts(id=str(uuid4()), agent="").as_namespace(tool)


def _outcome(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None,
    role: str | None,
    attributes: dict[str, Any] | None,
    run: Mapping[str, Any] | None,
) -> DecisionOutcome:
    resolved_run = run if run is not None else _zeroed_run(tool)
    if isinstance(policy, PolicySet):
        return policy.evaluate(
            role=role,
            tool=tool,
            args=args or {},
            attributes=attributes,
            run=resolved_run,
        ).outcome
    return evaluate_tool_call(
        policy, tool, args or {}, role=role, attributes=attributes, run=resolved_run
    ).outcome


def _check(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None,
    role: str | None,
    attributes: dict[str, Any] | None,
    run: Mapping[str, Any] | None,
    expected: DecisionOutcome,
) -> None:
    actual = _outcome(policy, tool, args, role, attributes, run)
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
    run: Mapping[str, Any] | None = None,
) -> None:
    """Assert the policy ALLOWS this call.

    ``attributes`` and ``run`` feed ``ctx.*`` and ``run.*`` constraints; ``run``
    defaults to a freshly-started run — see :func:`run_namespace` to set one."""
    _check(policy, tool, args, role, attributes, run, DecisionOutcome.ALLOW)


def assert_denies(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: dict[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> None:
    """Assert the policy DENIES this call."""
    _check(policy, tool, args, role, attributes, run, DecisionOutcome.DENY)


def assert_needs_approval(
    policy: Policy,
    tool: str,
    args: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: dict[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> None:
    """Assert the policy routes this call to approval."""
    _check(policy, tool, args, role, attributes, run, DecisionOutcome.NEEDS_APPROVAL)
