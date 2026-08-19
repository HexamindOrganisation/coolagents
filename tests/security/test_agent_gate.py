"""Tests for the admission gate (``security/agent_gate.py``).

The gate reuses ``PolicyEnforcer.decide`` on the synthetic ``agent.run`` key, so
these drive it through a real ``PolicySet`` enforcer under an open context scope,
the same path a run entry takes. Admission is opt-in: no admission block means no
gate (``resolve_agent_gate`` returns ``None``).
"""

from __future__ import annotations

import pytest

from hexgate.runtime.context import HexgateContext
from hexgate.security import (
    AgentNotAdmittedError,
    AgentPolicy,
    BaseToolPolicy,
    resolve_agent_gate,
)
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import load_policy_set

_ROLE = HexgateContext(user_id="u", user_roles=["support"])


def _enforcer(admission_mode: str | None) -> PolicyEnforcer:
    admission = BaseToolPolicy(mode=admission_mode) if admission_mode else None
    policy = AgentPolicy(
        default_policy=BaseToolPolicy(mode="deny"),
        admission=admission,
    )
    return PolicyEnforcer(load_policy_set(policy), agent_name="my-agent")


# --- opt-in ----------------------------------------------------------------


def test_no_admission_block_is_a_noop() -> None:
    # A gate is always built, but a policy with no admission block never refuses:
    # the opt-in is checked per run, so this stays a no-op (and hot-reload safe).
    gate = resolve_agent_gate(_enforcer(None))
    with _ROLE.sync_scope():
        gate.check_admission()  # does not raise


def test_gate_builds_with_admission() -> None:
    assert resolve_agent_gate(_enforcer("allow")) is not None


# --- verdicts --------------------------------------------------------------


def test_admission_allow_passes() -> None:
    gate = resolve_agent_gate(_enforcer("allow"))
    with _ROLE.sync_scope():
        gate.check_admission()  # does not raise


def test_admission_deny_raises() -> None:
    gate = resolve_agent_gate(_enforcer("deny"))
    with _ROLE.sync_scope(), pytest.raises(AgentNotAdmittedError):
        gate.check_admission()


def test_deny_error_carries_decision() -> None:
    gate = resolve_agent_gate(_enforcer("deny"))
    with _ROLE.sync_scope():
        try:
            gate.check_admission()
        except AgentNotAdmittedError as exc:
            assert exc.decision.tool_name == "agent.run"
            assert not exc.decision.allowed
        else:  # pragma: no cover
            pytest.fail("expected AgentNotAdmittedError")


# --- approval --------------------------------------------------------------


def test_approval_bool_true_passes() -> None:
    gate = resolve_agent_gate(_enforcer("approval_required"), approval_handler=True)
    with _ROLE.sync_scope():
        gate.check_admission()


def test_approval_bool_false_raises() -> None:
    gate = resolve_agent_gate(_enforcer("approval_required"), approval_handler=False)
    with _ROLE.sync_scope(), pytest.raises(AgentNotAdmittedError):
        gate.check_admission()


def test_approval_no_handler_raises() -> None:
    gate = resolve_agent_gate(_enforcer("approval_required"))
    with _ROLE.sync_scope(), pytest.raises(AgentNotAdmittedError):
        gate.check_admission()


def test_approval_sync_callable_approves_and_denies() -> None:
    approve = resolve_agent_gate(
        _enforcer("approval_required"), approval_handler=lambda d: True
    )
    deny = resolve_agent_gate(
        _enforcer("approval_required"), approval_handler=lambda d: False
    )
    with _ROLE.sync_scope():
        approve.check_admission()
        with pytest.raises(AgentNotAdmittedError):
            deny.check_admission()


def test_approval_handler_raises_fails_closed() -> None:
    def boom(_decision: object) -> bool:
        raise RuntimeError("handler blew up")

    gate = resolve_agent_gate(_enforcer("approval_required"), approval_handler=boom)
    with _ROLE.sync_scope(), pytest.raises(AgentNotAdmittedError):
        gate.check_admission()


def test_async_handler_on_sync_run_denies() -> None:
    async def slow(_decision: object) -> bool:
        return True

    gate = resolve_agent_gate(_enforcer("approval_required"), approval_handler=slow)
    # A coroutine handler cannot be awaited on the sync entrypoint → fail closed.
    with _ROLE.sync_scope(), pytest.raises(AgentNotAdmittedError):
        gate.check_admission()


# --- async path ------------------------------------------------------------


async def test_async_admission_allow_passes() -> None:
    gate = resolve_agent_gate(_enforcer("allow"))
    async with HexgateContext(user_id="u", user_roles=["support"]):
        await gate.check_admission_async()


async def test_async_admission_approval_async_handler() -> None:
    async def approve(_decision: object) -> bool:
        return True

    gate = resolve_agent_gate(_enforcer("approval_required"), approval_handler=approve)
    async with HexgateContext(user_id="u", user_roles=["support"]):
        await gate.check_admission_async()
