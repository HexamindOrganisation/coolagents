"""Tests for the admission gate (``security/agent_gate.py``).

The gate reuses ``PolicyEnforcer.decide`` on the synthetic ``agent.run`` key, so
these drive it through a real ``PolicySet`` enforcer under an open context scope,
the same path a run entry takes. Engagement is opt-in: ``resolve_agent_gate`` always
returns a gate, but a policy that declares no admission anywhere makes every check
a no-op. Once admission is declared, agent keys are closed-world (R-AGENT-002).
"""

from __future__ import annotations

import logging

import pytest

from hexgate.runtime.context import HexgateContext
from hexgate.security import (
    AgentNotAdmittedError,
    AgentPolicy,
    BaseToolPolicy,
    resolve_agent_gate,
    warn_if_admission_unenforced,
)
from hexgate.security import agent_gate as agent_gate_mod
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import load_policy_set, load_policy_set_from_dict

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


# --- multi-role (closed-world + permissive union) --------------------------


def test_admission_is_closed_world_across_roles_with_permissive_union() -> None:
    # Under Option B (R-AGENT-002) admission is closed-world once any role declares
    # it: engagement is PolicySet-wide (admin declares admission → the gate fires
    # for everyone), so a role not granted admission is refused. The multi-role
    # fold stays permissive: any role that grants admission admits the caller.
    ps = load_policy_set_from_dict(
        {
            "roles": {
                "default": {"default_policy": {"mode": "deny"}},
                "admin": {
                    "default_policy": {"mode": "deny"},
                    "admission": {"mode": "allow"},
                },
                "contractor": {
                    "default_policy": {"mode": "deny"},
                    "admission": {"mode": "deny"},
                },
                "viewer": {"default_policy": {"mode": "deny"}},  # no admission grant
            }
        }
    )
    gate = resolve_agent_gate(PolicyEnforcer(ps, agent_name="agent"))

    # admin is granted admission → admitted.
    with HexgateContext(user_id="u", user_roles=["admin"]).sync_scope():
        gate.check_admission()

    # viewer grants no admission → closed-world refuse (the gate is engaged because
    # admin declares admission somewhere in the set).
    with HexgateContext(user_id="u", user_roles=["viewer"]).sync_scope():
        with pytest.raises(AgentNotAdmittedError):
            gate.check_admission()

    # contractor explicitly denies admission → refused.
    with HexgateContext(user_id="u", user_roles=["contractor"]).sync_scope():
        with pytest.raises(AgentNotAdmittedError):
            gate.check_admission()

    # admin + contractor: the permissive union admits (admin grants; ALLOW wins).
    with HexgateContext(user_id="u", user_roles=["contractor", "admin"]).sync_scope():
        gate.check_admission()

    # viewer + contractor: neither grants admission → refused.
    with HexgateContext(user_id="u", user_roles=["viewer", "contractor"]).sync_scope():
        with pytest.raises(AgentNotAdmittedError):
            gate.check_admission()


# --- adapter interim warning (admission unenforced off the native agent) ---


def _engine(admission_mode: str | None):
    admission = BaseToolPolicy(mode=admission_mode) if admission_mode else None
    return load_policy_set(
        AgentPolicy(default_policy=BaseToolPolicy(mode="deny"), admission=admission)
    )


def test_warn_if_admission_unenforced_fires_once_when_declared(caplog) -> None:
    agent_gate_mod._admission_unenforced_warned.clear()
    engine = _engine("allow")
    with caplog.at_level(logging.WARNING, logger=agent_gate_mod.__name__):
        warn_if_admission_unenforced(engine, framework="OpenAI Agents", agent_name="a")
        warn_if_admission_unenforced(engine, framework="OpenAI Agents", agent_name="a")
    records = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(records) == 1  # deduped per (framework, agent)
    assert "admission" in records[0].getMessage()
    assert "OpenAI Agents" in records[0].getMessage()


def test_warn_if_admission_unenforced_silent_without_admission(caplog) -> None:
    agent_gate_mod._admission_unenforced_warned.clear()
    with caplog.at_level(logging.WARNING, logger=agent_gate_mod.__name__):
        warn_if_admission_unenforced(
            _engine(None), framework="Google ADK", agent_name="a"
        )
    assert not [r for r in caplog.records if r.levelno == logging.WARNING]


def test_warn_if_admission_unenforced_distinguishes_framework_and_agent(caplog) -> None:
    agent_gate_mod._admission_unenforced_warned.clear()
    engine = _engine("deny")  # declared (deny) still counts as configured
    with caplog.at_level(logging.WARNING, logger=agent_gate_mod.__name__):
        warn_if_admission_unenforced(engine, framework="OpenAI Agents", agent_name="a")
        warn_if_admission_unenforced(engine, framework="Google ADK", agent_name="a")
        warn_if_admission_unenforced(engine, framework="OpenAI Agents", agent_name="b")
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 3
