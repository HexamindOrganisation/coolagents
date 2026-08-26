"""Tests for the reach gate (``security/agent_gate.py``).

The reach gate mirrors the admission gate but decides a target's lowered reach key
(``agent.handoff:<target>`` / ``agent.tool:<target>``) at the handoff/delegation
seam. These drive it through a real ``PolicySet`` enforcer under an open context
scope. Engagement is opt-in: a policy with no ``agents`` block is a no-op.
"""

from __future__ import annotations

import pytest

from hexgate.runtime.context import HexgateContext
from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    ReachNotAllowedError,
    resolve_reach_gate,
)
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import load_policy_set

_ROLE = HexgateContext(user_id="u", user_roles=["support"])


def _enforcer(agents: dict | None) -> PolicyEnforcer:
    policy = AgentPolicy(
        default_policy=BaseToolPolicy(mode="allow"),  # permissive default...
        agents=agents or {},
    )
    return PolicyEnforcer(load_policy_set(policy), agent_name="orchestrator")


# --- engagement (opt-in) ---------------------------------------------------


def test_no_agents_block_is_a_noop() -> None:
    # No reach declared → gate never fires, even for an unknown target.
    gate = resolve_reach_gate(_enforcer(None))
    with _ROLE.sync_scope():
        gate.check_reach("billing-bot", via="handoff")  # does not raise


# --- verdicts --------------------------------------------------------------


def test_reach_allow_passes() -> None:
    gate = resolve_reach_gate(_enforcer({"billing-bot": {"mode": "allow"}}))
    with _ROLE.sync_scope():
        gate.check_reach("billing-bot", via="handoff")  # listed → allowed


def test_reach_unlisted_target_is_closed_world_denied() -> None:
    # ...even under an allow default: an unlisted reach key denies once reach is
    # declared (closed-world), so a permissive default cannot grant a handoff.
    gate = resolve_reach_gate(_enforcer({"billing-bot": {"mode": "allow"}}))
    with _ROLE.sync_scope(), pytest.raises(ReachNotAllowedError):
        gate.check_reach("evil-bot", via="handoff")


def test_reach_via_is_distinguished() -> None:
    # A target listed for handoff only is not reachable as a tool.
    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "allow", "via": ["handoff"]}})
    )
    with _ROLE.sync_scope():
        gate.check_reach("billing-bot", via="handoff")
        with pytest.raises(ReachNotAllowedError):
            gate.check_reach("billing-bot", via="tool")


def test_reach_deny_raises_and_carries_decision() -> None:
    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "allow", "via": ["handoff"]}})
    )
    with _ROLE.sync_scope():
        try:
            gate.check_reach("billing-bot", via="tool")
        except ReachNotAllowedError as exc:
            assert exc.decision.tool_name == "agent.tool:billing-bot"
            assert not exc.decision.allowed
        else:  # pragma: no cover
            pytest.fail("expected ReachNotAllowedError")


def test_reach_target_name_is_canonicalized() -> None:
    # A whitespace-padded runtime target matches the listed target.
    gate = resolve_reach_gate(_enforcer({"billing-bot": {"mode": "allow"}}))
    with _ROLE.sync_scope():
        gate.check_reach("  billing-bot ", via="handoff")  # trimmed → matches


# --- approval --------------------------------------------------------------


def test_reach_approval_bool_true_passes() -> None:
    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "approval_required"}}),
        approval_handler=True,
    )
    with _ROLE.sync_scope():
        gate.check_reach("billing-bot", via="handoff")


def test_reach_approval_bool_false_raises() -> None:
    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "approval_required"}}),
        approval_handler=False,
    )
    with _ROLE.sync_scope(), pytest.raises(ReachNotAllowedError):
        gate.check_reach("billing-bot", via="handoff")


def test_reach_approval_handler_raises_fails_closed() -> None:
    def boom(_decision: object) -> bool:
        raise RuntimeError("handler blew up")

    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "approval_required"}}),
        approval_handler=boom,
    )
    with _ROLE.sync_scope(), pytest.raises(ReachNotAllowedError):
        gate.check_reach("billing-bot", via="handoff")


# --- async path ------------------------------------------------------------


async def test_async_reach_allow_passes() -> None:
    gate = resolve_reach_gate(_enforcer({"billing-bot": {"mode": "allow"}}))
    async with HexgateContext(user_id="u", user_roles=["support"]):
        await gate.check_reach_async("billing-bot", via="handoff")


async def test_async_reach_approval_async_handler() -> None:
    async def approve(_decision: object) -> bool:
        return True

    gate = resolve_reach_gate(
        _enforcer({"billing-bot": {"mode": "approval_required"}}),
        approval_handler=approve,
    )
    async with HexgateContext(user_id="u", user_roles=["support"]):
        await gate.check_reach_async("billing-bot", via="handoff")
