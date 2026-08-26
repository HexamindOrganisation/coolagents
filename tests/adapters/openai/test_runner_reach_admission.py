"""Agent-level reach + admission wiring for the OpenAI runner (A3).

Reach is enforced at the SDK handoff seam via ``_HexgateReachHooks.on_handoff``
(governed by the *source* agent's policy); admission is enforced at run entry via
the top-level agent's policy. These drive the seams directly rather than through a
full SDK handoff, which needs a live model.
"""

from __future__ import annotations

from typing import Any

import pytest
from agents import Agent, FunctionTool

from hexgate.adapters.openai import runner as runner_mod
from hexgate.adapters.openai.runner import HexgateRunner, _HexgateReachHooks
from hexgate.runtime import HexgateContext
from hexgate.security import (
    AgentNotAdmittedError,
    AgentPolicy,
    BaseToolPolicy,
    HandoffDepthExceededError,
    PolicySet,
    ReachNotAllowedError,
    ResolvedPolicy,
)
from hexgate.security.binding import PolicyBinding
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


def _user() -> HexgateContext:
    return HexgateContext(user_id="u-1", session_id="s-1", user_roles=["developer"])


def _agent(name: str) -> Agent:
    async def on_invoke(_ctx: Any, raw: str) -> str:
        return raw

    tool = FunctionTool(
        name="echo",
        description="echo",
        params_json_schema={"type": "object"},
        on_invoke_tool=on_invoke,
    )
    return Agent(name=name, tools=[tool])


def _silence_observability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(HexgateRunner, "_setup_observability", lambda self: None)
    monkeypatch.setattr(runner_mod, "resolve_ban_gate", lambda *a, **k: None)


# --- reach at the handoff seam ---------------------------------------------


def _reach_binding(agents: dict) -> PolicyBinding:
    engine = PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy(
                default_policy=BaseToolPolicy(mode="allow"), agents=agents
            )
        }
    )
    return PolicyBinding(PolicyEnforcer(engine, agent_name="orchestrator"), None)


@pytest.mark.asyncio
async def test_reach_hook_gates_handoff_by_source_policy() -> None:
    runner = HexgateRunner(api_key="k")
    runner._bindings["orchestrator"] = _reach_binding(
        {"billing-bot": {"mode": "allow", "via": ["handoff"]}}
    )
    hook = _HexgateReachHooks(runner)
    source = _agent("orchestrator")
    async with _user():
        await hook.on_handoff(None, source, _agent("billing-bot"))  # listed → ok
        with pytest.raises(ReachNotAllowedError):
            await hook.on_handoff(None, source, _agent("evil-bot"))  # unlisted → deny


@pytest.mark.asyncio
async def test_reach_hook_skips_ungoverned_source() -> None:
    # A handoff from an agent with no cached binding (not Hexgate-governed) is not
    # gated here — no resolve, no raise.
    runner = HexgateRunner(api_key="k")
    hook = _HexgateReachHooks(runner)
    async with _user():
        await hook.on_handoff(None, _agent("stranger"), _agent("evil-bot"))


@pytest.mark.asyncio
async def test_reach_hook_noop_without_reach_policy() -> None:
    runner = HexgateRunner(api_key="k")
    runner._bindings["orchestrator"] = _reach_binding({})  # declares no reach
    hook = _HexgateReachHooks(runner)
    async with _user():
        await hook.on_handoff(None, _agent("orchestrator"), _agent("anyone"))


# --- handoff depth cap (A4) ------------------------------------------------


@pytest.mark.asyncio
async def test_reach_hook_enforces_depth_cap() -> None:
    # Depth counts every handoff in the run (the hook is per-run), independent of
    # reach policy: an un-governed source still counts toward the cap.
    runner = HexgateRunner(api_key="k", max_handoff_depth=1)
    hook = _HexgateReachHooks(runner)
    async with _user():
        await hook.on_handoff(None, _agent("a"), _agent("b"))  # depth 1 == cap → ok
        with pytest.raises(HandoffDepthExceededError):
            await hook.on_handoff(None, _agent("a"), _agent("c"))  # depth 2 > cap


@pytest.mark.asyncio
async def test_reach_hook_no_cap_by_default() -> None:
    runner = HexgateRunner(api_key="k")  # no cap
    hook = _HexgateReachHooks(runner)
    async with _user():
        for _ in range(5):
            await hook.on_handoff(None, _agent("a"), _agent("b"))  # never raises


# --- admission at run entry ------------------------------------------------


def _patch_admission_resolve(
    monkeypatch: pytest.MonkeyPatch, admission_mode: str
) -> None:
    def fake_resolve(name: str, *, api_key: str, client: object = None):
        engine = PolicySet(
            {
                DEFAULT_ROLE_NAME: AgentPolicy(
                    default_policy=BaseToolPolicy(mode="allow"),
                    admission=BaseToolPolicy(mode=admission_mode),
                )
            }
        )
        return ResolvedPolicy(engine, None)

    monkeypatch.setattr(runner_mod, "resolve_policy", fake_resolve)


@pytest.mark.asyncio
async def test_run_refuses_non_admitted_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_observability(monkeypatch)
    _patch_admission_resolve(monkeypatch, "deny")
    called = {"run": False}

    async def fake_run(*_a: Any, **_k: Any) -> str:
        called["run"] = True
        return "ok"

    monkeypatch.setattr(runner_mod.Runner, "run", staticmethod(fake_run))
    runner = HexgateRunner(api_key="k")
    with pytest.raises(AgentNotAdmittedError):
        await runner.run(_agent("my-agent"), "hi", hexgate_context=_user())
    assert called["run"] is False  # refused before the underlying run


@pytest.mark.asyncio
async def test_run_admits_when_policy_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_observability(monkeypatch)
    _patch_admission_resolve(monkeypatch, "allow")

    async def fake_run(*_a: Any, **_k: Any) -> str:
        return "ok"

    monkeypatch.setattr(runner_mod.Runner, "run", staticmethod(fake_run))
    runner = HexgateRunner(api_key="k")
    assert await runner.run(_agent("my-agent"), "hi", hexgate_context=_user()) == "ok"


def test_run_sync_refuses_non_admitted_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    _silence_observability(monkeypatch)
    _patch_admission_resolve(monkeypatch, "deny")
    monkeypatch.setattr(
        runner_mod.Runner, "run_sync", staticmethod(lambda *a, **k: "ok")
    )
    runner = HexgateRunner(api_key="k")
    with pytest.raises(AgentNotAdmittedError):
        runner.run_sync(_agent("my-agent"), "hi", hexgate_context=_user())
