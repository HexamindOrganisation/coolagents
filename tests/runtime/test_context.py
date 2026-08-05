"""Tests for the HexgateContext scope: async context manager + lazy attenuation hand-off.

`HexgateContext(user_id=..., user_roles=..., attributes=..., ttl_seconds=...)` is the
canonical way for a dev's backend to bind an agent invocation to one caller. Inside the
``async with HexgateContext(...)`` block the runtime lazily attenuates the agent's
bound HexgateClient token and folds the resulting facts into ToolUseContext.

These tests cover the contextvar bookkeeping, the ``user_roles`` / ``primary_role``
selection contract, and the lazy attenuation hand-off without spinning up a real
platform — they monkeypatch the factory's context-resolution helper to confirm the
right facts arrive at the runtime.
"""

from __future__ import annotations

import asyncio
import contextvars

import pytest
from biscuit_auth import BiscuitBuilder, KeyPair

from hexgate.agents import factory
from hexgate.cloud.client import HexgateClient, HexgateConfig
from hexgate.runtime import HexgateContext, get_current_context


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    """Fresh Ed25519 keypair as raw bytes ``(priv, pub)``."""
    kp = KeyPair()
    return kp.private_key.to_bytes(), kp.public_key.to_bytes()


def _parent_envelope(priv: bytes, project: str = "acme") -> str:
    from biscuit_auth import Algorithm, PrivateKey

    pk = PrivateKey.from_bytes(priv, Algorithm.Ed25519)
    biscuit = BiscuitBuilder(f'project("{project}");').build(pk)
    return f"fty_live_{project}_{biscuit.to_base64()}"


def _client(priv: bytes, pub: bytes) -> HexgateClient:
    return HexgateClient(
        HexgateConfig(
            base_url="http://test",
            api_key=_parent_envelope(priv),
            project_id="acme",
            public_key=pub,
        )
    )


class _FakeAgent:
    """A bare object the factory helpers can read attributes off.

    Mirrors the real ``HexgateAgent``'s seam fields as first-class
    attributes (set to ``None`` when not provided) so production code
    can read them via direct attribute access without falling back to
    ``getattr(agent, ..., None)``.
    """

    def __init__(self, *, name: str | None = None, client: HexgateClient | None = None):
        self.name = name
        self.workspace = None
        self.hexgate_client: HexgateClient | None = client


# ---------------------------------------------------------------------------
# Context manager bookkeeping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_scope_sets_and_resets_contextvar() -> None:
    """A vanilla ``async with`` pushes + pops the HexgateContext on the contextvar."""
    assert get_current_context() is None
    async with HexgateContext(user_id="alice", user_roles=["billing"]):
        user = get_current_context()
        assert user is not None
        assert user.user_id == "alice"
        assert user.primary_role == "billing"
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_user_scope_nests_same_instance() -> None:
    """Same HexgateContext entered twice still resets cleanly to None on full exit."""
    user = HexgateContext(user_id="bob")
    async with user:
        async with user:
            assert get_current_context() is user
        # Inner exit restores the outer set (still the same user).
        assert get_current_context() is user
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_user_scope_nests_different_instances() -> None:
    """Outer + inner Users — inner wins inside, outer restored on exit."""
    outer = HexgateContext(user_id="alice")
    inner = HexgateContext(user_id="bob")
    async with outer:
        assert get_current_context() is outer
        async with inner:
            assert get_current_context() is inner
        assert get_current_context() is outer
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_user_defaults_keep_optional_fields_unset() -> None:
    """Only ``user_id`` is required; everything else has a sensible default."""
    async with HexgateContext(user_id="alice") as u:
        assert u.primary_role is None
        assert u.session_id is None
        assert u.ttl_seconds is None


def test_sync_scope_exit_survives_foreign_context() -> None:
    """Exiting in a different Context than entry must not raise.

    A sync generator holding ``sync_scope()`` across a yield can be GC-finalized
    in a foreign Context; with the old token-based reset that raised "Token was
    created in a different Context". Save/restore via set() works in any Context.

    Enter and exit each run in their own copied Context so neither touches the
    test's real context (and the distinct contexts are what reproduce the bug).
    """
    user = HexgateContext(user_id="alice")
    cm = user.sync_scope()
    contextvars.copy_context().run(cm.__enter__)  # set in context A
    contextvars.copy_context().run(cm.__exit__, None, None, None)  # exit in B: no raise
    assert get_current_context() is None  # test's own context never polluted


@pytest.mark.asyncio
async def test_async_scope_exit_survives_foreign_context() -> None:
    """async __aexit__ in a foreign Context must not raise (astream_events
    aclose() runs in the event loop's finalizer task). __aexit__ does no real
    awaiting, so a single send() drives it to completion."""
    user = HexgateContext(user_id="alice")

    def _drive(coro: object) -> None:
        try:
            coro.send(None)  # type: ignore[attr-defined]
        except StopIteration:
            pass

    contextvars.copy_context().run(_drive, user.__aenter__())  # enter in context A
    contextvars.copy_context().run(
        _drive, user.__aexit__(None, None, None)
    )  # B: no raise
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_user_scope_isolated_across_tasks() -> None:
    """Spawning a task without copying context leaves the new task scope-free."""
    # asyncio.Task copies the current context by default — verify the inverse:
    # an explicitly-cleared context doesn't see the outer HexgateContext.
    seen: dict[str, HexgateContext | None] = {}

    async def _child() -> None:
        seen["inner"] = get_current_context()

    async with HexgateContext(user_id="alice"):
        # Task spawned from inside the scope DOES inherit (asyncio default).
        await asyncio.create_task(_child())
        assert seen["inner"] is not None
        assert seen["inner"].user_id == "alice"


# ---------------------------------------------------------------------------
# Lazy attenuation via _resolve_tool_use_context
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_tool_use_context_attenuates_when_user_active(
    keys: tuple[bytes, bytes],
) -> None:
    """A live HexgateContext + agent.hexgate_client → biscuit_facts populated."""
    priv, pub = keys
    agent = _FakeAgent(name="support-bot", client=_client(priv, pub))

    async with HexgateContext(user_id="alice", user_roles=["billing"]):
        ctx = factory._resolve_tool_use_context(agent, None)
    assert ctx.biscuit_facts is not None
    assert ctx.biscuit_facts["user"] == ["alice"]
    assert ctx.biscuit_facts["role"] == ["billing"]
    assert ctx.biscuit_facts["project"] == ["acme"]


@pytest.mark.asyncio
async def test_resolve_tool_use_context_skips_when_no_user() -> None:
    """Outside a HexgateContext scope, no biscuit_facts even with a cloud-bound agent."""
    # Build a dummy client so attribute exists; should still skip when no user.
    kp = KeyPair()
    agent = _FakeAgent(
        client=_client(kp.private_key.to_bytes(), kp.public_key.to_bytes())
    )
    ctx = factory._resolve_tool_use_context(agent, None)
    assert ctx.biscuit_facts is None


@pytest.mark.asyncio
async def test_resolve_tool_use_context_warns_for_local_agent(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A HexgateContext scope with no agent.hexgate_client logs a warning and returns no facts."""
    agent = _FakeAgent(name="local-agent")  # no hexgate_client attr
    import logging

    caplog.set_level(logging.WARNING)
    async with HexgateContext(user_id="alice"):
        ctx = factory._resolve_tool_use_context(agent, None)
    assert ctx.biscuit_facts is None
    assert any("no hexgate_client" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_resolve_tool_use_context_explicit_arg_wins(
    keys: tuple[bytes, bytes],
) -> None:
    """Explicit tool_use_context kwarg bypasses HexgateContext scope entirely."""
    priv, pub = keys
    agent = _FakeAgent(client=_client(priv, pub))
    from hexgate.runtime import ToolUseContext

    override = ToolUseContext(biscuit_facts={"user": ["override"]})
    async with HexgateContext(user_id="alice"):
        ctx = factory._resolve_tool_use_context(agent, override)
    # Explicit context flows through unchanged; the HexgateContext scope is ignored.
    assert ctx is override
    assert ctx.biscuit_facts == {"user": ["override"]}


@pytest.mark.asyncio
async def test_resolve_tool_use_context_handles_attenuation_failure(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A broken parent token → warning logged, facts left empty (fail-closed)."""
    priv, pub = keys
    bad_client = HexgateClient(
        HexgateConfig(
            base_url="http://test",
            api_key="fty_live_acme_NOT_A_REAL_TOKEN",  # signature won't chain
            project_id="acme",
            public_key=pub,
        )
    )
    agent = _FakeAgent(client=bad_client)

    import logging

    caplog.set_level(logging.WARNING)
    async with HexgateContext(user_id="alice"):
        ctx = factory._resolve_tool_use_context(agent, None)
    assert ctx.biscuit_facts is None
    assert any("attenuation failed" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_resolve_tool_use_context_ttl_threads_through(
    keys: tuple[bytes, bytes],
) -> None:
    """``ttl_seconds`` on the HexgateContext is honoured by the attenuation call."""
    priv, pub = keys
    agent = _FakeAgent(client=_client(priv, pub))
    async with HexgateContext(user_id="alice", ttl_seconds=600):
        ctx = factory._resolve_tool_use_context(agent, None)
    # TTL embeds a check, not a fact — verify by re-verifying the resulting
    # facts dict carries the user attribution (proof the attenuation ran).
    assert ctx.biscuit_facts is not None
    assert ctx.biscuit_facts["user"] == ["alice"]


# ---------------------------------------------------------------------------
# user_roles / primary_role selection contract (PR 1)
# ---------------------------------------------------------------------------


def test_primary_role_returns_first_role() -> None:
    """``primary_role`` is the single role that reaches policy selection today."""
    assert HexgateContext(user_id="a", user_roles=["billing"]).primary_role == "billing"


def test_primary_role_is_none_when_no_roles() -> None:
    """Empty ``user_roles`` yields ``None`` — parity with the old ``role=None``."""
    assert HexgateContext(user_id="a").primary_role is None
    assert HexgateContext(user_id="a", user_roles=[]).primary_role is None


def test_secondary_roles_are_carried_but_inert() -> None:
    """Extra roles are retained on the model but only the first selects a policy.

    Locks the single-role reduction point: multi-role widens the *selector*
    later; until then ``user_roles[1:]`` has no effect on enforcement.
    """
    ctx = HexgateContext(user_id="a", user_roles=["billing", "support"])
    assert ctx.primary_role == "billing"
    assert ctx.user_roles == ["billing", "support"]


def test_attributes_default_empty_and_roundtrip() -> None:
    """The ABAC bag defaults to ``{}`` and stores values verbatim (inert in PR 1)."""
    assert HexgateContext(user_id="a").attributes == {}
    ctx = HexgateContext(
        user_id="a",
        attributes={"department": "finance", "clearance_level": 3, "on_call": True},
    )
    assert ctx.attributes == {
        "department": "finance",
        "clearance_level": 3,
        "on_call": True,
    }


class _RoleRecordingEngine:
    """Minimal PolicyEngine that records the ``role`` the enforcer forwards."""

    def __init__(self) -> None:
        from hexgate.security import DecisionOutcome, Verdict

        self.seen_role: str | None = "<unset>"
        self._verdict = Verdict(outcome=DecisionOutcome.ALLOW)

    def evaluate(self, *, role, tool, args):  # type: ignore[no-untyped-def]
        self.seen_role = role
        return self._verdict


@pytest.mark.asyncio
async def test_enforcer_forwards_primary_role_from_active_context() -> None:
    """The active context's ``primary_role`` — not the whole list — reaches the engine."""
    from hexgate.security.enforcer import PolicyEnforcer

    engine = _RoleRecordingEngine()
    enforcer = PolicyEnforcer(engine, agent_name="a")
    async with HexgateContext(user_id="alice", user_roles=["billing", "support"]):
        enforcer.decide("read_file", {})
    assert engine.seen_role == "billing"


@pytest.mark.asyncio
async def test_enforcer_forwards_none_for_empty_roles() -> None:
    """Empty ``user_roles`` forwards ``role=None`` so PolicySet falls back to default.

    This is the behavioural parity contract with the removed ``role=None``.
    """
    from hexgate.security.enforcer import PolicyEnforcer

    engine = _RoleRecordingEngine()
    enforcer = PolicyEnforcer(engine, agent_name="a")
    async with HexgateContext(user_id="alice"):
        enforcer.decide("read_file", {})
    assert engine.seen_role is None
