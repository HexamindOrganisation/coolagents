"""Tests for :class:`RelayApprovalHandler` — the callback that routes
NEEDS_APPROVAL decisions over the serve WS to the playground.

We fake the websocket surface (only ``send`` is needed) so the tests
run in-memory without opening a real socket.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from hexgate.cli.serve import RelayApprovalHandler
from hexgate.security.decision import Decision, DecisionOutcome

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeWS:
    """Minimal stand-in for the websockets client WebSocket.

    Records every ``send()`` payload in ``self.sent`` for inspection.
    Optionally serializes concurrent sends behind an ``asyncio.Lock``
    that the handler is expected to hold — we assert the ordering
    invariant separately.
    """

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def send(self, message: str) -> None:
        # Yield control so a concurrent send has a chance to interleave
        # if the handler ISN'T using a lock — this catches the bug the
        # asyncio.Lock exists to prevent.
        await asyncio.sleep(0)
        self.sent.append(json.loads(message))


def _decision(tool: str = "send_invoice", **kwargs: Any) -> Decision:
    return Decision(
        outcome=DecisionOutcome.NEEDS_APPROVAL,
        agent_name=kwargs.pop("agent_name", "billing_bot"),
        tool_name=tool,
        user_roles=kwargs.pop("user_roles", ("default",)),
        deciding_role=kwargs.pop("deciding_role", "default"),
        reason=kwargs.pop("reason", "test approval"),
        error_type="approval_required",
        arguments=kwargs.pop("arguments", {"order_id": "ORD-1"}),
    )


# ---------------------------------------------------------------------------
# Happy path — request emitted, reply unblocks the coroutine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emits_approval_request_with_expected_shape() -> None:
    """``__call__`` must send a well-formed ``approval.request`` frame
    on the bound socket before it starts waiting for a reply."""
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=1.0)
    handler.bind_socket(ws, asyncio.Lock())

    async def approve_after_a_tick() -> None:
        # Give __call__ a chance to send + start awaiting.
        await asyncio.sleep(0.05)
        assert len(ws.sent) == 1
        decision_id = ws.sent[0]["decision_id"]
        handler.resolve(decision_id, allowed=True)

    task_approve = asyncio.create_task(approve_after_a_tick())
    result = await handler(_decision())
    await task_approve

    assert result is True
    sent = ws.sent[0]
    # ``type`` (not ``event_type``) — approval is a control frame, same
    # discriminator as hello / reset / session_reset.
    assert sent["type"] == "approval.request"
    assert sent["tool_name"] == "send_invoice"
    assert sent["arguments"] == {"order_id": "ORD-1"}
    assert sent["reason"] == "test approval"
    assert sent["agent_name"] == "billing_bot"
    # ``role`` is the role that would grant the call; ``roles`` is the caller's
    # whole set (additive, so an older dashboard ignoring it still works).
    assert sent["role"] == "default"
    assert sent["roles"] == ["default"]
    assert isinstance(sent["decision_id"], str)
    assert sent["decision_id"].startswith("appr_")
    assert isinstance(sent["expires_at"], str)


@pytest.mark.asyncio
async def test_resolve_deny_returns_false() -> None:
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=1.0)
    handler.bind_socket(ws, asyncio.Lock())

    async def deny_after_a_tick() -> None:
        await asyncio.sleep(0.05)
        handler.resolve(ws.sent[0]["decision_id"], allowed=False)

    task = asyncio.create_task(deny_after_a_tick())
    result = await handler(_decision())
    await task
    assert result is False


# ---------------------------------------------------------------------------
# Fail-closed paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_false_when_no_socket_bound() -> None:
    """Nothing to send an approval prompt to → deny rather than hang."""
    handler = RelayApprovalHandler(ttl_seconds=1.0)
    # Deliberately DON'T bind_socket.
    result = await handler(_decision())
    assert result is False


@pytest.mark.asyncio
async def test_timeout_returns_false() -> None:
    """No reply within the TTL → deny (fail-closed)."""
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=0.1)
    handler.bind_socket(ws, asyncio.Lock())
    result = await handler(_decision())
    assert result is False


@pytest.mark.asyncio
async def test_unbind_socket_denies_all_pending() -> None:
    """Disconnecting mid-approval must fail every waiting handler so
    coroutines don't outlive the socket they belonged to."""
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())

    # Fire two approvals in parallel; both will be blocked awaiting
    # their Events. Unbind should release them both as False.
    task_a = asyncio.create_task(handler(_decision(tool="a")))
    task_b = asyncio.create_task(handler(_decision(tool="b")))
    await asyncio.sleep(0.05)  # let both reach the await

    handler.unbind_socket()

    results = await asyncio.gather(task_a, task_b)
    assert results == [False, False]
    # Socket unbound → subsequent __call__ also denies immediately.
    assert await handler(_decision(tool="c")) is False


# ---------------------------------------------------------------------------
# Concurrency — decision_id keying, no cross-talk, serialized sends
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_requests_get_distinct_decision_ids() -> None:
    """5 parallel tool calls → 5 unique decision_ids, no key collisions
    (uuid4 is the source, but pin the invariant so a future rewrite
    doesn't break it)."""
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())

    tasks = [asyncio.create_task(handler(_decision(tool=f"t{i}"))) for i in range(5)]
    # Let all 5 send frames.
    await asyncio.sleep(0.05)
    assert len(ws.sent) == 5
    ids = [frame["decision_id"] for frame in ws.sent]
    assert len(set(ids)) == 5

    # Resolve each in a scrambled order — verifies the map lookup,
    # not any FIFO assumption.
    handler.resolve(ids[2], allowed=True)
    handler.resolve(ids[0], allowed=False)
    handler.resolve(ids[4], allowed=True)
    handler.resolve(ids[1], allowed=True)
    handler.resolve(ids[3], allowed=False)

    results = await asyncio.gather(*tasks)
    # Order in results matches task creation order; decisions match
    # the specific IDs we resolved above.
    assert results == [False, True, True, False, True]


@pytest.mark.asyncio
async def test_ws_send_is_serialized_across_concurrent_calls() -> None:
    """The websockets library doesn't serialize concurrent send() calls,
    so RelayApprovalHandler must hold a lock across the send. Without
    the lock, two coroutines calling __call__ at the same time could
    interleave WS frames — silent bug that hides until a big payload
    exposes it. This test forces the race window and asserts sends
    landed as complete frames (one after another, not interleaved)."""

    concurrent_in_send = 0
    peak_concurrency = 0

    class _RaceCapturingWS:
        def __init__(self) -> None:
            self.sent: list[dict[str, Any]] = []

        async def send(self, message: str) -> None:
            nonlocal concurrent_in_send, peak_concurrency
            concurrent_in_send += 1
            peak_concurrency = max(peak_concurrency, concurrent_in_send)
            # Widen the race window so an unprotected send would clearly
            # observe another concurrent one.
            await asyncio.sleep(0.01)
            concurrent_in_send -= 1
            self.sent.append(json.loads(message))

    ws = _RaceCapturingWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())

    tasks = [asyncio.create_task(handler(_decision(tool=f"t{i}"))) for i in range(5)]
    # Let all sends run (they all get serialized by the lock, then
    # each awaits its own Event; we don't care about those here).
    await asyncio.sleep(0.2)

    handler.unbind_socket()
    await asyncio.gather(*tasks)  # unblocks all as False

    # Peak concurrency inside send() must be 1: no two coroutines can
    # be mid-send simultaneously if the lock is held correctly.
    assert peak_concurrency == 1, (
        f"expected serialized sends, saw {peak_concurrency} concurrent"
    )
    assert len(ws.sent) == 5


# ---------------------------------------------------------------------------
# Resolve on unknown decision_id is a no-op
# ---------------------------------------------------------------------------


def test_resolve_unknown_decision_id_is_noop() -> None:
    """Spurious ``approval.reply`` payloads (stale from prev connection,
    typos in a test harness) mustn't crash the handler — they're just
    dropped silently."""
    handler = RelayApprovalHandler(ttl_seconds=1.0)
    # No exception; nothing to observe.
    handler.resolve("appr_does_not_exist", allowed=True)
    handler.resolve("appr_does_not_exist_either", allowed=False)


# ---------------------------------------------------------------------------
# Reply routing via ServeContext (integration with _handle_message)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handle_message_routes_approval_reply(monkeypatch) -> None:
    """``approval.reply`` frames coming off the WS must reach
    ``handler.resolve()`` via ``_handle_message`` — the small piece of
    routing that ties the WS to the handler."""
    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())

    context = ServeContext(
        runtime=None,  # type: ignore[arg-type] — unused for this branch
        state=ChatState(),
        api_key="test-key",
        approval_handler=handler,
    )

    # Start a pending approval so there's something to resolve.
    task = asyncio.create_task(handler(_decision()))
    await asyncio.sleep(0.05)
    decision_id = ws.sent[0]["decision_id"]

    await _handle_message(
        context,
        ws,
        {
            "type": "approval.reply",
            "decision_id": decision_id,
            "allowed": True,
        },
    )

    result = await task
    assert result is True


# ---------------------------------------------------------------------------
# End-to-end: _apply_approval_handler still routes NEEDS_APPROVAL through
# the enforcer's callback slot. Pins the full serve→enforcer chain so a
# future refactor can't silently drop the handler mid-plumbing.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_apply_approval_handler_wires_relay_handler_into_guarded_tools() -> None:
    """Verify the plumbing that connects ``RelayApprovalHandler`` all the
    way down to ``GuardedTool.approval_handler`` — the slot the enforcer
    actually calls on ``NEEDS_APPROVAL``. Without this test, a rename or
    refactor of ``_apply_approval_handler`` (which we don't own — it
    lives in ``hexgate/agents/loader.py``) could silently break the
    Playground approval flow with only the low-level unit tests staying
    green.
    """
    from types import SimpleNamespace

    from hexgate.adapters.langchain.tools import GuardedTool
    from hexgate.agents.loader import _apply_approval_handler
    from hexgate.security.enforcer import PolicyEnforcer
    from hexgate.security.policy_set import load_policy_set_from_dict

    # Minimal Agent-shaped object with one GuardedTool. Real agents get
    # wrapped by create_agent; we shortcut to just the surface
    # _apply_approval_handler reads (``.tools``, ``.with_tools``).
    engine = load_policy_set_from_dict(
        {
            "version": 1,
            "default_policy": {"mode": "deny"},
            "tools": {"noop": {"mode": "allow"}},
        }
    )
    enforcer = PolicyEnforcer(engine, agent_name="test")

    async def _stub_tool_run(**_: Any) -> str:
        return "ok"

    from langchain_core.tools import StructuredTool

    inner = StructuredTool.from_function(
        coroutine=_stub_tool_run,
        name="noop",
        description="test tool",
    )
    guarded = GuardedTool.wrap(inner, enforcer=enforcer, approval_handler=None)

    class _StubAgent(SimpleNamespace):
        def with_tools(self, tools):
            self.tools = list(tools)
            return self

    agent = _StubAgent(tools=[guarded])

    # This is the exact call serve.py's main() → build_runtime_from_
    # local_agent → _build_runtime_from_spec makes. If it silently
    # stops touching guarded.approval_handler, Playground approvals
    # silently break.
    relay = RelayApprovalHandler()
    _apply_approval_handler(agent, relay)

    # Every GuardedTool on the returned agent now carries the relay.
    assert len(agent.tools) == 1
    assert isinstance(agent.tools[0], GuardedTool)
    assert agent.tools[0].approval_handler is relay


# ---------------------------------------------------------------------------
# Strict-bool + protocol contract on `approval.reply`
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_string_allowed_is_treated_as_deny() -> None:
    """Fail-closed contract: a client that sends ``allowed: "false"``
    (JSON string, not bool) must be treated as deny, not approved via
    ``bool("false") == True``. The strict check lives in
    ``_handle_message``, which is where the reply enters the process."""
    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=handler,
    )

    task = asyncio.create_task(handler(_decision()))
    await asyncio.sleep(0.05)
    decision_id = ws.sent[0]["decision_id"]

    # String "false" would be truthy under bool() — but must be denied.
    await _handle_message(
        context,
        ws,
        {"type": "approval.reply", "decision_id": decision_id, "allowed": "false"},
    )
    result = await task
    assert result is False


@pytest.mark.asyncio
async def test_true_bool_allowed_approves() -> None:
    """Sanity: the strict check doesn't accidentally reject legit True."""
    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=10.0)
    handler.bind_socket(ws, asyncio.Lock())
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=handler,
    )

    task = asyncio.create_task(handler(_decision()))
    await asyncio.sleep(0.05)
    decision_id = ws.sent[0]["decision_id"]
    await _handle_message(
        context,
        ws,
        {"type": "approval.reply", "decision_id": decision_id, "allowed": True},
    )
    assert (await task) is True


# ---------------------------------------------------------------------------
# End-to-end deadlock regression (finding #1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_serve_loop_does_not_deadlock_on_approval() -> None:
    """The critical bug the review caught: `_serve_loop` used to await
    `_handle_message` inline, so a chat frame that triggered an approval
    prompt would block the very coroutine that must read the matching
    approval.reply off the socket. Every real approval TTL-denied.

    This test simulates the real read loop's dispatch model (each
    inbound frame → its own task) and confirms an approval AND its
    reply can flow through without a stall.
    """
    from hexgate.cli.serve import ServeContext, _dispatch_message
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=5.0)
    handler.bind_socket(ws, asyncio.Lock())
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=handler,
    )

    # Simulate a chat frame arriving that immediately triggers an
    # approval (bypass stream_agent — we're testing the dispatch model,
    # not the LLM). Do that by directly calling handler() from a
    # dispatched task; then dispatch the reply frame from ANOTHER task
    # to prove the read loop stays free.
    approval_task = asyncio.create_task(handler(_decision()))
    await asyncio.sleep(0.05)
    decision_id = ws.sent[0]["decision_id"]

    # The reply arrives as a separate frame — under the old serial
    # design, this dispatch would sit behind the still-awaiting
    # approval_task and deadlock. Under the fixed design (each frame in
    # its own task), it runs concurrently and resolve() fires the Event.
    reply_task = asyncio.create_task(
        _dispatch_message(
            context,
            ws,
            {
                "type": "approval.reply",
                "decision_id": decision_id,
                "allowed": True,
            },
        )
    )

    # Give both tasks time to complete. If deadlocked, we hit the 5s
    # TTL and get False; asyncio.wait_for with a 2s cap turns the
    # deadlock into a clear assertion failure rather than a slow test.
    result = await asyncio.wait_for(approval_task, timeout=2.0)
    await reply_task
    assert result is True, (
        "approval TTL-denied — dispatch model regressed to inline await"
    )


# ---------------------------------------------------------------------------
# Additional fail-closed branches on _handle_message and __call__
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_failure_denies_and_cleans_pending() -> None:
    """If ``ws.send`` raises (peer went away between bind and send), the
    handler must fail-closed and not leak a pending entry."""

    class _BrokenWS:
        async def send(self, _: str) -> None:
            raise ConnectionError("peer gone")

    handler = RelayApprovalHandler(ttl_seconds=1.0)
    handler.bind_socket(_BrokenWS(), asyncio.Lock())
    result = await handler(_decision())
    assert result is False
    assert handler._pending == {}


@pytest.mark.asyncio
async def test_handle_message_ignores_approval_reply_when_handler_is_not_relay(
    caplog,
) -> None:
    """A non-relay handler (auto-approve bool, custom callable) can't
    consume replies — the router must log + drop, not crash."""
    import logging

    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=True,  # auto-approve bool, not a RelayApprovalHandler
    )

    with caplog.at_level(logging.WARNING, logger="hexgate.cli.serve"):
        await _handle_message(
            context,
            _FakeWS(),
            {"type": "approval.reply", "decision_id": "appr_x", "allowed": True},
        )
    assert any("not a RelayApprovalHandler" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_handle_message_ignores_approval_reply_missing_decision_id(
    caplog,
) -> None:
    """Malformed reply (no string decision_id) must warn and drop, not
    NPE deep inside ``resolve``."""
    import logging

    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    handler = RelayApprovalHandler(ttl_seconds=1.0)
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=handler,
    )

    with caplog.at_level(logging.WARNING, logger="hexgate.cli.serve"):
        await _handle_message(
            context,
            _FakeWS(),
            {"type": "approval.reply", "allowed": True},  # no decision_id
        )
    assert any("missing string decision_id" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatch_message_echoes_error_back_to_peer_on_exception() -> None:
    """When _handle_message crashes, _dispatch_message must catch, log,
    and echo an ``error`` event to the peer — the read loop mustn't die."""
    from hexgate.cli.serve import ServeContext, _dispatch_message
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=None,
    )
    # Malformed reset — will crash inside _handle_message because state
    # isn't fully wired; any exception path works to prove the catch.
    # We force one by sending an unknown-type frame after monkey-patching
    # logger to raise. Simpler: send a chat frame — state.start_turn on a
    # fresh ChatState with runtime=None will trip inside stream_agent.
    # Cleanest: patch _handle_message directly.
    import hexgate.cli.serve as serve_mod

    async def _boom(*_, **__):
        raise RuntimeError("kapow")

    original = serve_mod._handle_message
    serve_mod._handle_message = _boom
    try:
        await _dispatch_message(context, ws, {"type": "chat", "message": "hi"})
    finally:
        serve_mod._handle_message = original

    assert len(ws.sent) == 1
    assert ws.sent[0]["event_type"] == "error"
    assert "kapow" in ws.sent[0]["message"]


# ---------------------------------------------------------------------------
# Post-review fixes (Victor's comments)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_pops_before_setting_so_unbind_cannot_flip_allowed() -> None:
    """Race regression: if unbind_socket fires between resolve() setting
    box[allowed]=True and __call__ waking to read it, the pre-fix
    unbind_socket would find the entry still in _pending and overwrite
    allowed back to False — silently denying an approved call. Now
    resolve() pops the entry atomically before mutating box, so unbind
    can't see it.

    Simulate the race by driving the ordering manually: resolve first
    (approve), then unbind. The parked __call__ must return True.
    """
    ws = _FakeWS()
    handler = RelayApprovalHandler(ttl_seconds=5.0)
    handler.bind_socket(ws, asyncio.Lock())

    task = asyncio.create_task(handler(_decision()))
    await asyncio.sleep(0.05)
    decision_id = ws.sent[0]["decision_id"]

    # HexgateContext approves — resolve() should pop the entry atomically.
    handler.resolve(decision_id, allowed=True)
    # Immediately after, a disconnect happens. unbind_socket must NOT
    # find the resolved entry (already popped) and must NOT flip it.
    handler.unbind_socket()

    result = await task
    assert result is True, (
        "approve was silently flipped to deny — resolve() did not pop "
        "before mutating, or unbind_socket found the stale entry"
    )


@pytest.mark.asyncio
async def test_serve_context_send_lock_serializes_concurrent_sends() -> None:
    """Fix #1 regression: every ws.send on the serve socket must go
    through _safe_send, which acquires context.send_lock. Two
    concurrent sends must not interleave at the byte-write level.
    Assert that the lock is actually held by wrapping ws.send with a
    counter that would spike above 1 if the lock leaked."""
    from hexgate.cli.serve import ServeContext, _safe_send
    from hexgate.cli.state import ChatState

    concurrent_in_send = 0
    max_seen_concurrent = 0

    class _CountingWS:
        async def send(self, _: str) -> None:
            nonlocal concurrent_in_send, max_seen_concurrent
            concurrent_in_send += 1
            max_seen_concurrent = max(max_seen_concurrent, concurrent_in_send)
            # Yield control so any second send that isn't lock-guarded
            # gets the chance to interleave here.
            await asyncio.sleep(0)
            concurrent_in_send -= 1

    ws = _CountingWS()
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=None,
        send_lock=asyncio.Lock(),
    )
    await asyncio.gather(*[_safe_send(context, ws, f"m-{i}") for i in range(10)])
    assert max_seen_concurrent == 1


@pytest.mark.asyncio
async def test_safe_send_falls_back_when_context_has_no_lock() -> None:
    """When send_lock is None (test bypass of _serve_loop), _safe_send
    still forwards to ws.send unchanged — otherwise it would hang."""
    from hexgate.cli.serve import ServeContext, _safe_send
    from hexgate.cli.state import ChatState

    ws = _FakeWS()
    context = ServeContext(
        runtime=None,  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=None,
        send_lock=None,
    )
    await _safe_send(context, ws, json.dumps({"type": "hello"}))
    assert ws.sent == [{"type": "hello"}]


@pytest.mark.asyncio
async def test_chat_lock_serializes_concurrent_chat_turns() -> None:
    """Fix #2 regression: two 'chat' frames arriving back-to-back must
    NOT both call ChatState.start_turn concurrently. Under the current
    dispatch model each frame runs in its own task; the chat_lock on
    the context is what keeps them serial. Assert by counting overlap
    inside the chat branch — should stay at 1.
    """
    from hexgate.cli.serve import ServeContext, _handle_message
    from hexgate.cli.state import ChatState

    concurrent_in_chat = 0
    max_seen_concurrent = 0

    class _NoopWS:
        async def send(self, _: str) -> None:
            pass

    async def _fake_stream_agent(agent, handler, inp):  # noqa: ARG001
        nonlocal concurrent_in_chat, max_seen_concurrent
        concurrent_in_chat += 1
        max_seen_concurrent = max(max_seen_concurrent, concurrent_in_chat)
        # Yield so a lock-free second chat would race in here.
        await asyncio.sleep(0.01)
        concurrent_in_chat -= 1
        if False:  # pragma: no cover — never yields, keeps signature async iter
            yield None

    class _StubRuntime:
        agent = object()
        handler = object()

    context = ServeContext(
        runtime=_StubRuntime(),  # type: ignore[arg-type]
        state=ChatState(),
        api_key="test-key",
        approval_handler=None,
        send_lock=asyncio.Lock(),
        chat_lock=asyncio.Lock(),
    )

    import hexgate.cli.serve as serve_mod

    original = serve_mod.stream_agent
    serve_mod.stream_agent = _fake_stream_agent
    try:
        ws = _NoopWS()
        await asyncio.gather(
            _handle_message(context, ws, {"type": "chat", "message": "first"}),
            _handle_message(context, ws, {"type": "chat", "message": "second"}),
        )
    finally:
        serve_mod.stream_agent = original

    assert max_seen_concurrent == 1, (
        "two chat frames overlapped — chat_lock did not serialize them"
    )
