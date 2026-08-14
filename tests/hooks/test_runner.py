"""Behavioral tests for the guarded-call runner.

Covers the four-step order (before, decide, invoke, after), the security
invariant that ``decide`` sees the exact args that execute, halt-message
safety, the modification/observer channel, the fail-closed / observe-open
error tiers, arg rewrite, selectivity, ordering, approval, and the sync path.
"""

from __future__ import annotations

import pytest

from hexgate.hooks import after_tool, before_tool
from hexgate.hooks.runner import run_guarded_async, run_guarded_sync
from hexgate.hooks.types import (
    Halt,
    Hook,
    HookEvent,
    Modification,
    Proceed,
    ToolCall,
    ToolOutcome,
    ToolPipeline,
)
from hexgate.security.decision import DecisionOutcome
from tests.hooks.helpers import FakeEnforcer, RecordingInvoke, langchain_error


def _pipe(pre=(), post=(), observer=None) -> ToolPipeline:
    """Build a pipeline, wrapping bare callables in the right decorator."""
    return ToolPipeline(
        pre=[p if isinstance(p, Hook) else before_tool(p) for p in pre],
        post=[q if isinstance(q, Hook) else after_tool(q) for q in post],
        observer=observer,
    )


async def _run(enforcer, pipeline, args, *, invoke, approval_handler=None):
    return await run_guarded_async(
        "echo",
        args,
        enforcer=enforcer,
        pipeline=pipeline,
        approval_handler=approval_handler,
        invoke=invoke.aio,
        render_error=langchain_error,
    )


# ---------------------------------------------------------------------------
# The happy path and the ordering invariant
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allow_returns_raw_and_decide_sees_args() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    out = await _run(enf, None, {"x": 1}, invoke=inv)
    assert out == "ok"
    assert enf.seen_args == {"x": 1}
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_pre_observe_none_is_a_noop() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: None])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert out == "tool-ran"
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_pre_rewrite_is_what_decide_and_the_tool_see() -> None:
    """The security invariant: decide authorizes the rewritten args, not the original."""
    enf, inv = FakeEnforcer(), RecordingInvoke()

    def drop_secret(call: ToolCall):
        return Proceed(args={k: v for k, v in call.args.items() if k != "secret"})

    pipe = _pipe(pre=[drop_secret])
    await _run(enf, pipe, {"x": 1, "secret": "AKIA"}, invoke=inv)

    assert enf.seen_args == {"x": 1}
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_pre_rewrite_records_a_modification_to_the_observer() -> None:
    events: list[HookEvent] = []
    enf, inv = FakeEnforcer(), RecordingInvoke()

    def redact(call: ToolCall):
        return Proceed(
            args={"x": 1},
            modification=Modification("redact", "args", "dropped secret"),
        )

    pipe = _pipe(pre=[redact], observer=events.append)
    await _run(enf, pipe, {"x": 1, "secret": "s"}, invoke=inv)

    assert len(events) == 1
    assert events[0].modifications[0].summary == "dropped secret"


@pytest.mark.asyncio
async def test_pre_rewrite_synthesizes_a_default_modification() -> None:
    events: list[HookEvent] = []
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Proceed(args={"x": 2})], observer=events.append)
    await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert events[0].modifications[0].plugin == "<lambda>"
    assert events[0].modifications[0].target == "args"


@pytest.mark.asyncio
async def test_two_pre_hooks_run_in_order_and_compose() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(
        pre=[
            lambda call: Proceed(args={**call.args, "a": 1}),
            lambda call: Proceed(args={**call.args, "b": call.args["a"] + 1}),
        ]
    )
    await _run(enf, pipe, {}, invoke=inv)
    assert enf.seen_args == {"a": 1, "b": 2}


# ---------------------------------------------------------------------------
# Halt: safety of the model-facing message
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pre_halt_blocks_before_decide_and_tool() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Halt(reason="Refused: a credential was found.")])
    out = await _run(enf, pipe, {"secret": "AKIAXXXX"}, invoke=inv)

    assert out["ok"] is False
    assert inv.calls == []  # tool not invoked
    assert enf.seen_args is None  # decide skipped


@pytest.mark.asyncio
async def test_halt_message_carries_reason_but_never_the_input_or_detail() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(
        pre=[
            lambda call: Halt(
                reason="Refused: a credential was found in the arguments.",
                detail="matched field=secret value_sha256=abc123",
            )
        ]
    )
    out = await _run(enf, pipe, {"secret": "AKIASUPERSECRET"}, invoke=inv)
    payload = out["error"]

    assert "credential" in payload["message"]
    assert "AKIASUPERSECRET" not in str(payload)  # the input is never echoed
    assert "secret" not in str(payload)  # nor the operator detail
    assert "abc123" not in str(payload)
    assert "arguments" not in payload  # args snapshot stays off the model
    assert payload["retryable"] is False


@pytest.mark.asyncio
async def test_decide_deny_blocks_and_does_not_invoke() -> None:
    enf, inv = FakeEnforcer(DecisionOutcome.DENY, reason="nope"), RecordingInvoke()
    out = await _run(enf, None, {"x": 1}, invoke=inv)
    assert out["ok"] is False
    assert out["error"]["type"] == "policy_denied"
    assert inv.calls == []


@pytest.mark.asyncio
async def test_rewrite_then_deny_still_reports_the_modification() -> None:
    """A rewrite followed by a policy deny is the coercion-detection signal."""
    events: list[HookEvent] = []
    enf = FakeEnforcer(DecisionOutcome.DENY)
    inv = RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Proceed(args={"x": 0})], observer=events.append)
    await _run(enf, pipe, {"x": 999}, invoke=inv)

    assert len(events) == 1
    assert events[0].modifications[0].target == "args"
    assert events[0].halt is None
    assert inv.calls == []


# ---------------------------------------------------------------------------
# After-guards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_halt_suppresses_a_result_that_was_produced() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("leaked-secret")
    pipe = _pipe(post=[lambda call, out: Halt(reason="Result withheld by policy.")])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)

    assert out["ok"] is False
    assert inv.calls == [{"x": 1}]  # the tool DID run; only the result is suppressed


@pytest.mark.asyncio
async def test_post_observe_sees_the_outcome_and_passes_it_through() -> None:
    seen: list[ToolOutcome] = []
    enf, inv = FakeEnforcer(), RecordingInvoke("value")

    def watch(call: ToolCall, out: ToolOutcome):
        seen.append(out)
        return None

    pipe = _pipe(post=[watch])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)

    assert out == "value"
    assert seen[0].ok is True and seen[0].value == "value"


@pytest.mark.asyncio
async def test_scratch_is_shared_from_pre_to_post() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    seen: list[str] = []

    def pre(call: ToolCall):
        call.scratch["tag"] = "hello"
        return None

    def post(call: ToolCall, out: ToolOutcome):
        seen.append(call.scratch.get("tag", ""))
        return None

    pipe = _pipe(pre=[pre], post=[post])
    await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert seen == ["hello"]


# ---------------------------------------------------------------------------
# Error tiers: fail-closed vs observe-open
# ---------------------------------------------------------------------------


def _boom(*_a):
    raise RuntimeError("kaboom")


@pytest.mark.asyncio
async def test_raising_pre_hook_fails_closed(caplog) -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[_boom])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert out["ok"] is False
    assert inv.calls == []


@pytest.mark.asyncio
async def test_raising_post_hook_fails_closed_after_the_tool_ran() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(post=[_boom])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert out["ok"] is False
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_observe_guard_is_fail_open() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(pre=[before_tool(_boom, observe=True)])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert out == "ok"
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_observe_guard_cannot_halt() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(pre=[before_tool(lambda call: Halt(reason="ignored"), observe=True)])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert out == "ok"  # the halt is discarded
    assert inv.calls == [{"x": 1}]


# ---------------------------------------------------------------------------
# Contract violations raise (developer bugs, not runtime denials)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bad_hook_return_type_raises() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: "not-an-outcome"])
    with pytest.raises(TypeError, match="expected Proceed, Halt, or None"):
        await _run(enf, pipe, {"x": 1}, invoke=inv)


@pytest.mark.asyncio
async def test_pre_hook_result_rewrite_is_rejected_in_v1() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Proceed(result="x")])
    with pytest.raises(ValueError, match="result rewrite"):
        await _run(enf, pipe, {"x": 1}, invoke=inv)


@pytest.mark.asyncio
async def test_post_hook_arg_rewrite_is_rejected() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(post=[lambda call, out: Proceed(args={"x": 2})])
    with pytest.raises(ValueError, match="cannot rewrite args"):
        await _run(enf, pipe, {"x": 1}, invoke=inv)


@pytest.mark.asyncio
async def test_post_hook_result_rewrite_is_rejected() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(post=[lambda call, out: Proceed(result="rewritten")])
    with pytest.raises(ValueError, match="result rewrite"):
        await _run(enf, pipe, {"x": 1}, invoke=inv)


# ---------------------------------------------------------------------------
# Selectivity and no-enforcer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_names_scopes_a_guard_to_some_tools() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    guard = before_tool(lambda call: Halt(reason="blocked"), tool_names="other")
    pipe = _pipe(pre=[guard])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)  # tool is "echo", not "other"
    assert out == "tool-ran"
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_hooks_run_without_an_enforcer() -> None:
    inv = RecordingInvoke()
    seen: list[str] = []
    pipe = _pipe(pre=[lambda call: seen.append(call.tool_name) or None])
    out = await _run(None, pipe, {"x": 1}, invoke=inv)
    assert out == "tool-ran"
    assert seen == ["echo"]
    assert inv.calls == [{"x": 1}]


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pre_halt_needs_approval_approved_proceeds() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(
        pre=[
            lambda call: Halt(reason="sign-off", outcome=DecisionOutcome.NEEDS_APPROVAL)
        ]
    )
    out = await _run(enf, pipe, {"x": 1}, invoke=inv, approval_handler=True)
    assert out == "ok"
    assert inv.calls == [{"x": 1}]


@pytest.mark.asyncio
async def test_pre_halt_needs_approval_declined_blocks() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(
        pre=[
            lambda call: Halt(reason="sign-off", outcome=DecisionOutcome.NEEDS_APPROVAL)
        ]
    )
    out = await _run(enf, pipe, {"x": 1}, invoke=inv, approval_handler=False)
    assert out["ok"] is False
    assert inv.calls == []


# ---------------------------------------------------------------------------
# Sync path
# ---------------------------------------------------------------------------


def test_sync_rewrite_and_allow() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("sync-ok")
    pipe = _pipe(pre=[lambda call: Proceed(args={"y": 2})])
    out = run_guarded_sync(
        "echo",
        {"secret": "z"},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=inv.sync,
        render_error=langchain_error,
    )
    assert out == "sync-ok"
    assert enf.seen_args == {"y": 2}
    assert inv.calls == [{"y": 2}]


def test_sync_halt_blocks() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Halt(reason="no")])
    out = run_guarded_sync(
        "echo",
        {"x": 1},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=inv.sync,
        render_error=langchain_error,
    )
    assert out["ok"] is False
    assert inv.calls == []


@pytest.mark.filterwarnings("ignore::RuntimeWarning")
def test_sync_rejects_a_coroutine_returning_hook() -> None:
    async def async_hook(call: ToolCall):
        return None

    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[async_hook])
    with pytest.raises(RuntimeError, match="coroutine"):
        run_guarded_sync(
            "echo",
            {"x": 1},
            enforcer=enf,
            pipeline=pipe,
            approval_handler=None,
            invoke=inv.sync,
            render_error=langchain_error,
        )


def test_sync_observe_guard_async_is_swallowed() -> None:
    """An async observe guard on the sync path is fail-open, not fatal."""

    async def watcher(call: ToolCall):
        return None

    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(pre=[before_tool(watcher, observe=True)])
    out = run_guarded_sync(
        "echo",
        {"x": 1},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=inv.sync,
        render_error=langchain_error,
    )
    assert out == "ok"
    assert inv.calls == [{"x": 1}]


# ---------------------------------------------------------------------------
# Tool failures reach after-guards (the try/except around invoke)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_post_hook_observes_a_tool_that_raised() -> None:
    seen: list[ToolOutcome] = []
    enf = FakeEnforcer()

    def watch(call: ToolCall, out: ToolOutcome):
        seen.append(out)
        return None

    async def boom(_final):
        raise ValueError("db error blah")

    pipe = _pipe(post=[watch])
    with pytest.raises(ValueError, match="db error"):
        await run_guarded_async(
            "echo",
            {"x": 1},
            enforcer=enf,
            pipeline=pipe,
            approval_handler=None,
            invoke=boom,
            render_error=langchain_error,
        )
    assert seen[0].ok is False
    assert seen[0].value is None
    assert "db error" in (seen[0].error or "")


@pytest.mark.asyncio
async def test_post_hook_can_halt_a_raising_tool_instead_of_propagating() -> None:
    enf = FakeEnforcer()

    def scrub(call: ToolCall, out: ToolOutcome):
        if not out.ok:
            return Halt(reason="An upstream error was suppressed by policy.")
        return None

    async def boom(_final):
        raise ValueError("leaky-secret-in-message")

    pipe = _pipe(post=[scrub])
    out = await run_guarded_async(
        "echo",
        {"x": 1},
        enforcer=enf,
        pipeline=pipe,
        approval_handler=None,
        invoke=boom,
        render_error=langchain_error,
    )
    assert out["ok"] is False
    assert "leaky-secret" not in str(out)


@pytest.mark.asyncio
async def test_tool_raise_without_post_hooks_propagates_unchanged() -> None:
    enf = FakeEnforcer()

    async def boom(_final):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        await run_guarded_async(
            "echo",
            {"x": 1},
            enforcer=enf,
            pipeline=None,
            approval_handler=None,
            invoke=boom,
            render_error=langchain_error,
        )


# ---------------------------------------------------------------------------
# Observer scope: fires on guard actions, not on every call
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_observer_is_silent_on_a_clean_allow() -> None:
    events: list[HookEvent] = []
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: None], observer=events.append)
    await _run(enf, pipe, {"x": 1}, invoke=inv)
    assert events == []  # no rewrite, no halt, no approval -> no HookEvent


@pytest.mark.asyncio
async def test_rewrite_plus_approved_halt_reports_the_modification_once() -> None:
    """A rewrite and an approved halt on one call must not double-count the mod."""
    events: list[HookEvent] = []
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(
        pre=[
            lambda call: Proceed(args={"x": 1}),
            lambda call: Halt(reason="ok?", outcome=DecisionOutcome.NEEDS_APPROVAL),
        ],
        observer=events.append,
    )
    out = await _run(enf, pipe, {"x": 0}, invoke=inv, approval_handler=True)

    assert out == "ok"
    # The mod is carried by exactly one event, not by both the approval event
    # and the terminal event.
    total_mods = sum(len(e.modifications) for e in events)
    assert total_mods == 1
    assert any(e.approved for e in events)


@pytest.mark.asyncio
async def test_approved_pre_halt_reports_a_hookevent() -> None:
    events: list[HookEvent] = []
    enf, inv = FakeEnforcer(), RecordingInvoke("ok")
    pipe = _pipe(
        pre=[
            lambda call: Halt(reason="sign-off", outcome=DecisionOutcome.NEEDS_APPROVAL)
        ],
        observer=events.append,
    )
    out = await _run(enf, pipe, {"x": 1}, invoke=inv, approval_handler=True)
    assert out == "ok"
    assert len(events) == 1
    assert events[0].approved is True
    assert events[0].halt is not None


# ---------------------------------------------------------------------------
# In-place mutation is contained (args read-only, result isolated)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_observe_guard_cannot_mutate_args_in_place() -> None:
    """call.args is read-only, so an in-place write can't slip past decide."""
    enf, inv = FakeEnforcer(), RecordingInvoke()

    def mutate(call: ToolCall):
        call.args["injected"] = True  # raises on the proxy; observe = fail-open
        return None

    pipe = _pipe(pre=[before_tool(mutate, observe=True)])
    out = await _run(enf, pipe, {"x": 1}, invoke=inv)

    assert out == "tool-ran"
    assert enf.seen_args == {"x": 1}  # decide saw the original
    assert inv.calls == [{"x": 1}]  # the tool saw the original


@pytest.mark.asyncio
async def test_observe_after_guard_cannot_mutate_the_returned_object() -> None:
    """The value handed to after-guards is a copy; the caller's object is safe."""
    enf = FakeEnforcer()
    real = {"name": "bob"}
    inv = RecordingInvoke(real)

    def mutate(call: ToolCall, out: ToolOutcome):
        out.value["ssn"] = "LEAK"  # mutates the copy, not the real object
        return None

    pipe = _pipe(post=[after_tool(mutate, observe=True)])
    result = await _run(enf, pipe, {"x": 1}, invoke=inv)

    assert result == {"name": "bob"}  # caller gets the original, unmutated
    assert "ssn" not in real


# ---------------------------------------------------------------------------
# Guard halts hit the audit trail (record), with a distinct marker
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pre_halt_is_recorded_as_guard_denied_with_args() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke()
    pipe = _pipe(pre=[lambda call: Halt(reason="blocked")])
    await _run(enf, pipe, {"x": 1}, invoke=inv)

    assert len(enf.recorded) == 1  # decide never ran; only the halt is recorded
    assert enf.recorded[0].error_type == "guard_denied"
    assert enf.recorded[0].arguments == {"x": 1}  # args on the trail, not the model


@pytest.mark.asyncio
async def test_post_halt_records_both_the_allow_and_the_guard_denial() -> None:
    enf, inv = FakeEnforcer(), RecordingInvoke("val")
    pipe = _pipe(post=[lambda call, out: Halt(reason="withheld")])
    await _run(enf, pipe, {"x": 1}, invoke=inv)

    outcomes = [d.outcome for d in enf.recorded]
    markers = [d.error_type for d in enf.recorded]
    assert DecisionOutcome.ALLOW in outcomes  # the tool genuinely ran
    assert "guard_denied" in markers  # and the halt is also on the trail
