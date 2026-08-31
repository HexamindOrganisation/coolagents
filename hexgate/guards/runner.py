"""The guarded-call runner: pre-guards, decide, invoke, post-guards.

One shared sequence the adapters call instead of their own inline
decide-then-invoke. It is adapter-agnostic: the caller passes an ``invoke``
closure that runs the wrapped tool on the (possibly rewritten) args, and a
``render_error`` closure that shapes a blocked :class:`Decision` for that
framework (LangChain returns a dict, the string-result adapters return a
string).

Ordering is fixed and load-bearing: **pre-guards run before ``decide``**, so
``decide`` always authorizes the exact args that will execute. A pre-guard can
rewrite args or halt; it can never widen, because ``decide`` still runs on its
output. Post-guards observe or halt in v1 (result rewrite is a later phase), and
they run whether the tool returned or raised, so a watcher sees a failure the
same way it sees a result. If the tool raised and no post-guard halts, the
original exception propagates unchanged.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from inspect import isawaitable
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from hexgate.agents.approvals import resolve_approval_async, resolve_approval_sync
from hexgate.guards.types import (
    _UNSET,
    Halt,
    Guard,
    GuardEvent,
    Modification,
    Proceed,
    ToolCall,
    ToolOutcome,
    ToolPipeline,
)
from hexgate.runtime.context import get_current_context
from hexgate.runtime.run_facts import get_run_facts
from hexgate.security.decision import Decision, DecisionOutcome, Verdict

if TYPE_CHECKING:
    from hexgate.approvals import ApprovalHandler
    from hexgate.security.enforcer import PolicyEnforcer

_log = logging.getLogger(__name__)

RenderError = Callable[[Decision], Any]

# Sentinel a post-guard runner returns when nothing halted, distinct from any
# value ``render_error`` might produce (a dict or str). Identity-compared only.
_NO_HALT: Any = object()


# ---------------------------------------------------------------------------
# Shared, async-free helpers
# ---------------------------------------------------------------------------


def _has_guards(pipeline: ToolPipeline | None) -> bool:
    return pipeline is not None and not pipeline.is_empty


def _new_call(
    tool_name: str,
    args: Mapping[str, Any],
    enforcer: "PolicyEnforcer | None",
    context: Any,
) -> ToolCall:
    agent_name = getattr(enforcer, "agent_name", None) if enforcer is not None else None
    return ToolCall(
        tool_name=tool_name,
        # Read-only view: guards read args freely, but the only way to change
        # them is Proceed(args=...); an in-place write raises. (Shallow: a
        # nested dict stays mutable, the documented residual.)
        args=MappingProxyType(dict(args)),
        agent_name=agent_name,
        context=context,
        scratch={},
    )


def _applies(guard: Guard, tool_name: str) -> bool:
    return guard.applies(tool_name)


def _fail_closed(guard: Guard) -> Halt | None:
    """Turn a guard exception into a denial, or ``None`` for an observe guard.

    Called from inside the ``except`` block so ``_log.exception`` still has the
    live traceback.
    """
    if guard.observe:
        _log.exception("observe guard %s raised; ignoring", guard.label)
        return None
    _log.exception("guard %s raised; failing closed (deny)", guard.label)
    return Halt(
        reason="Blocked by a policy guard.",
        outcome=DecisionOutcome.DENY,
        detail=f"guard {guard.label!r} raised",
    )


def _normalize(guard: Guard, result: Any) -> Proceed | Halt | None:
    """Validate a guard's return value.

    An observe guard's return is discarded (it can neither rewrite nor halt). A
    normal guard must return ``Proceed``, ``Halt``, or ``None``; any other type
    is a contract violation and raises, so the bug surfaces in development
    rather than silently passing.
    """
    if guard.observe:
        if result is not None:
            _log.warning(
                "observe guard %s returned %s; ignoring (observe guards cannot "
                "rewrite or halt)",
                guard.label,
                type(result).__name__,
            )
        return None
    if result is None or isinstance(result, (Proceed, Halt)):
        return result
    raise TypeError(
        f"guard {guard.label!r} returned {type(result).__name__}; "
        "expected Proceed, Halt, or None"
    )


def _apply_pre(
    call: ToolCall, guard: Guard, proceed: Proceed, mods: list[Modification]
) -> ToolCall:
    """Apply a pre-guard ``Proceed`` (an arg rewrite) to the working call."""
    if proceed.result is not _UNSET:
        raise ValueError(
            f"pre-guard {guard.label!r} returned Proceed(result=...); result "
            "rewrite is a post-guard, later-phase feature"
        )
    if proceed.args is None:
        return call
    mods.append(
        proceed.modification
        or Modification(plugin=guard.label, target="args", summary="rewrote arguments")
    )
    return replace(call, args=MappingProxyType(dict(proceed.args)))


def _reject_post_proceed(guard: Guard, proceed: Proceed) -> None:
    if proceed.args is not None:
        raise ValueError(
            f"post-guard {guard.label!r} returned Proceed(args=...); post-guards "
            "cannot rewrite args"
        )
    if proceed.result is not _UNSET:
        raise ValueError(
            f"post-guard {guard.label!r} returned Proceed(result=...); result "
            "rewrite is a later phase"
        )


def _halt_to_decision(halt: Halt, call: ToolCall) -> Decision:
    """Render a ``Halt`` as a :class:`Decision`.

    ``reason`` is the model-facing text; ``detail`` stays on the observer
    channel. The arguments are attached for the audit trail only, since
    ``as_error_payload`` / ``as_error_message`` never render them, so the model
    still cannot see the input the guard objected to. A DENY halt is marked
    ``guard_denied`` so it is distinguishable from a real policy denial to both
    the model and any trail consumer.
    """
    # A guard halt has no policy-deciding role (the guard decided, not a role),
    # so deciding_role stays None; user_roles carries the caller's roles.
    user_roles = tuple(call.context.user_roles) if call.context is not None else ()
    decision = Decision.from_verdict(
        Verdict(outcome=halt.outcome, reason=halt.reason),
        agent_name=call.agent_name or "default",
        tool_name=call.tool_name,
        user_roles=user_roles,
        arguments=dict(call.args),
    )
    if halt.outcome is DecisionOutcome.DENY:
        decision = replace(decision, error_type="guard_denied")
    return decision


def _seal_result(value: Any) -> Any:
    """Wrap a dict result in a read-only view before the after-guards see it,
    so an in-place mutation can't escape into the tool's real return object
    (R-GUARD-003). O(1), the same seal ``_new_call`` puts on args — a whole
    deep-copy on the hot path (a large response cloned for an observe-only
    watcher) is the cost this avoids. Lists and opaque objects pass through:
    there is no cheap read-only view for them, and a nested dict inside a
    sealed dict is the same documented shallow residual as on args."""
    if isinstance(value, dict):
        return MappingProxyType(value)
    return value


def _record_halt(
    enforcer: "PolicyEnforcer | None", decision: Decision, call: ToolCall
) -> None:
    """Record a guard halt on the enforcer's audit + observer channels, so a
    guard-blocked call leaves the same trail a policy denial does. No-op with no
    enforcer (the guards-only path has no audit sender)."""
    if enforcer is None:
        return
    ctx = call.context
    enforcer.record(
        decision,
        user_id=ctx.user_id if ctx is not None and ctx.user_id else "",
        session_id=ctx.session_id if ctx is not None and ctx.session_id else "",
    )


def _record_run_decision(outcome: DecisionOutcome) -> None:
    """Accrue a non-allow decision to the run's facts.

    Denials and approval gates are separate counters: a denied call consumes no
    tool budget, and neither does an approval that's never granted. The enum
    branch lives here (not on ``RunFacts``) so ``hexgate.runtime`` never
    imports ``hexgate.security``.
    """
    facts = get_run_facts()
    if outcome is DecisionOutcome.DENY:
        facts.record_denial()
    elif outcome is DecisionOutcome.NEEDS_APPROVAL:
        facts.record_approval()


def _record_run_execution(tool_name: str, *, failed: bool = False) -> None:
    """Count a tool that ran, whether it returned or raised. Called around
    ``invoke``, before the post-guards — a post-guard halt must not un-count a
    call whose side effect already happened."""
    facts = get_run_facts()
    facts.record_execution(tool_name)
    if failed:
        facts.record_error()


def _notify(
    pipeline: ToolPipeline | None,
    call: ToolCall,
    mods: list[Modification],
    *,
    halt: Halt | None = None,
    halted_by: str | None = None,
    approved: bool = False,
    blocked: bool = False,
) -> None:
    if pipeline is None or pipeline.observer is None:
        return
    try:
        pipeline.observer(
            GuardEvent(
                call=call,
                modifications=tuple(mods),
                halt=halt,
                halted_by=halted_by,
                approved=approved,
                blocked=blocked,
            )
        )
    except Exception:
        _log.exception("guard observer raised; ignoring")


# ---------------------------------------------------------------------------
# Async path
# ---------------------------------------------------------------------------


async def _call_guard_async(guard: Guard, *guard_args: Any) -> Proceed | Halt | None:
    try:
        result = guard.fn(*guard_args)
        if isawaitable(result):
            result = await result
    except Exception:
        return _fail_closed(guard)
    return _normalize(guard, result)


async def _halt_approved_async(
    halt: Halt, call: ToolCall, approval_handler: "ApprovalHandler | None"
) -> bool:
    if halt.outcome is not DecisionOutcome.NEEDS_APPROVAL or approval_handler is None:
        return False
    return await resolve_approval_async(approval_handler, _halt_to_decision(halt, call))


async def _run_post_async(
    pipeline: ToolPipeline | None,
    call: ToolCall,
    outcome: ToolOutcome,
    mods: list[Modification],
    approval_handler: "ApprovalHandler | None",
    enforcer: "PolicyEnforcer | None",
    render_error: RenderError,
) -> Any:
    """Run the post-guards over ``outcome``.

    Returns a rendered error when a post-guard halts, else :data:`_NO_HALT`.
    Runs for a successful result and for a tool that raised
    (``outcome.ok is False``), so an observe or redact guard sees failures too.
    A blocking halt is recorded to the audit trail *in addition to* the tool's
    genuine ALLOW (the tool did run; only the result is withheld).
    """
    if pipeline is None:
        return _NO_HALT
    for guard in pipeline.post:
        if not _applies(guard, call.tool_name):
            continue
        res = await _call_guard_async(guard, call, outcome)
        if isinstance(res, Halt):
            halt_decision = _halt_to_decision(res, call)
            # No execution recorded: the tool already counted around ``invoke``.
            _record_run_decision(halt_decision.outcome)
            if await _halt_approved_async(res, call, approval_handler):
                _record_halt(enforcer, halt_decision, call)
                _notify(
                    pipeline, call, [], halt=res, halted_by=guard.label, approved=True
                )
                continue
            _record_halt(enforcer, halt_decision, call)
            _notify(pipeline, call, mods, halt=res, halted_by=guard.label)
            return render_error(halt_decision)
        if isinstance(res, Proceed):
            _reject_post_proceed(guard, res)
    return _NO_HALT


async def run_guarded_async(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    enforcer: "PolicyEnforcer | None",
    pipeline: ToolPipeline | None,
    approval_handler: "ApprovalHandler | None",
    invoke: Callable[[dict[str, Any]], Awaitable[Any]],
    render_error: RenderError,
) -> Any:
    """Run one guarded tool call, async. See module docstring for the order."""
    context = get_current_context() if _has_guards(pipeline) else None
    call = _new_call(tool_name, args, enforcer, context)
    mods: list[Modification] = []

    if pipeline is not None:
        for guard in pipeline.pre:
            if not _applies(guard, call.tool_name):
                continue
            outcome = await _call_guard_async(guard, call)
            if isinstance(outcome, Halt):
                halt_decision = _halt_to_decision(outcome, call)
                # The tool hasn't run yet, whatever this halt's outcome is.
                _record_run_decision(halt_decision.outcome)
                if await _halt_approved_async(outcome, call, approval_handler):
                    # A granted guard approval is audited too, mirroring how
                    # ``decide`` records a policy NEEDS_APPROVAL — the human
                    # sign-off on a privileged call is the most worth keeping.
                    _record_halt(enforcer, halt_decision, call)
                    _notify(
                        pipeline,
                        call,
                        [],  # mods are reported once, by the terminal notify
                        halt=outcome,
                        halted_by=guard.label,
                        approved=True,
                    )
                    continue
                _record_halt(enforcer, halt_decision, call)
                _notify(pipeline, call, mods, halt=outcome, halted_by=guard.label)
                return render_error(halt_decision)
            if isinstance(outcome, Proceed):
                call = _apply_pre(call, guard, outcome, mods)

    if enforcer is not None:
        # A before-guard's NEEDS_APPROVAL (handled in the loop above) and the
        # policy's are independent gates: if both fire on one call, the handler
        # is prompted for each. We do not merge them, because a guard's approval
        # must not silently satisfy the policy's separate requirement.
        decision = enforcer.decide(call.tool_name, call.args)
        if not decision.allowed:
            # Counts the gate firing; whether it's granted is a separate count.
            _record_run_decision(decision.outcome)
            approved = (
                decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                and approval_handler is not None
                and await resolve_approval_async(approval_handler, decision)
            )
            if not approved:
                # A pre-guard may have rewritten args that the policy then
                # denied: report the rewrite, but flagged blocked so a
                # consumer never reads it as a rewrite that took effect.
                if mods:
                    _notify(pipeline, call, mods, blocked=True)
                return render_error(decision)

    try:
        raw = await invoke(dict(call.args))
        _record_run_execution(call.tool_name)
    except Exception as exc:
        _record_run_execution(call.tool_name, failed=True)
        rendered = await _run_post_async(
            pipeline,
            call,
            ToolOutcome(ok=False, value=None, error=str(exc)),
            mods,
            approval_handler,
            enforcer,
            render_error,
        )
        if rendered is not _NO_HALT:
            return rendered
        if mods:
            _notify(pipeline, call, mods)
        raise

    result_value = _seal_result(raw) if (pipeline and pipeline.post) else raw
    rendered = await _run_post_async(
        pipeline,
        call,
        ToolOutcome(ok=True, value=result_value),
        mods,
        approval_handler,
        enforcer,
        render_error,
    )
    if rendered is not _NO_HALT:
        return rendered
    if mods:
        _notify(pipeline, call, mods)
    return raw


# ---------------------------------------------------------------------------
# Sync path
# ---------------------------------------------------------------------------


def _call_guard_sync(guard: Guard, *guard_args: Any) -> Proceed | Halt | None:
    try:
        result = guard.fn(*guard_args)
    except Exception:
        return _fail_closed(guard)
    if isawaitable(result):
        if guard.observe:
            # An observe guard is fail-open: an async side-effect guard on a
            # sync path never ran, but it must not break the call. Drop the
            # coroutine (avoids an un-awaited warning) and log.
            result.close()
            _log.warning(
                "observe guard %s returned a coroutine on a sync path; "
                "ignoring (write it sync, or use an async entry point)",
                guard.label,
            )
            return None
        # A non-observe guard returning a coroutine on a sync path is a wiring
        # mistake, not a runtime denial. Surface it loudly.
        result.close()
        raise RuntimeError(
            f"guard {guard.label!r} returned a coroutine; sync tool invocation "
            "cannot await it — use an async entry point (ainvoke / astream / "
            "astream_events / run_async / etc.)."
        )
    return _normalize(guard, result)


def _halt_approved_sync(
    halt: Halt, call: ToolCall, approval_handler: "ApprovalHandler | None"
) -> bool:
    if halt.outcome is not DecisionOutcome.NEEDS_APPROVAL or approval_handler is None:
        return False
    return resolve_approval_sync(approval_handler, _halt_to_decision(halt, call))


def _run_post_sync(
    pipeline: ToolPipeline | None,
    call: ToolCall,
    outcome: ToolOutcome,
    mods: list[Modification],
    approval_handler: "ApprovalHandler | None",
    enforcer: "PolicyEnforcer | None",
    render_error: RenderError,
) -> Any:
    """Sync mirror of :func:`_run_post_async`."""
    if pipeline is None:
        return _NO_HALT
    for guard in pipeline.post:
        if not _applies(guard, call.tool_name):
            continue
        res = _call_guard_sync(guard, call, outcome)
        if isinstance(res, Halt):
            halt_decision = _halt_to_decision(res, call)
            # No execution recorded: the tool already counted around ``invoke``.
            _record_run_decision(halt_decision.outcome)
            if _halt_approved_sync(res, call, approval_handler):
                _record_halt(enforcer, halt_decision, call)
                _notify(
                    pipeline, call, [], halt=res, halted_by=guard.label, approved=True
                )
                continue
            _record_halt(enforcer, halt_decision, call)
            _notify(pipeline, call, mods, halt=res, halted_by=guard.label)
            return render_error(halt_decision)
        if isinstance(res, Proceed):
            _reject_post_proceed(guard, res)
    return _NO_HALT


def run_guarded_sync(
    tool_name: str,
    args: Mapping[str, Any],
    *,
    enforcer: "PolicyEnforcer | None",
    pipeline: ToolPipeline | None,
    approval_handler: "ApprovalHandler | None",
    invoke: Callable[[dict[str, Any]], Any],
    render_error: RenderError,
) -> Any:
    """Run one guarded tool call, sync. Mirrors :func:`run_guarded_async`."""
    context = get_current_context() if _has_guards(pipeline) else None
    call = _new_call(tool_name, args, enforcer, context)
    mods: list[Modification] = []

    if pipeline is not None:
        for guard in pipeline.pre:
            if not _applies(guard, call.tool_name):
                continue
            outcome = _call_guard_sync(guard, call)
            if isinstance(outcome, Halt):
                halt_decision = _halt_to_decision(outcome, call)
                # See the async path: recorded before the approval branch.
                _record_run_decision(halt_decision.outcome)
                if _halt_approved_sync(outcome, call, approval_handler):
                    # See the async path: a granted guard approval is audited.
                    _record_halt(enforcer, halt_decision, call)
                    _notify(
                        pipeline,
                        call,
                        [],  # mods are reported once, by the terminal notify
                        halt=outcome,
                        halted_by=guard.label,
                        approved=True,
                    )
                    continue
                _record_halt(enforcer, halt_decision, call)
                _notify(pipeline, call, mods, halt=outcome, halted_by=guard.label)
                return render_error(halt_decision)
            if isinstance(outcome, Proceed):
                call = _apply_pre(call, guard, outcome, mods)

    if enforcer is not None:
        decision = enforcer.decide(call.tool_name, call.args)
        if not decision.allowed:
            # See the async path: the gate firing is counted, the grant is not.
            _record_run_decision(decision.outcome)
            approved = (
                decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                and approval_handler is not None
                and resolve_approval_sync(approval_handler, decision)
            )
            if not approved:
                # See the async path: a rewrite the policy denied is reported
                # blocked, never as one that took effect.
                if mods:
                    _notify(pipeline, call, mods, blocked=True)
                return render_error(decision)

    try:
        raw = invoke(dict(call.args))
        # See the async path: counted after the decision, non-deny only.
        _record_run_execution(call.tool_name)
    except Exception as exc:
        _record_run_execution(call.tool_name, failed=True)
        rendered = _run_post_sync(
            pipeline,
            call,
            ToolOutcome(ok=False, value=None, error=str(exc)),
            mods,
            approval_handler,
            enforcer,
            render_error,
        )
        if rendered is not _NO_HALT:
            return rendered
        if mods:
            _notify(pipeline, call, mods)
        raise

    result_value = _seal_result(raw) if (pipeline and pipeline.post) else raw
    rendered = _run_post_sync(
        pipeline,
        call,
        ToolOutcome(ok=True, value=result_value),
        mods,
        approval_handler,
        enforcer,
        render_error,
    )
    if rendered is not _NO_HALT:
        return rendered
    if mods:
        _notify(pipeline, call, mods)
    return raw


__all__ = ["run_guarded_async", "run_guarded_sync"]
