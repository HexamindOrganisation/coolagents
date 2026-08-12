"""The guarded-call runner: pre-hooks, decide, invoke, post-hooks.

One shared sequence the adapters call instead of their own inline
decide-then-invoke. It is adapter-agnostic: the caller passes an ``invoke``
closure that runs the wrapped tool on the (possibly rewritten) args, and a
``render_error`` closure that shapes a blocked :class:`Decision` for that
framework (LangChain returns a dict, the string-result adapters return a
string).

Ordering is fixed and load-bearing: **pre-hooks run before ``decide``**, so
``decide`` always authorizes the exact args that will execute. A pre-hook can
rewrite args or halt; it can never widen, because ``decide`` still runs on its
output. Post-hooks observe or halt in v1 (result rewrite is a later phase).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import replace
from inspect import isawaitable
from typing import TYPE_CHECKING, Any

from hexgate.agents.approvals import resolve_approval_async, resolve_approval_sync
from hexgate.hooks.types import (
    _UNSET,
    Halt,
    Hook,
    HookEvent,
    Modification,
    Proceed,
    ToolCall,
    ToolOutcome,
    ToolPipeline,
)
from hexgate.runtime.context import get_current_context
from hexgate.security.decision import Decision, DecisionOutcome, Verdict

if TYPE_CHECKING:
    from hexgate.approvals import ApprovalHandler
    from hexgate.security.enforcer import PolicyEnforcer

_log = logging.getLogger(__name__)

RenderError = Callable[[Decision], Any]


# ---------------------------------------------------------------------------
# Shared, async-free helpers
# ---------------------------------------------------------------------------


def _new_call(
    tool_name: str, args: Mapping[str, Any], enforcer: "PolicyEnforcer | None"
) -> ToolCall:
    agent_name = getattr(enforcer, "agent_name", None) if enforcer is not None else None
    return ToolCall(
        tool_name=tool_name,
        args=dict(args),
        agent_name=agent_name,
        context=get_current_context(),
        scratch={},
    )


def _applies(hook: Hook, tool_name: str) -> bool:
    return hook.matches is None or hook.matches(tool_name)


def _fail_closed(hook: Hook) -> Halt | None:
    """Turn a hook exception into a denial, or ``None`` for observe-only.

    Called from inside the ``except`` block so ``_log.exception`` still has the
    live traceback.
    """
    if hook.observe_only:
        _log.exception("observe_only hook %s raised; ignoring", hook.label)
        return None
    _log.exception("hook %s raised; failing closed (deny)", hook.label)
    return Halt(
        reason="Blocked by a policy hook.",
        outcome=DecisionOutcome.DENY,
        detail=f"hook {hook.label!r} raised",
    )


def _normalize(hook: Hook, result: Any) -> Proceed | Halt | None:
    """Validate a hook's return value.

    An ``observe_only`` hook's return is discarded (it can neither rewrite nor
    halt). A normal hook must return ``Proceed``, ``Halt``, or ``None``; any
    other type is a contract violation and raises, so the bug surfaces in
    development rather than silently passing.
    """
    if hook.observe_only:
        if result is not None:
            _log.warning(
                "observe_only hook %s returned %s; ignoring (observe-only hooks "
                "cannot rewrite or halt)",
                hook.label,
                type(result).__name__,
            )
        return None
    if result is None or isinstance(result, (Proceed, Halt)):
        return result
    raise TypeError(
        f"hook {hook.label!r} returned {type(result).__name__}; "
        "expected Proceed, Halt, or None"
    )


def _apply_pre(
    call: ToolCall, hook: Hook, proceed: Proceed, mods: list[Modification]
) -> ToolCall:
    """Apply a pre-hook ``Proceed`` (an arg rewrite) to the working call."""
    if proceed.result is not _UNSET:
        raise ValueError(
            f"pre-hook {hook.label!r} returned Proceed(result=...); result "
            "rewrite is a post-hook, later-phase feature"
        )
    if proceed.args is None:
        return call
    mods.append(
        proceed.modification
        or Modification(plugin=hook.label, target="args", summary="rewrote arguments")
    )
    return replace(call, args=dict(proceed.args))


def _reject_post_proceed(hook: Hook, proceed: Proceed) -> None:
    if proceed.args is not None:
        raise ValueError(
            f"post-hook {hook.label!r} returned Proceed(args=...); post-hooks "
            "cannot rewrite args"
        )
    if proceed.result is not _UNSET:
        raise ValueError(
            f"post-hook {hook.label!r} returned Proceed(result=...); result "
            "rewrite is a later phase"
        )


def _halt_to_decision(halt: Halt, call: ToolCall) -> Decision:
    """Render a ``Halt`` through the same path a policy denial uses.

    No arguments are attached, so ``as_error_payload`` cannot echo the input
    the hook objected to. ``reason`` is the model-facing text; ``detail`` stays
    on the observer channel.
    """
    role = call.context.primary_role if call.context is not None else None
    return Decision.from_verdict(
        Verdict(outcome=halt.outcome, reason=halt.reason),
        agent_name=call.agent_name or "default",
        tool_name=call.tool_name,
        role=role,
    )


def _notify(
    pipeline: ToolPipeline | None,
    call: ToolCall,
    mods: list[Modification],
    *,
    halt: Halt | None = None,
    halted_by: str | None = None,
) -> None:
    if pipeline is None or pipeline.observer is None:
        return
    try:
        pipeline.observer(
            HookEvent(
                call=call,
                modifications=tuple(mods),
                halt=halt,
                halted_by=halted_by,
            )
        )
    except Exception:
        _log.exception("hook observer raised; ignoring")


# ---------------------------------------------------------------------------
# Async path
# ---------------------------------------------------------------------------


async def _call_hook_async(hook: Hook, *hook_args: Any) -> Proceed | Halt | None:
    try:
        result = hook.fn(*hook_args)
        if isawaitable(result):
            result = await result
    except Exception:
        return _fail_closed(hook)
    return _normalize(hook, result)


async def _halt_approved_async(
    halt: Halt, call: ToolCall, approval_handler: "ApprovalHandler | None"
) -> bool:
    if halt.outcome is not DecisionOutcome.NEEDS_APPROVAL or approval_handler is None:
        return False
    return await resolve_approval_async(approval_handler, _halt_to_decision(halt, call))


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
    call = _new_call(tool_name, args, enforcer)
    mods: list[Modification] = []

    if pipeline is not None:
        for hook in pipeline.pre:
            if not _applies(hook, call.tool_name):
                continue
            outcome = await _call_hook_async(hook, call)
            if isinstance(outcome, Halt):
                if await _halt_approved_async(outcome, call, approval_handler):
                    continue
                _notify(pipeline, call, mods, halt=outcome, halted_by=hook.label)
                return render_error(_halt_to_decision(outcome, call))
            if isinstance(outcome, Proceed):
                call = _apply_pre(call, hook, outcome, mods)

    if enforcer is not None:
        decision = enforcer.decide(call.tool_name, call.args)
        if not decision.allowed:
            approved = (
                decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                and approval_handler is not None
                and await resolve_approval_async(approval_handler, decision)
            )
            if not approved:
                if mods:
                    _notify(pipeline, call, mods)
                return render_error(decision)

    raw = await invoke(call.args)

    if pipeline is not None and pipeline.post:
        result_outcome = ToolOutcome(ok=True, value=raw)
        for hook in pipeline.post:
            if not _applies(hook, call.tool_name):
                continue
            outcome = await _call_hook_async(hook, call, result_outcome)
            if isinstance(outcome, Halt):
                if await _halt_approved_async(outcome, call, approval_handler):
                    continue
                _notify(pipeline, call, mods, halt=outcome, halted_by=hook.label)
                return render_error(_halt_to_decision(outcome, call))
            if isinstance(outcome, Proceed):
                _reject_post_proceed(hook, outcome)

    if mods:
        _notify(pipeline, call, mods)
    return raw


# ---------------------------------------------------------------------------
# Sync path
# ---------------------------------------------------------------------------


def _call_hook_sync(hook: Hook, *hook_args: Any) -> Proceed | Halt | None:
    try:
        result = hook.fn(*hook_args)
    except Exception:
        return _fail_closed(hook)
    if isawaitable(result):
        # A wiring mistake (async hook on a sync entry point), not a runtime
        # denial. Surface it loudly rather than drop an un-awaited coroutine.
        raise RuntimeError(
            f"hook {hook.label!r} returned a coroutine; sync tool invocation "
            "cannot await it — use an async entry point (ainvoke / astream / "
            "astream_events / run_async / etc.)."
        )
    return _normalize(hook, result)


def _halt_approved_sync(
    halt: Halt, call: ToolCall, approval_handler: "ApprovalHandler | None"
) -> bool:
    if halt.outcome is not DecisionOutcome.NEEDS_APPROVAL or approval_handler is None:
        return False
    return resolve_approval_sync(approval_handler, _halt_to_decision(halt, call))


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
    call = _new_call(tool_name, args, enforcer)
    mods: list[Modification] = []

    if pipeline is not None:
        for hook in pipeline.pre:
            if not _applies(hook, call.tool_name):
                continue
            outcome = _call_hook_sync(hook, call)
            if isinstance(outcome, Halt):
                if _halt_approved_sync(outcome, call, approval_handler):
                    continue
                _notify(pipeline, call, mods, halt=outcome, halted_by=hook.label)
                return render_error(_halt_to_decision(outcome, call))
            if isinstance(outcome, Proceed):
                call = _apply_pre(call, hook, outcome, mods)

    if enforcer is not None:
        decision = enforcer.decide(call.tool_name, call.args)
        if not decision.allowed:
            approved = (
                decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                and approval_handler is not None
                and resolve_approval_sync(approval_handler, decision)
            )
            if not approved:
                if mods:
                    _notify(pipeline, call, mods)
                return render_error(decision)

    raw = invoke(call.args)

    if pipeline is not None and pipeline.post:
        result_outcome = ToolOutcome(ok=True, value=raw)
        for hook in pipeline.post:
            if not _applies(hook, call.tool_name):
                continue
            outcome = _call_hook_sync(hook, call, result_outcome)
            if isinstance(outcome, Halt):
                if _halt_approved_sync(outcome, call, approval_handler):
                    continue
                _notify(pipeline, call, mods, halt=outcome, halted_by=hook.label)
                return render_error(_halt_to_decision(outcome, call))
            if isinstance(outcome, Proceed):
                _reject_post_proceed(hook, outcome)

    if mods:
        _notify(pipeline, call, mods)
    return raw


__all__ = ["run_guarded_async", "run_guarded_sync"]
