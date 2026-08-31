"""What each path through the runner accrues to ``run.*``.

The counters *are* the semantics, and the semantics are what a policy author
reasons about when they write ``run.tool_calls < 20``. So this is a table over
every terminal path, run against both the sync and async runners — which are
line-for-line mirrors, and whose drift is the failure mode this file guards.

The invariants the table encodes:

  * A tool counts when it **executes**, after the decision and never on a deny.
    ``run.tool_calls < 20`` therefore permits exactly 20 executions.
  * A denied call consumes no tool budget. It accrues to ``run.denials``, which
    a policy bounds separately — otherwise a misbehaving agent burns a
    legitimate caller's budget by being refused.
  * An approval gate counts on the *decision*; execution counts separately, so
    an approval never granted consumes nothing.
  * A pre-guard halt is not a tool call — the tool never ran. A *post*-guard
    halt is: the tool ran and only the result is withheld.
"""

from __future__ import annotations

from typing import Any

import pytest

from hexgate.guards import after_tool, before_tool
from hexgate.guards.runner import run_guarded_async, run_guarded_sync
from hexgate.guards.types import Halt, ToolPipeline
from hexgate.runtime.run_facts import RunFacts, run_scope
from hexgate.security.decision import DecisionOutcome
from tests.guards.helpers import FakeEnforcer, RecordingInvoke, langchain_error

_TOOL = "echo"
_OTHER_TOOL = "search"

_ASYNC, _SYNC = "async", "sync"
_BOTH = pytest.mark.parametrize("path", [_ASYNC, _SYNC])


# An approval handler is a bool or a ``Decision -> bool`` callable; the
# constant form is what the existing runner suite uses.
_APPROVE, _REFUSE = True, False


class _Raises:
    """An ``invoke`` that always raises — the tool ran and failed."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def aio(self, final: dict[str, Any]) -> Any:
        self.calls.append(final)
        raise RuntimeError("tool blew up")

    def sync(self, final: dict[str, Any]) -> Any:
        self.calls.append(final)
        raise RuntimeError("tool blew up")


async def _drive(
    path: str,
    *,
    enforcer: Any,
    pipeline: ToolPipeline | None = None,
    invoke: Any = None,
    approval_handler: Any = None,
    tool: str = _TOOL,
) -> Any:
    """Run one guarded call through whichever runner ``path`` names."""
    invoke = invoke if invoke is not None else RecordingInvoke()
    if path == _ASYNC:
        return await run_guarded_async(
            tool,
            {"x": 1},
            enforcer=enforcer,
            pipeline=pipeline,
            approval_handler=approval_handler,
            invoke=invoke.aio,
            render_error=langchain_error,
        )
    return run_guarded_sync(
        tool,
        {"x": 1},
        enforcer=enforcer,
        pipeline=pipeline,
        approval_handler=approval_handler,
        invoke=invoke.sync,
        render_error=langchain_error,
    )


def _halting(outcome: DecisionOutcome, *, post: bool = False) -> ToolPipeline:
    halt = Halt(reason="guard says no", outcome=outcome)
    if post:
        return ToolPipeline(pre=[], post=[after_tool(lambda call, out: halt)])
    return ToolPipeline(pre=[before_tool(lambda call: halt)], post=[])


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------


@_BOTH
@pytest.mark.asyncio
async def test_allowed_call_counts_one_execution(path: str) -> None:
    with run_scope("a") as facts:
        await _drive(path, enforcer=FakeEnforcer())

    assert (facts.tool_calls, facts.errors, facts.denials, facts.approvals) == (
        1,
        0,
        0,
        0,
    )


@_BOTH
@pytest.mark.asyncio
async def test_tool_that_raises_counts_an_execution_and_an_error(path: str) -> None:
    """A failed call consumed budget just as a successful one did — the model
    can retry it, and an agent looping on a broken tool is exactly what
    ``run.errors < 5`` is for."""
    with run_scope("a") as facts:
        with pytest.raises(RuntimeError):
            await _drive(path, enforcer=FakeEnforcer(), invoke=_Raises())

    assert (facts.tool_calls, facts.errors) == (1, 1)


@_BOTH
@pytest.mark.asyncio
async def test_denied_call_consumes_no_tool_budget(path: str) -> None:
    with run_scope("a") as facts:
        await _drive(path, enforcer=FakeEnforcer(DecisionOutcome.DENY, "nope"))

    assert (facts.tool_calls, facts.denials, facts.approvals) == (0, 1, 0)


@_BOTH
@pytest.mark.asyncio
async def test_granted_approval_counts_the_gate_and_the_execution(path: str) -> None:
    with run_scope("a") as facts:
        await _drive(
            path,
            enforcer=FakeEnforcer(DecisionOutcome.NEEDS_APPROVAL),
            approval_handler=_APPROVE,
        )

    assert (facts.approvals, facts.tool_calls, facts.denials) == (1, 1, 0)


@_BOTH
@pytest.mark.asyncio
async def test_refused_approval_counts_the_gate_but_not_an_execution(
    path: str,
) -> None:
    """An approval never granted must not consume the cap — which is why the
    write site is the runner and not ``decide``."""
    with run_scope("a") as facts:
        await _drive(
            path,
            enforcer=FakeEnforcer(DecisionOutcome.NEEDS_APPROVAL),
            approval_handler=_REFUSE,
        )

    assert (facts.approvals, facts.tool_calls) == (1, 0)


@_BOTH
@pytest.mark.asyncio
async def test_pre_guard_halt_is_a_denial_not_a_tool_call(path: str) -> None:
    with run_scope("a") as facts:
        await _drive(
            path, enforcer=FakeEnforcer(), pipeline=_halting(DecisionOutcome.DENY)
        )

    assert (facts.denials, facts.tool_calls) == (1, 0)


@_BOTH
@pytest.mark.asyncio
async def test_granted_pre_guard_approval_halt_proceeds_and_counts_both(
    path: str,
) -> None:
    with run_scope("a") as facts:
        await _drive(
            path,
            enforcer=FakeEnforcer(),
            pipeline=_halting(DecisionOutcome.NEEDS_APPROVAL),
            approval_handler=_APPROVE,
        )

    assert (facts.approvals, facts.tool_calls, facts.denials) == (1, 1, 0)


@_BOTH
@pytest.mark.asyncio
async def test_post_guard_halt_still_counts_the_execution(path: str) -> None:
    """The tool ran; only the result is withheld. Un-counting it would let an
    agent spend an unbounded number of side effects behind a redacting guard."""
    with run_scope("a") as facts:
        await _drive(
            path,
            enforcer=FakeEnforcer(),
            pipeline=_halting(DecisionOutcome.DENY, post=True),
        )

    assert (facts.tool_calls, facts.denials) == (1, 1)


@_BOTH
@pytest.mark.asyncio
async def test_post_guard_halt_does_not_double_count_the_tool(path: str) -> None:
    """Guard against the obvious mis-wiring: recording the execution after the
    post-guards instead of around ``invoke`` would count a halted call twice
    and make a guarded pipeline burn budget at double rate."""
    with run_scope("a") as facts:
        await _drive(
            path,
            enforcer=FakeEnforcer(),
            pipeline=_halting(DecisionOutcome.DENY, post=True),
        )

    assert facts.tool_calls == 1
    assert facts._calls_by_tool == {_TOOL: 1}


# ---------------------------------------------------------------------------
# Per-tool counting and the projected namespace
# ---------------------------------------------------------------------------


@_BOTH
@pytest.mark.asyncio
async def test_calls_of_this_tool_is_per_tool_across_a_run(path: str) -> None:
    """``run.calls_of_this_tool < 5`` is the tool-name-free per-tool cap, so it
    must read the tool being decided, not the run total."""
    enforcer = FakeEnforcer()
    with run_scope("a") as facts:
        for _ in range(3):
            await _drive(path, enforcer=enforcer, tool=_TOOL)
        await _drive(path, enforcer=enforcer, tool=_OTHER_TOOL)

    assert facts.as_namespace(_TOOL)["calls_of_this_tool"] == 3
    assert facts.as_namespace(_OTHER_TOOL)["calls_of_this_tool"] == 1
    assert facts.as_namespace(_TOOL)["tool_calls"] == 4


@_BOTH
@pytest.mark.asyncio
async def test_tools_used_is_first_use_ordered_and_deduplicated(path: str) -> None:
    enforcer = FakeEnforcer()
    with run_scope("a") as facts:
        await _drive(path, enforcer=enforcer, tool=_OTHER_TOOL)
        await _drive(path, enforcer=enforcer, tool=_TOOL)
        await _drive(path, enforcer=enforcer, tool=_OTHER_TOOL)

    assert facts.as_namespace(_TOOL)["tools_used"] == [_OTHER_TOOL, _TOOL]


# ---------------------------------------------------------------------------
# The detached path
# ---------------------------------------------------------------------------


@_BOTH
@pytest.mark.asyncio
async def test_recording_outside_a_run_scope_is_a_no_op(path: str) -> None:
    """A boundary that was never wired must not brick the agent, and must not
    accumulate onto the process-wide detached record either."""
    from hexgate.runtime.run_facts import DETACHED

    before = DETACHED.tool_calls
    await _drive(path, enforcer=FakeEnforcer())
    assert DETACHED.tool_calls == before


# ---------------------------------------------------------------------------
# The overshoot bound
# ---------------------------------------------------------------------------

_CAP = 5
_CONCURRENCY = 8


@pytest.mark.asyncio
async def test_parallel_overshoot_is_bounded_by_concurrency() -> None:
    """A run cap is a circuit breaker, not a quota.

    Counting *after* execution means N concurrent calls all read the same
    pre-increment snapshot, so a cap of K permits up to ``K - 1 + N``
    executions. Inherent: making the decision atomic would need
    reserve-at-decide / release-on-deny, which breaks monotonicity and with it
    the latching property that makes the cap a circuit breaker at all.

    The bound is asserted, never an exact count — how many actually race is
    scheduler-dependent, and an exact assertion would flake.
    """
    import asyncio

    executed = 0

    class _CappingEnforcer:
        """Denies once the run has already executed ``_CAP`` calls."""

        agent_name = "a"

        def decide(self, tool_name: str, arguments: Any) -> Any:
            from hexgate.runtime.run_facts import get_run_facts
            from hexgate.security.decision import Decision, Verdict

            over = get_run_facts().as_namespace(tool_name)["tool_calls"] >= _CAP
            return Decision.from_verdict(
                Verdict(
                    outcome=DecisionOutcome.DENY if over else DecisionOutcome.ALLOW,
                    reason="cap",
                ),
                agent_name=self.agent_name,
                tool_name=tool_name,
            )

        def record(self, decision: Any, **kwargs: Any) -> None:
            pass

    class _CountingInvoke:
        async def aio(self, final: dict[str, Any]) -> Any:
            nonlocal executed
            await asyncio.sleep(0)  # yield, so the calls genuinely interleave
            executed += 1
            return "ok"

    enforcer, invoke = _CappingEnforcer(), _CountingInvoke()
    with run_scope("a"):
        await asyncio.gather(
            *(
                run_guarded_async(
                    _TOOL,
                    {},
                    enforcer=enforcer,
                    pipeline=None,
                    approval_handler=None,
                    invoke=invoke.aio,
                    render_error=langchain_error,
                )
                for _ in range(_CONCURRENCY)
            )
        )

    assert _CAP <= executed <= _CAP - 1 + _CONCURRENCY


@pytest.mark.asyncio
async def test_concurrent_runs_do_not_share_facts() -> None:
    """Two runs in one process, in parallel tasks: each sees only its own tool
    calls. Catches a contextvar leak, which would make one caller's budget
    bound another's."""
    import asyncio

    seen: list[RunFacts] = []

    async def one_run() -> None:
        with run_scope("a") as facts:
            enforcer = FakeEnforcer()
            await _drive(_ASYNC, enforcer=enforcer)
            await _drive(_ASYNC, enforcer=enforcer)
            seen.append(facts)

    await asyncio.gather(one_run(), one_run())

    first, second = seen
    assert first is not second
    assert first.id != second.id
    assert [first.tool_calls, second.tool_calls] == [2, 2]  # never 4
