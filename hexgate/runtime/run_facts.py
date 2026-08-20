"""Per-invocation fact record — the ``run.*`` policy namespace.

``run.*`` is a fact family alongside the call-scope facts ``role`` / ``tool``
(:mod:`hexgate.security.constraints`), the signed ``biscuit_facts``
(:mod:`hexgate.cloud.biscuit`), and the advisory ``ctx.*`` bag
(:attr:`~hexgate.runtime.context.HexgateContext.attributes`). It is the only
one that is local *and* exact: the SDK accumulates it in-process, so it can
never be unavailable and never needs a fail-soft path.

It records only what has happened — no limits, no thresholds, no pricing.
Those live in ``policy_yaml`` and on the platform, which is what keeps
``PolicyEngine.evaluate`` a pure predicate over its inputs.

Every counter is monotone non-decreasing within a run, and elapsed comes off a
monotonic clock. A ``<`` predicate over a non-decreasing value therefore
*latches* — once a cap denies it keeps denying, which is what makes it a
circuit breaker rather than a flapping gate.

The contextvar distributes a *reference*, not a value. Sub-tasks that copy the
context share one :class:`RunFacts`, so their writes reach the run that
spawned them, while a ``set()`` inside a sub-task cannot rebind the parent's.
Consequences, including the paths that do *not* propagate (raw threads, tasks
created outside the scope), are in
``plans/run-state/run-facts-phase1-implementation.md`` §0.4.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Final
from uuid import uuid4

# Every ``run.*`` path a policy may reference. One source of truth, shared by
# :meth:`RunFacts.as_namespace` — which returns exactly these — and, from the
# next change, the load-time linter that rejects anything else.
#
# A path is registered in the same change that starts *projecting* it, never
# earlier. A registered path with no value behind it resolves to a permanent
# zero, and ``run.tool_calls < 20`` against a permanent zero never fires: a
# silently fail-open cap, shipped as a working feature. So the counters this
# record already accumulates are deliberately absent below; each joins the
# registry and the projection together, in the change that wires its writer.
KNOWN_RUN_PATHS: Final[frozenset[str]] = frozenset({"id", "agent", "elapsed_seconds"})


@dataclass(slots=True)
class RunFacts:
    """Mutable accumulator for one agent invocation.

    Monotone by discipline, not by construction: the ``record_*`` methods are
    the only monotone-preserving way in, and assigning a field directly
    bypasses both the lock and the detached guard. Read through
    :meth:`as_namespace`.

    Not single-writer. Parallel tool calls run as separate asyncio tasks that
    copy the context and therefore share one instance by reference, so several
    writers are expected — that is what ``_lock`` is for.
    """

    id: str
    agent: str
    # True only for DETACHED, where every mutator returns early. See DETACHED.
    detached: bool = False
    # Origin for ``elapsed_seconds``. Monotonic, not wall clock: an NTP step
    # backwards would un-block a run that had already exceeded its time
    # budget. Private and never a ``run.*`` path — only the derived elapsed is
    # exposed, so there is no second time field to keep consistent.
    #
    # Wrapped in a lambda rather than passed as ``default_factory=
    # time.monotonic``: the bare reference binds this function object at class
    # definition, while :meth:`as_namespace` resolves ``time.monotonic`` at
    # call time. The origin and the elapsed would then read different clocks
    # whenever one is substituted, yielding a negative elapsed.
    #
    # Deliberately still an ``__init__`` parameter, unlike the internals below:
    # it is the seam a caller substitutes to control the clock, so only the
    # default is hard-wired.
    _started_monotonic: float = field(default_factory=lambda: time.monotonic())

    tool_calls: int = 0
    llm_calls: int = 0
    denials: int = 0
    approvals: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    # Per-tool call counts, which also give the first-use-ordered set of tools
    # used: a dict preserves insertion order and an update to an existing key
    # does not reorder it, so ``list(_calls_by_tool)`` is that set. Private
    # because its keys are tool names, which may not be legal policy-path
    # identifiers (MCP tool names are hyphenated), so exposing
    # ``run.calls_by_tool.<name>`` needs a sanitisation scheme first.
    #
    # ``init=False`` here and on the lock: neither has a legitimate
    # caller-supplied value, and a dataclass would otherwise expose them as
    # constructor parameters — injectable by accident, which is worse than not
    # being injectable. It keeps ``__init__`` a designed surface: identity, the
    # detached flag, the clock origin, and the counters.
    _calls_by_tool: dict[str, int] = field(default_factory=dict, init=False)
    # threading.Lock, not asyncio.Lock: the mutators are called from sync paths
    # (``run_guarded_sync``, LangChain's sync callback handler) as well as
    # async ones, and every critical section is a few integer increments.
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def record_execution(self, tool_name: str) -> None:
        """Count one tool call that actually executed.

        Called after the tool returns *or* raises — a failed call consumed
        budget just as a successful one did.
        """
        if self.detached:
            return
        with self._lock:
            self.tool_calls += 1
            self._calls_by_tool[tool_name] = self._calls_by_tool.get(tool_name, 0) + 1

    def record_error(self) -> None:
        """Count one tool that raised."""
        if self.detached:
            return
        with self._lock:
            self.errors += 1

    def record_denial(self) -> None:
        """Count one refused call.

        Deliberately not a ``tool_calls``: a denied call must not consume the
        budget a legitimate caller is bounded by.
        """
        if self.detached:
            return
        with self._lock:
            self.denials += 1

    def record_approval(self) -> None:
        """Count one call gated on human approval.

        Counted on the *decision*; whether it then executes is counted
        separately by :meth:`record_execution`, so an approval never granted
        consumes no tool budget.
        """
        if self.detached:
            return
        with self._lock:
            self.approvals += 1

    def record_llm_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Count one model request and its tokens.

        ``input_tokens`` includes cached tokens, matching OpenTelemetry's
        billed-count rule.
        """
        if self.detached:
            return
        with self._lock:
            self.llm_calls += 1
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens

    def as_namespace(self) -> dict[str, Any]:
        """Build the ``run`` mapping the policy grammar evaluates against.

        Its keys are exactly :data:`KNOWN_RUN_PATHS`, so a policy can only
        reference something this record actually projects — never a permanent
        zero. ``test_as_namespace_returns_only_registered_paths`` keeps the two
        in step.

        Read under the lock, even though none of the three values below can be
        touched by a recorder and the lock is therefore inert today. The next
        change projects the counters, and a reader that already holds the lock
        cannot forget to acquire it: the grammar permits cross-field
        comparison (``run.a < run.b`` parses), so an unsynchronised read could
        evaluate a pair of counters that never coexisted.
        """
        with self._lock:
            return {
                "id": self.id,
                "agent": self.agent,
                # Derived, not stored: the grammar has no time functions.
                # Zero when detached rather than process uptime — DETACHED's
                # origin is set at import, so a live subtraction would make
                # ``run.elapsed_seconds < 300`` deny every out-of-scope call once
                # the process had been up five minutes.
                "elapsed_seconds": (
                    0.0 if self.detached else time.monotonic() - self._started_monotonic
                ),
            }


# The ContextVar default, and therefore shared process-wide: ``get()`` hands
# back this same instance in every context that has not ``set()`` one. That is
# safe only because every mutator is a no-op on it. A plain zeroed instance
# here would be a global accumulator that never resets — counters would climb
# for the process lifetime until they exceeded every cap, and then every tool
# call in the process would deny.
#
# Reading zeros outside a run scope is the deliberate choice: it fails *open*
# on counters, which is right for a boundary that was never wired, versus
# bricking an agent. ``run.id == ""`` is the signal that a decision happened
# outside a run.
DETACHED: Final[RunFacts] = RunFacts(id="", agent="", detached=True)

_CURRENT_RUN_FACTS: ContextVar[RunFacts] = ContextVar(
    "hexgate_run_facts",
    default=DETACHED,
)


def get_run_facts() -> RunFacts:
    """Return the active run's facts, or :data:`DETACHED` outside a run scope.

    Never ``None``. An absent ``run`` namespace makes every ``run.*``
    constraint fail closed, so a tool call decided outside a run scope — a
    unit test, a direct ``decide()``, an unwired entry point — would deny
    everything, with an error message naming a constraint rather than the real
    cause.
    """
    return _CURRENT_RUN_FACTS.get()


@contextmanager
def use_run_facts(facts: RunFacts) -> Iterator[RunFacts]:
    """Bind ``facts`` for the duration of the block, minting nothing.

    The primitive :func:`run_scope` is built from. Call it directly to join a
    run already in flight: ``Runner.run_streamed`` (OpenAI Agents) spawns the
    agent loop as a background task that snapshots the contextvars at creation
    and then returns, so the consumer-side iterator has to re-bind the same
    object — minting there would split one invocation across two runs.

    Saves and restores by ``set()`` rather than ``reset(token)``, matching
    :class:`~hexgate.runtime.context.HexgateContext`: async-generator
    finalizers run ``__aexit__`` in a different ``Context``, where a token
    reset raises. Three run entry points are async generators, so this is
    load-bearing rather than defensive.
    """
    saved = _CURRENT_RUN_FACTS.get()
    _CURRENT_RUN_FACTS.set(facts)
    try:
        yield facts
    finally:
        _CURRENT_RUN_FACTS.set(saved)


@contextmanager
def run_scope(agent: str) -> Iterator[RunFacts]:
    """Open a new run — mint a :class:`RunFacts` and bind it.

    One scope per agent invocation. Open it at the adapter run boundary, after
    the policy refresh and the ban check (a refused invocation is not a run),
    and *not* in ``HexgateContext.__aenter__``: that scope is request-shaped
    and may wrap several invocations.
    """
    with use_run_facts(RunFacts(id=str(uuid4()), agent=agent)) as facts:
        yield facts
