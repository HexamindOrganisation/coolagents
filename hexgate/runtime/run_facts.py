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

Every field is monotone non-decreasing within a run: counters only increment,
the tool set only grows, elapsed comes off a monotonic clock. A ``<``
predicate over a non-decreasing value therefore *latches* — once a cap
denies it keeps denying, which is what makes it a circuit breaker rather than
a flapping gate.

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

# The single source of truth for what ``run.*`` exposes to a policy. Drives
# :meth:`RunFacts.as_namespace` and, from the next change, the load-time
# linter — so a path cannot be readable-but-unlintable or lintable-but-absent.
#
# A path is added here in the same change that makes it truthful, never
# earlier. A registered path with no writer reads a permanent zero, and
# ``run.tool_calls < 20`` against a permanent zero never fires: a silently
# fail-open cap, shipped as a working feature. The counters below are computed
# by ``as_namespace`` already but stay unregistered until their write sites
# land, so the only edit needed then is to this tuple.
SCALAR_PATHS: Final[frozenset[str]] = frozenset({"id", "agent", "elapsed_s"})
LIST_PATHS: Final[frozenset[str]] = frozenset()
KNOWN_RUN_PATHS: Final[frozenset[str]] = SCALAR_PATHS | LIST_PATHS


@dataclass(slots=True)
class RunFacts:
    """Mutable, single-writer accumulator for one agent invocation.

    Read through :meth:`as_namespace`; mutate only through the ``record_*``
    methods. Assigning a counter directly bypasses the lock.
    """

    id: str
    agent: str
    # True only for DETACHED, where every mutator returns early. See DETACHED.
    detached: bool = False
    # Origin for ``elapsed_s``. Monotonic, not wall clock: an NTP step
    # backwards would un-block a run that had already exceeded its time
    # budget. Private and never a ``run.*`` path — only the derived elapsed is
    # exposed, so there is no second time field to keep consistent.
    #
    # Wrapped in a lambda rather than passed as ``default_factory=
    # time.monotonic``: the bare reference binds this function object at class
    # definition, while ``as_namespace`` resolves ``time.monotonic`` at call
    # time. The origin and the elapsed would then read different clocks
    # whenever one is substituted, yielding a negative elapsed.
    _started_monotonic: float = field(default_factory=lambda: time.monotonic())

    tool_calls: int = 0
    llm_calls: int = 0
    denials: int = 0
    approvals: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    # Backs ``calls_of_this_tool``. Private: its keys are tool names, which may
    # not be legal policy-path identifiers (MCP tool names are hyphenated), so
    # exposing ``run.calls_by_tool.<name>`` needs a sanitisation scheme first.
    _calls_by_tool: dict[str, int] = field(default_factory=dict)
    # First-use-ordered set. A dict rather than a set because "first-use order"
    # is the documented semantic for ``run.tools_used``.
    _tools_used: dict[str, None] = field(default_factory=dict)
    # threading.Lock, not asyncio.Lock: the mutators are called from sync paths
    # (``run_guarded_sync``, LangChain's sync callback handler) as well as
    # async ones, and every critical section is a few integer increments.
    # Parallel tool calls run as separate asyncio tasks that copy the context
    # and therefore share this object by reference — which is why a lock is
    # needed at all.
    _lock: threading.Lock = field(default_factory=threading.Lock)

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
            self._tools_used.setdefault(tool_name)

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

    def as_namespace(self, tool_name: str) -> dict[str, Any]:
        """Build the ``run`` mapping the policy grammar evaluates against.

        ``tool_name`` is the tool being decided: ``calls_of_this_tool`` is a
        per-decision view of the private per-tool map, not a counter, so it is
        the one value here that is not monotone across a run.

        Only paths in :data:`KNOWN_RUN_PATHS` are returned, so a path a policy
        can reference is always one this SDK maintains. That makes the filter
        and the load-time linter two independent guards against a cap reading
        a permanently-zero field.

        Takes the lock for the read: without it a concurrent
        :meth:`record_llm_usage` could be observed half-applied, and
        ``total_tokens`` would not equal its own parts.
        """
        with self._lock:
            facts: dict[str, Any] = {
                "id": self.id,
                "agent": self.agent,
                "tool_calls": self.tool_calls,
                "calls_of_this_tool": self._calls_by_tool.get(tool_name, 0),
                "llm_calls": self.llm_calls,
                "denials": self.denials,
                "approvals": self.approvals,
                "errors": self.errors,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                # Derived, never stored: the grammar has no arithmetic, so a
                # policy cannot sum the parts itself.
                "total_tokens": self.input_tokens + self.output_tokens,
                # Zero when detached, not process uptime: DETACHED's origin is
                # set at import, so a live subtraction would make
                # ``run.elapsed_s < 300`` start denying every out-of-scope
                # call once the process had been up five minutes.
                "elapsed_s": (
                    0.0 if self.detached else time.monotonic() - self._started_monotonic
                ),
                "tools_used": list(self._tools_used),
            }
        return {path: value for path, value in facts.items() if path in KNOWN_RUN_PATHS}


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
def _install(facts: RunFacts) -> Iterator[RunFacts]:
    """Bind ``facts`` for the duration of the block.

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
    with _install(RunFacts(id=str(uuid4()), agent=agent)) as facts:
        yield facts


@contextmanager
def use_run_facts(facts: RunFacts) -> Iterator[RunFacts]:
    """Join a run already in flight — bind ``facts``, minting nothing.

    For a context that must see an existing run rather than start one.
    ``Runner.run_streamed`` (OpenAI Agents) spawns the agent loop as a
    background task that snapshots the contextvars at creation and then
    returns, so the consumer-side iterator has to re-bind the same object;
    minting there would split one invocation's facts across two runs.
    """
    with _install(facts) as bound:
        yield bound
