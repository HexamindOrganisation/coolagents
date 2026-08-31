"""Per-invocation facts — the ``run.*`` policy namespace.

A fourth fact family beside ``role`` / ``tool``, the signed ``biscuit_facts`` and
the advisory ``ctx.*`` bag, and the only one local and exact. Records what happened,
never limits: those stay in ``policy_yaml``, keeping ``PolicyEngine.evaluate`` a
pure predicate.

Counters are monotone, so a ``<`` predicate latches once a cap trips. The contextvar
holds a *reference*: sub-tasks sharing the context reach the parent run's record but
cannot rebind it.
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

# Every ``run.*`` path a policy may reference; :meth:`RunFacts.as_namespace` returns
# exactly these and the load-time linter rejects anything else. Register a path only
# once something projects it: a registered path with no value reads a permanent zero,
# and ``run.tool_calls < 20`` against zero never fires — a fail-open cap that looks
# like it works.
#
# Split by value shape because the linter must tell them apart: a list-valued path is
# fine inside ``count()`` / ``any()`` / ``every()`` and right of ``in``, but as the
# *left* operand of an ordered or membership operator it silently always passes.
SCALAR_PATHS: Final[frozenset[str]] = frozenset(
    {
        "id",
        "agent",
        "elapsed_seconds",
        "tool_calls",
        "calls_of_this_tool",
        "denials",
        "approvals",
        "errors",
        "llm_calls",
        "input_tokens",
        "output_tokens",
        "total_tokens",
    }
)
LIST_PATHS: Final[frozenset[str]] = frozenset({"tools_used"})
KNOWN_RUN_PATHS: Final[frozenset[str]] = SCALAR_PATHS | LIST_PATHS

# Fallback when a wrapped agent has no name. Lives here, below both callers, so a
# nameless agent's audit events and its run facts agree on the label rather than
# drifting apart — and so core (``agents.factory``) need not import the adapter layer.
DEFAULT_AGENT_NAME: Final[str] = "default"


@dataclass(slots=True)
class RunFacts:
    """Mutable accumulator for one agent invocation.

    Monotone by discipline: the ``record_*`` methods are the only safe way in, since
    assigning a field bypasses both the lock and the detached guard. Several writers
    are expected — parallel tool calls share one instance by reference.
    """

    id: str
    agent: str
    # True only for DETACHED, whose mutators all no-op.
    detached: bool = False
    # Monotonic, not wall clock: an NTP step backwards would un-block a run that had
    # already exceeded its budget. The lambda matters — a bare ``time.monotonic``
    # reference binds at class definition while :meth:`as_namespace` resolves it at
    # call time, so a substituted clock would yield a negative elapsed.
    _started_monotonic: float = field(default_factory=lambda: time.monotonic())

    tool_calls: int = 0
    llm_calls: int = 0
    denials: int = 0
    approvals: int = 0
    errors: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    # Doubles as the first-use-ordered tool set (``list(...)``): dict preserves
    # insertion order and re-keying does not reorder. Private — tool names are not
    # always legal path identifiers, so ``run.calls_by_tool.<name>`` needs escaping.
    # ``init=False`` here and on the lock: internals, not caller-supplied.
    _calls_by_tool: dict[str, int] = field(default_factory=dict, init=False)
    # threading, not asyncio: the mutators run on sync paths too.
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def record_execution(self, tool_name: str) -> None:
        """Count one executed tool call, whether it returned or raised."""
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
        """Count one refused call. Deliberately not a ``tool_calls`` — a denial must
        not consume a legitimate caller's budget."""
        if self.detached:
            return
        with self._lock:
            self.denials += 1

    def record_approval(self) -> None:
        """Count one call gated on approval. Execution is counted separately, so an
        approval never granted consumes no budget."""
        if self.detached:
            return
        with self._lock:
            self.approvals += 1

    def record_llm_usage(self, input_tokens: int, output_tokens: int) -> None:
        """Count one model request. ``input_tokens`` includes cached tokens, matching
        OpenTelemetry's billed-count rule."""
        if self.detached:
            return
        with self._lock:
            self.llm_calls += 1
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens

    def as_namespace(self, tool_name: str) -> dict[str, Any]:
        """The ``run`` mapping the policy grammar evaluates for a decision on
        ``tool_name``; its keys are exactly :data:`KNOWN_RUN_PATHS`.

        ``calls_of_this_tool`` is a per-decision view of the per-tool map, so it is
        the one value here that is not monotone across a run.

        Locked because the grammar allows cross-field comparison (``run.a < run.b``),
        so an unsynchronised read could pair counters that never coexisted.
        """
        with self._lock:
            return {
                "id": self.id,
                "agent": self.agent,
                "tool_calls": self.tool_calls,
                "calls_of_this_tool": self._calls_by_tool.get(tool_name, 0),
                "denials": self.denials,
                "approvals": self.approvals,
                "errors": self.errors,
                "llm_calls": self.llm_calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                # Derived: the grammar has no arithmetic.
                "total_tokens": self.input_tokens + self.output_tokens,
                # Re-keying a dict does not reorder it, so the keys already are the
                # first-use-ordered deduplicated tool set.
                "tools_used": list(self._calls_by_tool),
                # Derived: the grammar has no time functions. Zero when detached, not
                # process uptime — DETACHED's origin is set at import.
                "elapsed_seconds": (
                    0.0 if self.detached else time.monotonic() - self._started_monotonic
                ),
            }


# The ContextVar default, so one shared instance process-wide — safe only because
# every mutator no-ops on it. A plain zeroed record here would accumulate for the
# process lifetime until it tripped every cap. Reading zeros outside a run fails
# *open*, which is right for a boundary that was never wired; ``id == ""`` marks it.
DETACHED: Final[RunFacts] = RunFacts(id="", agent="", detached=True)

_CURRENT_RUN_FACTS: ContextVar[RunFacts] = ContextVar(
    "hexgate_run_facts",
    default=DETACHED,
)


def get_run_facts() -> RunFacts:
    """The active run's facts, or :data:`DETACHED` outside a run scope.

    Never ``None`` — were it, the ``run`` namespace would be absent, and a missing
    ref fails every comparison closed, so an unwired boundary would deny everything
    for the wrong reason. :data:`DETACHED` reads as zeros instead: a projected path
    (``elapsed_seconds``) then fails open, an unprojected one is still a missing ref.
    """
    return _CURRENT_RUN_FACTS.get()


@contextmanager
def use_run_facts(facts: RunFacts) -> Iterator[RunFacts]:
    """Bind ``facts`` without minting — the primitive :func:`run_scope` builds on.

    Call it directly to join a run in flight: ``Runner.run_streamed`` snapshots the
    contextvars into a background task and returns, so the consumer-side iterator
    must re-bind that object rather than start a second run.

    Restores by ``set()``, not ``reset(token)``: async-generator finalizers run in a
    different ``Context``, where a token reset raises.
    """
    saved = _CURRENT_RUN_FACTS.get()
    _CURRENT_RUN_FACTS.set(facts)
    try:
        yield facts
    finally:
        _CURRENT_RUN_FACTS.set(saved)


@contextmanager
def run_scope(agent: str) -> Iterator[RunFacts]:
    """Mint a :class:`RunFacts` and bind it — one scope per agent invocation.

    Belongs at the adapter run boundary, after the ban check (a refused invocation is
    not a run) and not in ``HexgateContext.__aenter__``, which may wrap several.
    """
    with use_run_facts(RunFacts(id=str(uuid4()), agent=agent)) as facts:
        yield facts
