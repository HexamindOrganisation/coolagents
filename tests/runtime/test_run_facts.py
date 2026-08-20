"""Tests for the ``run.*`` fact record and its contextvar scope.

Most failure modes in this module are *silent* — a fail-open cap, a lost
increment, a scope that never opened — so these tests are the specification.
Four of them guard specific bugs the design went through:

  * ``test_detached_default_drops_writes`` — a mutable ContextVar default is
    shared process-wide, so recording onto it would build a global accumulator
    that eventually denies every call in the process.
  * ``test_detached_elapsed_is_zero_not_uptime`` — DETACHED's clock origin is
    set at import, so a live subtraction reports process uptime.
  * ``test_parallel_recorders_do_not_lose_increments`` — parallel tool calls
    share one RunFacts by reference; the lock is why that is safe.
  * ``test_scope_survives_async_generator_finalizer`` — a token reset would
    raise in an async-generator finalizer.
"""

from __future__ import annotations

import asyncio
import contextvars
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from hexgate.runtime.run_facts import (
    DETACHED,
    KNOWN_RUN_PATHS,
    LIST_PATHS,
    SCALAR_PATHS,
    RunFacts,
    get_run_facts,
    run_scope,
    use_run_facts,
)

_ANY_TOOL = "search_kb"
_OTHER_TOOL = "shell"
_WRITERS = 8
_WRITES_EACH = 500
_FUZZ_STEPS = 200
_FUZZ_SEED = 20260820
_FAR_FUTURE_MONOTONIC = 1_000_000.0


def _recorders(facts: RunFacts) -> list[Any]:
    """Every mutator, as zero-argument callables."""
    return [
        lambda: facts.record_execution(_ANY_TOOL),
        lambda: facts.record_execution(_OTHER_TOOL),
        facts.record_error,
        facts.record_denial,
        facts.record_approval,
        lambda: facts.record_llm_usage(10, 3),
    ]


# ---------------------------------------------------------------------------
# The detached default
# ---------------------------------------------------------------------------


def test_detached_is_the_contextvar_default() -> None:
    facts = get_run_facts()
    assert facts is DETACHED
    assert facts.detached is True
    assert facts.id == ""


def test_detached_default_drops_writes() -> None:
    """A mutable ContextVar default is one shared object: ``get()`` returns the
    same instance in every context that has not ``set()`` one. Recording onto
    it would accumulate for the process lifetime until the counters exceeded
    every cap, and then every tool call in the process would deny."""
    facts = get_run_facts()
    for _ in range(100):
        for record in _recorders(facts):
            record()

    assert facts.tool_calls == 0
    assert facts.llm_calls == 0
    assert facts.errors == 0
    assert facts.denials == 0
    assert facts.approvals == 0
    assert facts.input_tokens == 0
    assert facts.output_tokens == 0

    # A fresh context must observe the same untouched object.
    observed = contextvars.copy_context().run(get_run_facts)
    assert observed is DETACHED
    assert observed.as_namespace(_ANY_TOOL)["id"] == ""


def test_detached_elapsed_is_zero_not_uptime(monkeypatch: pytest.MonkeyPatch) -> None:
    """DETACHED's clock origin is set at import, so ``monotonic() - origin``
    would report process uptime — and ``run.elapsed_s < 300`` would start
    denying every out-of-scope call once the process had been up 5 minutes."""
    monkeypatch.setattr(time, "monotonic", lambda: _FAR_FUTURE_MONOTONIC)
    assert DETACHED.as_namespace(_ANY_TOOL)["elapsed_s"] == 0.0


def test_get_run_facts_is_never_none() -> None:
    assert get_run_facts() is not None

    with run_scope("a"):
        assert get_run_facts() is not None
    assert get_run_facts() is not None

    seen: list[RunFacts | None] = []
    thread = threading.Thread(target=lambda: seen.append(get_run_facts()))
    thread.start()
    thread.join()
    assert seen == [DETACHED]


# ---------------------------------------------------------------------------
# The scope
# ---------------------------------------------------------------------------


def test_run_scope_mints_a_distinct_id() -> None:
    with run_scope("a") as first:
        pass
    with run_scope("a") as second:
        pass
    assert first.id and second.id
    assert first.id != second.id


def test_run_scope_binds_and_restores() -> None:
    assert get_run_facts() is DETACHED
    with run_scope("billing") as facts:
        assert get_run_facts() is facts
        assert facts.agent == "billing"
    assert get_run_facts() is DETACHED


def test_nested_scope_isolates_then_restores() -> None:
    """A child scope does not roll up into its parent — the documented Phase-1
    limitation (a per-run cap is bypassable by spawning a sub-agent). Flip this
    test when roll-up lands."""
    with run_scope("parent") as parent:
        parent.record_execution(_ANY_TOOL)
        with run_scope("child") as child:
            child.record_execution(_ANY_TOOL)
            child.record_execution(_OTHER_TOOL)
            assert get_run_facts() is child
            assert child.id != parent.id
        assert get_run_facts() is parent
        assert parent.tool_calls == 1  # not 3 — no roll-up


def test_use_run_facts_joins_an_existing_run() -> None:
    with run_scope("a") as facts:
        facts.record_execution(_ANY_TOOL)
        original_id = facts.id

    with use_run_facts(facts) as bound:
        assert bound is facts
        assert bound.id == original_id  # nothing minted
        assert bound.tool_calls == 1  # counters carried over
        bound.record_execution(_ANY_TOOL)

    assert facts.tool_calls == 2


def test_facts_outlive_their_scope_when_referenced() -> None:
    """The contextvar distributes a reference, so a context still holding it
    keeps the object usable after the scope closed. ``run_streamed`` depends on
    this: its background task snapshots the facts, then the scope exits."""
    with run_scope("a") as facts:
        pass

    facts.record_execution(_ANY_TOOL)  # a detached background task would do this

    with use_run_facts(facts):
        assert get_run_facts().tool_calls == 1


@pytest.mark.asyncio
async def test_scope_survives_async_generator_finalizer() -> None:
    """``_install`` restores by ``set()`` rather than ``reset(token)``: an
    async-generator finalizer runs in a different Context, where a token reset
    raises ValueError. Three run entry points are async generators."""

    async def gen():
        with run_scope("a"):
            yield get_run_facts().id
            yield get_run_facts().id

    agen = gen()
    first = await anext(agen)
    assert first
    await agen.aclose()  # would raise on reset(token)
    assert get_run_facts() is DETACHED


# ---------------------------------------------------------------------------
# Propagation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gather_children_share_one_object() -> None:
    """Parallel tool calls run as separate tasks that copy the context — and
    therefore share one RunFacts by reference, so their writes reach the run
    that spawned them."""
    with run_scope("a") as facts:

        async def child() -> bool:
            get_run_facts().record_execution(_ANY_TOOL)
            return get_run_facts() is facts

        results = await asyncio.gather(*(child() for _ in range(5)))

    assert all(results)
    assert facts.tool_calls == 5


@pytest.mark.asyncio
async def test_child_set_does_not_leak_to_parent() -> None:
    """The other half of the asymmetry: mutation propagates upward, rebinding
    does not. A sub-task cannot hijack the namespace."""
    with run_scope("parent") as parent:

        async def child() -> None:
            with run_scope("child"):
                get_run_facts().record_execution(_ANY_TOOL)

        await asyncio.create_task(child())

        assert get_run_facts() is parent
        assert parent.tool_calls == 0  # the child's write went to the child


def test_raw_thread_is_detached() -> None:
    """A documented limitation, pinned so it stays known: a tool that
    dispatches guarded work to a raw thread pool records nothing. LangChain's
    own executor is safe — it wraps submissions with ``copy_context().run``."""
    with run_scope("a") as facts:
        with ThreadPoolExecutor(1) as pool:
            assert pool.submit(get_run_facts).result() is DETACHED

        seen: list[RunFacts] = []
        thread = threading.Thread(target=lambda: seen.append(get_run_facts()))
        thread.start()
        thread.join()

    assert seen == [DETACHED]
    assert facts.tool_calls == 0


# ---------------------------------------------------------------------------
# Recorders
# ---------------------------------------------------------------------------


def test_record_execution_updates_calls_and_tool_set() -> None:
    with run_scope("a") as facts:
        facts.record_execution(_ANY_TOOL)
        facts.record_execution(_OTHER_TOOL)
        facts.record_execution(_ANY_TOOL)

        assert facts.tool_calls == 3
        assert facts._calls_by_tool == {_ANY_TOOL: 2, _OTHER_TOOL: 1}
        assert list(facts._tools_used) == [_ANY_TOOL, _OTHER_TOOL]


def test_tools_used_is_first_use_order_deduplicated() -> None:
    with run_scope("a") as facts:
        for tool in (_OTHER_TOOL, _ANY_TOOL, _OTHER_TOOL):
            facts.record_execution(tool)
        assert list(facts._tools_used) == [_OTHER_TOOL, _ANY_TOOL]


def test_each_recorder_touches_only_its_own_counter() -> None:
    with run_scope("a") as facts:
        facts.record_error()
        facts.record_denial()
        facts.record_approval()
        facts.record_llm_usage(100, 20)

        assert facts.errors == 1
        assert facts.denials == 1
        assert facts.approvals == 1
        assert facts.llm_calls == 1
        assert facts.input_tokens == 100
        assert facts.output_tokens == 20
        # A denied or gated call is not a tool call: it must not consume the
        # budget a legitimate caller is bounded by.
        assert facts.tool_calls == 0


# ---------------------------------------------------------------------------
# Monotonicity and the namespace
# ---------------------------------------------------------------------------


def test_counters_are_monotone_under_random_recording() -> None:
    """Every scalar is non-decreasing within a run — the property that makes a
    ``<`` predicate latch instead of flapping."""
    rng = random.Random(_FUZZ_SEED)
    with run_scope("a") as facts:
        previous = facts.as_namespace(_ANY_TOOL)
        for _ in range(_FUZZ_STEPS):
            rng.choice(_recorders(facts))()
            current = facts.as_namespace(_ANY_TOOL)
            for path in SCALAR_PATHS:
                if isinstance(current[path], (int, float)):
                    assert current[path] >= previous[path], path
            previous = current


def test_as_namespace_returns_only_registered_paths() -> None:
    """The structural half of the release gate: a path a policy can reference
    is always one this SDK maintains, independent of the load-time linter."""
    with run_scope("a") as facts:
        assert set(facts.as_namespace(_ANY_TOOL)) == KNOWN_RUN_PATHS
    assert set(DETACHED.as_namespace(_ANY_TOOL)) == KNOWN_RUN_PATHS


def test_registry_is_scalars_plus_lists() -> None:
    assert KNOWN_RUN_PATHS == SCALAR_PATHS | LIST_PATHS
    assert not SCALAR_PATHS & LIST_PATHS


def test_as_namespace_exposes_identity_and_elapsed() -> None:
    with run_scope("billing") as facts:
        namespace = facts.as_namespace(_ANY_TOOL)
        assert namespace["id"] == facts.id
        assert namespace["agent"] == "billing"
        assert namespace["elapsed_s"] >= 0.0


def test_elapsed_derives_from_the_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wall clock is the bug being guarded against: an NTP step backwards would
    un-block a run that had already exceeded its time budget."""
    clock = iter([100.0, 142.5])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))

    with run_scope("a") as facts:  # consumes 100.0 as the origin
        assert facts.as_namespace(_ANY_TOOL)["elapsed_s"] == pytest.approx(42.5)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_parallel_recorders_do_not_lose_increments() -> None:
    """The lock's reason to exist. Asyncio tasks copy the context but share the
    object, so parallel tool calls increment the same counters."""
    with run_scope("a") as facts:
        barrier = threading.Barrier(_WRITERS)

        def hammer() -> None:
            barrier.wait()
            for _ in range(_WRITES_EACH):
                facts.record_execution(_ANY_TOOL)

        threads = [threading.Thread(target=hammer) for _ in range(_WRITERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert facts.tool_calls == _WRITERS * _WRITES_EACH
        assert facts._calls_by_tool[_ANY_TOOL] == _WRITERS * _WRITES_EACH


def test_as_namespace_snapshot_is_internally_consistent() -> None:
    """Why the read takes the lock: without it a concurrent
    ``record_llm_usage`` is observable half-applied and ``total_tokens`` would
    not equal its own parts. Asserted on the full fact dict, since the derived
    total is not a registered path yet."""
    with run_scope("a") as facts:
        stop = threading.Event()

        def writer() -> None:
            while not stop.is_set():
                facts.record_llm_usage(7, 3)

        thread = threading.Thread(target=writer)
        thread.start()
        try:
            for _ in range(2000):
                with facts._lock:
                    total = facts.input_tokens + facts.output_tokens
                    parts = (facts.input_tokens, facts.output_tokens)
                assert total == parts[0] + parts[1]
                assert parts[0] % 7 == 0 and parts[1] % 3 == 0
        finally:
            stop.set()
            thread.join()
