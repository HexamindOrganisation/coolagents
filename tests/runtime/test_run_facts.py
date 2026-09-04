"""Tests for the ``run.*`` fact record and its contextvar scope.

Every failure mode here is *silent* — a fail-open cap, a lost increment, a scope
that never opened — so these tests are the specification.
"""

from __future__ import annotations

import asyncio
import contextvars
import copy
import dataclasses
import inspect
import random
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
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
_RECORDER_PREFIX = "record_"
_DETACHED_GUARD = "if self.detached:"
_AN_INT = 1
# Not counters, so out of scope for _mutable_state.
_NOT_MUTABLE_STATE = frozenset(
    {"id", "agent", "detached", "_started_monotonic", "_lock"}
)


def _recorder_names() -> list[str]:
    """Every ``record_*`` method, discovered so a new one cannot be added without
    the detached guard and go unnoticed."""
    return sorted(name for name in dir(RunFacts) if name.startswith(_RECORDER_PREFIX))


def _invoke(recorder: Callable[..., None]) -> None:
    """Call a recorder with an argument per parameter, inferred from its
    signature, so a new recorder needs no test-side wiring."""
    arguments = [
        _ANY_TOOL if parameter.annotation in (str, "str") else _AN_INT
        for parameter in inspect.signature(recorder).parameters.values()
    ]
    recorder(*arguments)


def _recorders(facts: RunFacts) -> list[Callable[[], None]]:
    """Every mutator as a zero-argument callable, plus a second
    ``record_execution`` on another tool so the per-tool map is exercised."""
    discovered: list[Callable[[], None]] = [
        partial(_invoke, getattr(facts, name)) for name in _recorder_names()
    ]
    return [*discovered, lambda: facts.record_execution(_OTHER_TOOL)]


def _mutable_state(facts: RunFacts) -> dict[str, Any]:
    """Every field a recorder could touch, discovered from the dataclass so a new
    counter is covered without editing this helper."""
    return {
        f.name: copy.deepcopy(getattr(facts, f.name))
        for f in dataclasses.fields(facts)
        if f.name not in _NOT_MUTABLE_STATE
    }


# ---------------------------------------------------------------------------
# The detached default
# ---------------------------------------------------------------------------


def test_detached_is_the_contextvar_default() -> None:
    facts = get_run_facts()
    assert facts is DETACHED
    assert facts.detached is True
    assert facts.id == ""


def test_detached_default_drops_writes() -> None:
    """A ContextVar default is one shared object, so recording onto it would
    accumulate process-wide until it tripped every cap."""
    facts = get_run_facts()
    before = _mutable_state(facts)

    for _ in range(100):
        for record in _recorders(facts):
            record()

    assert _mutable_state(facts) == before

    # A fresh context must observe the same untouched object.
    observed = contextvars.copy_context().run(get_run_facts)
    assert observed is DETACHED
    assert observed.as_namespace(_ANY_TOOL)["id"] == ""


def test_every_recorder_has_the_detached_guard() -> None:
    """Structural half of the test above: each recorder must be *written* to
    return early, so one mutating something off-dataclass still fails."""
    unguarded = [
        name
        for name in _recorder_names()
        if _DETACHED_GUARD not in inspect.getsource(getattr(RunFacts, name))
    ]
    assert not unguarded, (
        f"{unguarded} lack the detached guard: they would accumulate on the "
        "process-wide DETACHED singleton, which never resets, until the "
        "counters exceeded every cap and the process denied every tool call."
    )


def test_recorder_discovery_is_not_vacuous() -> None:
    """Guards the guard: a typo in the prefix would pass by iterating nothing."""
    assert len(_recorder_names()) >= 5


def test_detached_elapsed_is_zero_not_uptime(monkeypatch: pytest.MonkeyPatch) -> None:
    """DETACHED's origin is set at import, so a live subtraction would report
    process uptime and eventually deny every out-of-scope call."""
    monkeypatch.setattr(time, "monotonic", lambda: _FAR_FUTURE_MONOTONIC)
    assert DETACHED.as_namespace(_ANY_TOOL)["elapsed_seconds"] == 0.0


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
    """A child scope does not roll up: a per-run cap is bypassable by spawning a
    sub-agent. Flip this test when roll-up lands."""
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
    """A context still holding the reference keeps the record usable after the
    scope closed — what ``run_streamed`` depends on."""
    with run_scope("a") as facts:
        pass

    facts.record_execution(_ANY_TOOL)  # a detached background task would do this

    with use_run_facts(facts):
        assert get_run_facts().tool_calls == 1


@pytest.mark.asyncio
async def test_scope_survives_async_generator_finalizer() -> None:
    """Why the restore uses ``set()``: an async-generator finalizer runs in a
    different Context, where ``reset(token)`` raises."""

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
    """Tasks copy the context but share the record, so their writes reach the run
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
    """The other half of the asymmetry: mutation propagates up, rebinding does
    not, so a sub-task cannot hijack the namespace."""
    with run_scope("parent") as parent:

        async def child() -> None:
            with run_scope("child"):
                get_run_facts().record_execution(_ANY_TOOL)

        await asyncio.create_task(child())

        assert get_run_facts() is parent
        assert parent.tool_calls == 0  # the child's write went to the child


def test_raw_thread_is_detached() -> None:
    """Known limitation: guarded work dispatched to a raw thread pool records
    nothing. LangChain's own executor is safe — it copies the context."""
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


def test_record_execution_counts_per_tool() -> None:
    with run_scope("a") as facts:
        facts.record_execution(_ANY_TOOL)
        facts.record_execution(_OTHER_TOOL)
        facts.record_execution(_ANY_TOOL)

        assert facts.tool_calls == 3
        assert facts._calls_by_tool == {_ANY_TOOL: 2, _OTHER_TOOL: 1}


def test_calls_by_tool_is_the_first_use_ordered_tool_set() -> None:
    """Why there is no separate ``tools_used`` field: re-keying a dict does not
    reorder it, so the keys already are the deduplicated first-use sequence."""
    with run_scope("a") as facts:
        for tool in (_OTHER_TOOL, _ANY_TOOL, _OTHER_TOOL):
            facts.record_execution(tool)
        assert list(facts._calls_by_tool) == [_OTHER_TOOL, _ANY_TOOL]


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
    """Every counter is non-decreasing — the property that makes a ``<`` predicate
    latch. Asserted on the fields, where the invariant lives, and over discovered
    sets so a new counter is covered without editing this test."""
    rng = random.Random(_FUZZ_SEED)
    with run_scope("a") as facts:
        previous = _mutable_state(facts)
        for _ in range(_FUZZ_STEPS):
            rng.choice(_recorders(facts))()
            current = _mutable_state(facts)
            for name, value in current.items():
                if isinstance(value, int):
                    assert value >= previous[name], name
                elif isinstance(value, dict):
                    for key, count in value.items():
                        assert count >= previous[name].get(key, 0), f"{name}.{key}"
            previous = current


def test_registry_is_the_disjoint_union_of_its_halves() -> None:
    """The linter reads the halves, ``as_namespace`` reads the union. A path in
    both would be linted as a list *and* as a scalar; one in neither would be
    projected and unlintable."""
    assert KNOWN_RUN_PATHS == SCALAR_PATHS | LIST_PATHS
    assert not (SCALAR_PATHS & LIST_PATHS)


def test_as_namespace_returns_only_registered_paths() -> None:
    """A path a policy can reference is always one the SDK maintains, independent
    of the load-time linter."""
    with run_scope("a") as facts:
        assert set(facts.as_namespace(_ANY_TOOL)) == KNOWN_RUN_PATHS
    assert set(DETACHED.as_namespace(_ANY_TOOL)) == KNOWN_RUN_PATHS


def test_as_namespace_exposes_identity_and_elapsed() -> None:
    with run_scope("billing") as facts:
        namespace = facts.as_namespace(_ANY_TOOL)
        assert namespace["id"] == facts.id
        assert namespace["agent"] == "billing"
        assert namespace["elapsed_seconds"] >= 0.0


def test_elapsed_derives_from_the_monotonic_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wall clock is the bug guarded against: an NTP step back would un-block a
    run that had already exceeded its budget."""
    clock = iter([100.0, 142.5])
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))

    with run_scope("a") as facts:  # consumes 100.0 as the origin
        assert facts.as_namespace(_ANY_TOOL)["elapsed_seconds"] == pytest.approx(42.5)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------


def test_parallel_recorders_do_not_lose_increments() -> None:
    """The lock's reason to exist: parallel tool calls increment one record."""
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


def test_llm_usage_is_applied_atomically() -> None:
    """Both token counters move together or not at all — what will make a
    projected ``total_tokens`` equal its parts, and why the read is locked."""
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
