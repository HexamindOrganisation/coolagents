"""Every run entry point must open a ``run_scope``.

A missed boundary is a *silent fail-open*: outside a scope ``get_run_facts()``
returns ``DETACHED``, which reads zeros, so ``run.tool_calls < 20`` would pass
forever and nothing else in the suite would notice.

Hence two halves: :func:`_boundaries` derives the expected set from method
signatures, catching an entry point added later; ``SCOPE_SITES`` pins where each
opens it. The source-text assertions are deliberate — what is guarded against is a
missing line of code.
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any

import pytest

_CONTEXT_PARAM = "hexgate_context"
_OPENS_SCOPE = "run_scope("
_JOINS_SCOPE = "use_run_facts("
# langchain and pydantic_ai delegate _abind/_bind to these shared helpers instead
# of calling run_scope() inline; test_shared_bind_helpers_open_a_scope pins that
# the helpers do open one.
_DELEGATES_TO_SHARED_BIND = ("abind(", "bind(")

# These four take the caller's HexgateContext explicitly, so their boundaries are
# derivable. The native HexgateAgent is ambient, so it is pinned but not derived.
_DERIVABLE = [
    ("hexgate.adapters.langchain.agent", "HexgateLangchainAgent"),
    ("hexgate.adapters.openai.runner", "HexgateRunner"),
    ("hexgate.adapters.pydantic_ai.agent", "HexgatePydanticAgent"),
    ("hexgate.adapters.google.runner", "HexgateRunner"),
]

# (module, class, run method, symbol that must open the scope). Keyed on
# module *and* class because the OpenAI and Google adapters both export a
# class named HexgateRunner. The symbol differs from the method wherever the
# boundary delegates its scope to a shared helper.
SCOPE_SITES: list[tuple[str, str, str, str]] = [
    ("hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "ainvoke", "_abind"),
    ("hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "invoke", "_bind"),
    ("hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "astream", "_abind"),
    ("hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "stream", "_bind"),
    (
        "hexgate.adapters.langchain.agent",
        "HexgateLangchainAgent",
        "astream_events",
        "_abind",
    ),
    ("hexgate.adapters.openai.runner", "HexgateRunner", "run", "run"),
    ("hexgate.adapters.openai.runner", "HexgateRunner", "run_sync", "run_sync"),
    # Both streaming entry points delegate the wrap + scope to _launch_streamed
    # after refreshing the binding and ban gate in their own (sync/async) way.
    (
        "hexgate.adapters.openai.runner",
        "HexgateRunner",
        "run_streamed",
        "_launch_streamed",
    ),
    (
        "hexgate.adapters.openai.runner",
        "HexgateRunner",
        "arun_streamed",
        "_launch_streamed",
    ),
    ("hexgate.adapters.pydantic_ai.agent", "HexgatePydanticAgent", "run", "_abind"),
    ("hexgate.adapters.pydantic_ai.agent", "HexgatePydanticAgent", "run_sync", "_bind"),
    (
        "hexgate.adapters.pydantic_ai.agent",
        "HexgatePydanticAgent",
        "run_stream",
        "_abind",
    ),
    ("hexgate.adapters.pydantic_ai.agent", "HexgatePydanticAgent", "iter", "_abind"),
    ("hexgate.adapters.google.runner", "HexgateRunner", "run", "run"),
    ("hexgate.adapters.google.runner", "HexgateRunner", "run_async", "run_async"),
    # Ambient: no hexgate_context parameter, so _boundaries cannot derive these.
    ("hexgate.agents.factory", "HexgateAgent", "ainvoke", "ainvoke"),
    ("hexgate.agents.factory", "HexgateAgent", "astream_events", "astream_events"),
]


def _load(module_name: str, class_name: str) -> Any:
    return getattr(importlib.import_module(module_name), class_name)


def _boundaries(cls: type) -> set[str]:
    """Public methods taking a ``hexgate_context`` keyword — i.e. run boundaries.
    Derived, not listed, so a new entry point cannot pass by nobody updating a
    constant."""
    found: set[str] = set()
    for name, member in inspect.getmembers(cls, callable):
        if name.startswith("_"):
            continue
        try:
            signature = inspect.signature(member)
        except (TypeError, ValueError):  # pragma: no cover - builtins
            continue
        if _CONTEXT_PARAM in signature.parameters:
            found.add(name)
    return found


def _source_of(module_name: str, class_name: str, symbol: str) -> str:
    return inspect.getsource(getattr(_load(module_name, class_name), symbol))


@pytest.mark.parametrize(("module_name", "class_name"), _DERIVABLE)
def test_every_adapter_boundary_is_covered(module_name: str, class_name: str) -> None:
    """The guard against a *future* unwired entry point: a new method taking
    ``hexgate_context`` and missing from SCOPE_SITES fails here, rather than
    silently running detached."""
    listed = {
        method
        for module, klass, method, _ in SCOPE_SITES
        if (module, klass) == (module_name, class_name)
    }
    assert _boundaries(_load(module_name, class_name)) == listed


@pytest.mark.parametrize(
    ("module_name", "class_name", "method", "symbol"),
    SCOPE_SITES,
    ids=[f"{m.rsplit('.', 1)[-1]}.{c}.{meth}" for m, c, meth, _ in SCOPE_SITES],
)
def test_scope_is_opened_for_every_boundary(
    module_name: str, class_name: str, method: str, symbol: str
) -> None:
    source = _source_of(module_name, class_name, symbol)
    opens_directly = _OPENS_SCOPE in source
    delegates = any(marker in source for marker in _DELEGATES_TO_SHARED_BIND)
    assert opens_directly or delegates, (
        f"{module_name}.{class_name}.{method} does not open a run scope, "
        f"directly or via the shared abind/bind helpers (expected it in "
        f"{symbol!r}). An unscoped boundary reads DETACHED, so every run.* "
        f"constraint silently passes."
    )


def test_shared_bind_helpers_open_a_scope() -> None:
    """Delegating boundaries trust the helper to open the scope; pin that once
    here rather than per call site."""
    from hexgate.adapters import _common

    for name in ("abind", "bind"):
        source = inspect.getsource(getattr(_common, name))
        assert _OPENS_SCOPE in source, (
            f"hexgate.adapters._common.{name} no longer opens a run scope; "
            f"every adapter boundary delegating to it would silently run "
            f"detached."
        )


def test_scope_opens_after_the_ban_check() -> None:
    """A refused invocation is not a run, so the ban gate must fire first."""
    source = _source_of(
        "hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "ainvoke"
    )
    assert source.index("_check_ban_async") < source.index("_abind")


@pytest.mark.parametrize("method", ["run_streamed", "arun_streamed"])
def test_streamed_boundaries_launch_after_the_ban_check(method: str) -> None:
    """The streaming boundaries own only the refresh + ban gate; the scope lives
    in ``_launch_streamed``, so each must actually hand off to it — and only
    once a banned run has been refused."""
    source = _source_of("hexgate.adapters.openai.runner", "HexgateRunner", method)
    assert "_launch_streamed(" in source
    assert source.index("ban_gate.check") < source.index("_launch_streamed(")


def test_run_streamed_rejoins_rather_than_mints() -> None:
    """``run_streamed`` hands tools to a background task that snapshots the
    contextvars, so the consumer-side iterator must re-bind the same object —
    minting would split one invocation across two run ids."""
    source = _source_of(
        "hexgate.adapters.openai.runner", "HexgateRunner", "_launch_streamed"
    )
    assert _OPENS_SCOPE in source
    assert _JOINS_SCOPE in source
    # The scope must wrap the run_streamed call itself, since that is where the
    # background task snapshots the context.
    assert source.index(_OPENS_SCOPE) < source.index("Runner.run_streamed(")
    assert source.index("Runner.run_streamed(") < source.index(_JOINS_SCOPE)


def test_run_sync_keeps_the_loop_drain_inside_the_scope() -> None:
    """The drain pumps a late fire-and-forget audit or usage send; outside the
    scope those tokens would belong to no run."""
    source = _source_of("hexgate.adapters.openai.runner", "HexgateRunner", "run_sync")
    assert source.index(_OPENS_SCOPE) < source.index("_drain_default_loop()")
