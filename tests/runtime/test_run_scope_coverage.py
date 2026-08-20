"""Every run entry point must open a ``run_scope``.

A missed boundary is a *silent fail-open*, not a loud failure: outside a scope
``get_run_facts()`` returns ``DETACHED``, which reads zeros, so a policy
carrying ``run.tool_calls < 20`` would pass forever. Nothing else in the suite
would notice.

So this file has two halves. :func:`_boundaries` **derives** the expected set
from method signatures, which is what catches an entry point added later
without a scope. ``SCOPE_SITES`` then pins where each one opens it, since some
boundaries delegate to a helper and the native ambient path has no
``hexgate_context`` parameter to derive from.

The source-text assertions are deliberate. A behavioural equivalent needs a
live agent fixture per framework, and the thing being guarded against is a
line of code that is missing.
"""

from __future__ import annotations

import importlib
import inspect
from typing import Any

import pytest

_CONTEXT_PARAM = "hexgate_context"
_OPENS_SCOPE = "run_scope("
_JOINS_SCOPE = "use_run_facts("

# The four framework adapters take the caller's HexgateContext explicitly, so
# their run boundaries are derivable (see _boundaries). The native HexgateAgent
# is ambient — it reads the contextvar — so it is listed but excluded there.
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
    ("hexgate.adapters.openai.runner", "HexgateRunner", "run_streamed", "run_streamed"),
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

    Derived rather than listed so that adding an entry point without wiring a
    scope fails, instead of quietly passing because nobody updated a constant.
    """
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
    """The guard against a *future* unwired entry point.

    If someone adds a run method taking ``hexgate_context`` and does not add it
    to SCOPE_SITES, this fails — rather than the boundary silently running
    detached, where every ``run.*`` cap reads zero and passes.
    """
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
    assert _OPENS_SCOPE in source, (
        f"{module_name}.{class_name}.{method} does not open a run scope "
        f"(expected it in {symbol!r}). An unscoped boundary reads DETACHED, "
        f"so every run.* constraint silently passes."
    )


def test_scope_opens_after_the_ban_check() -> None:
    """A refused invocation is not a run: the ban gate must fire before the
    scope opens, or a banned caller mints run facts nothing ever reads."""
    source = _source_of(
        "hexgate.adapters.langchain.agent", "HexgateLangchainAgent", "ainvoke"
    )
    assert source.index("_check_ban_async") < source.index("_abind")


def test_run_streamed_rejoins_rather_than_mints() -> None:
    """``Runner.run_streamed`` hands tools to a background task that snapshots
    the contextvars, then returns. The consumer-side iterator has to re-bind
    that same object; minting there would split one invocation across two run
    ids, and every cap would read half the truth."""
    source = _source_of(
        "hexgate.adapters.openai.runner", "HexgateRunner", "run_streamed"
    )
    assert _OPENS_SCOPE in source
    assert _JOINS_SCOPE in source
    # The scope must wrap the run_streamed call itself, since that is where the
    # background task snapshots the context.
    assert source.index(_OPENS_SCOPE) < source.index("Runner.run_streamed(")
    assert source.index("Runner.run_streamed(") < source.index(_JOINS_SCOPE)


def test_run_sync_keeps_the_loop_drain_inside_the_scope() -> None:
    """``_drain_default_loop`` exists to pump a late fire-and-forget audit or
    usage send. Draining outside the scope would attribute those tokens to no
    run at all."""
    source = _source_of("hexgate.adapters.openai.runner", "HexgateRunner", "run_sync")
    assert source.index(_OPENS_SCOPE) < source.index("_drain_default_loop()")
