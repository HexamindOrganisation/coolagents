"""Types and authoring decorators for the tool-hook pipeline.

A *guard* is a function you attach before or after a tool call with the
``@before_tool`` / ``@after_tool`` decorators. It receives the
:class:`ToolCall` (and, after the tool runs, the :class:`ToolOutcome`) and
returns :class:`Proceed` (carry on, optionally rewriting args), :class:`Halt`
(refuse), or ``None`` (the same as ``Proceed()``).

You register guards as one flat ``hooks=[...]`` list; the framework splits them
into a pre list and a post list by their decoration, preserving order within
each. There is no ``Hook`` type to construct by hand: position is the decorator
you used, and reach is the decorator's ``tool_names`` argument. See
``docs/adr/R-HOOK-001..003`` and the runner in :mod:`hexgate.hooks.runner`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from hexgate.security.decision import DecisionOutcome

if TYPE_CHECKING:
    from hexgate.runtime.context import HexgateContext

# Sentinel distinguishing "field not provided" from an explicit ``None`` (a
# real value a later result-rewrite phase must be able to set). Identity-only.
_UNSET: Any = object()


# ---------------------------------------------------------------------------
# What a guard sees and returns
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Modification:
    """One recorded change a guard made to a call.

    Provenance, routed to the operator/audit channel, never echoed to the
    model in cleartext. ``summary`` must be operator-safe: name the field and
    a count, not the stripped value.
    """

    plugin: str
    target: str  # "args" | "result"
    summary: str


@dataclass(frozen=True, slots=True)
class ToolCall:
    """The proposed call a guard inspects.

    ``args`` is always JSON-ish (the model emits tool arguments as JSON, so
    there is no opaque object on the args side). ``context`` is the active
    :class:`HexgateContext` (caller identity, role, attributes), the same
    source ``decide`` reads. ``scratch`` is a per-call dict shared from a
    before-guard to an after-guard.
    """

    tool_name: str
    args: dict[str, Any]
    agent_name: str | None = None
    context: "HexgateContext | None" = None
    scratch: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """The result of running the tool, handed to after-guards.

    ``ok=True`` carries the return in ``value`` (JSON-ish or an opaque object);
    ``ok=False`` carries the stringified exception in ``error`` when the tool
    raised, so an after-guard sees a failure the same way it sees a result. In
    v1 after-guards observe or halt; they do not rewrite the value.
    """

    ok: bool
    value: Any = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Proceed:
    """Continue the pipeline.

    ``Proceed()`` continues unchanged. ``Proceed(args=...)`` rewrites the args
    a before-guard passes downstream (to ``decide`` and the tool); the optional
    ``modification`` documents it, and the runner synthesizes a generic one if
    omitted. ``result`` is reserved for the later result-rewrite phase and is
    rejected in v1.
    """

    args: dict[str, Any] | None = None
    result: Any = _UNSET
    modification: Modification | None = None


@dataclass(frozen=True, slots=True)
class Halt:
    """Stop the call and hand the model a safe refusal.

    ``reason`` is the only field the model sees: name the rule and category,
    never the offending input, so the refusal does not leak and does not hand
    the model a substring to obfuscate and resend. ``detail`` is operator-only
    and rides the audit/observer channel. ``outcome`` is ``DENY`` or
    ``NEEDS_APPROVAL`` (the latter consults the approval handler, exactly like a
    policy ``NEEDS_APPROVAL``).
    """

    reason: str
    outcome: DecisionOutcome = DecisionOutcome.DENY
    detail: str | None = None


# ---------------------------------------------------------------------------
# The internal carrier and the authoring decorators
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hook:
    """A guard plus its decoration. Internal: built by the decorators.

    ``position`` is ``"pre"`` or ``"post"``. ``tool_names`` is the reach
    (``None`` = every tool). ``observe`` marks a fail-open, side-effect-only
    guard: it is not allowed to rewrite or halt, and a raise is swallowed
    rather than denying the call.
    """

    fn: Callable[..., Any]
    position: str
    tool_names: frozenset[str] | None = None
    observe: bool = False

    @property
    def label(self) -> str:
        return getattr(self.fn, "__name__", None) or repr(self.fn)

    def applies(self, tool_name: str) -> bool:
        return self.tool_names is None or tool_name in self.tool_names

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Keep a decorated guard callable, so `before_tool(f)` is not a
        # surprising thing to have bound to a name.
        return self.fn(*args, **kwargs)


def _as_names(tool_names: "str | Iterable[str] | None") -> frozenset[str] | None:
    if tool_names is None:
        return None
    if isinstance(tool_names, str):
        return frozenset((tool_names,))
    return frozenset(tool_names)


def _decorator(
    position: str,
    fn: Callable[..., Any] | None,
    tool_names: "str | Iterable[str] | None",
    observe: bool,
) -> Any:
    names = _as_names(tool_names)

    def wrap(f: Callable[..., Any]) -> Hook:
        inner = f.fn if isinstance(f, Hook) else f
        return Hook(fn=inner, position=position, tool_names=names, observe=observe)

    # Bare form (`@before_tool` / `before_tool(fn)`) vs called form
    # (`@before_tool(tool_names=..., observe=...)`).
    return wrap(fn) if fn is not None else wrap


def before_tool(
    fn: Callable[..., Any] | None = None,
    *,
    tool_names: "str | Iterable[str] | None" = None,
    observe: bool = False,
) -> Any:
    """Attach a guard that runs before a tool call (before ``decide``).

    Use bare for every tool (``@before_tool``), or called to scope and
    configure it (``@before_tool(tool_names=["refund_order"], observe=True)``).
    ``tool_names`` accepts a name or a list of names (``None`` = every tool).
    ``observe=True`` makes it a fail-open watcher that cannot rewrite or halt.
    Also usable inline as a wrapper: ``hooks=[before_tool(lambda call: ...)]``.
    """
    return _decorator("pre", fn, tool_names, observe)


def after_tool(
    fn: Callable[..., Any] | None = None,
    *,
    tool_names: "str | Iterable[str] | None" = None,
    observe: bool = False,
) -> Any:
    """Attach a guard that runs after a tool call, on its result.

    Same forms as :func:`before_tool`. An after-guard sees the
    :class:`ToolOutcome` (a return, or a raised error) and may observe or halt;
    it does not rewrite the result in v1. Note the tool has already executed by
    the time an after-guard runs, so a `Halt` here gates whether the model *sees*
    the result, not the tool's side effect (which already happened). A
    `Halt(NEEDS_APPROVAL)` on an after-guard therefore gates result release, not
    the action; use a `@before_tool` guard to gate the action itself.
    """
    return _decorator("post", fn, tool_names, observe)


# ---------------------------------------------------------------------------
# Provenance observer and the internal pipeline
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HookEvent:
    """What the pipeline reports to a :data:`HookObserver`.

    A local-process, fire-and-forget record (like ``decision_observer``),
    emitted when a guard *acts* on a call, not on every call: a halt (blocked),
    an approved halt (``approved=True``, a guard required and got sign-off and
    the call proceeded), or the set of modifications applied to a proceeding
    call. A plain allow with no guard action emits nothing.
    """

    call: ToolCall
    modifications: tuple[Modification, ...]
    halt: Halt | None = None
    halted_by: str | None = None
    approved: bool = False


HookObserver = Callable[[HookEvent], None]


class ToolPipeline:
    """The split pre/post guard lists for one agent. Internal.

    Built by :func:`build_pipeline` from a flat ``hooks`` list; the runner and
    the ``GuardedTool`` seam consume it. Not part of the public surface.
    """

    __slots__ = ("pre", "post", "observer")

    def __init__(
        self,
        pre: "Iterable[Hook]" = (),
        post: "Iterable[Hook]" = (),
        observer: HookObserver | None = None,
    ) -> None:
        self.pre: tuple[Hook, ...] = tuple(pre)
        self.post: tuple[Hook, ...] = tuple(post)
        self.observer = observer

    @property
    def is_empty(self) -> bool:
        return not self.pre and not self.post


def build_pipeline(
    hooks: "Iterable[Hook] | None", *, observer: HookObserver | None = None
) -> ToolPipeline | None:
    """Split a flat ``hooks`` list into a :class:`ToolPipeline`.

    Preserves the relative order of guards within the pre list and within the
    post list. Every element must be a guard produced by ``@before_tool`` /
    ``@after_tool``; a bare undecorated callable is a hard error, since a guard
    has to declare whether it runs before or after. Returns ``None`` only when
    there is nothing to run and nothing to observe, so ``hooks=None`` and
    ``hooks=[]`` behave the same when an ``observer`` is supplied.
    """
    pre: list[Hook] = []
    post: list[Hook] = []
    for h in hooks or ():
        if not isinstance(h, Hook):
            raise TypeError(
                f"{h!r} is not a guard; decorate it with @before_tool or "
                "@after_tool (or wrap it: before_tool(fn) / after_tool(fn))"
            )
        (pre if h.position == "pre" else post).append(h)
    pipeline = ToolPipeline(pre=pre, post=post, observer=observer)
    return None if pipeline.is_empty and observer is None else pipeline


__all__ = [
    "Halt",
    "HookEvent",
    "HookObserver",
    "Modification",
    "Proceed",
    "ToolCall",
    "ToolOutcome",
    "after_tool",
    "before_tool",
]
