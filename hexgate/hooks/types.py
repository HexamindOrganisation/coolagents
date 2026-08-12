"""Types for the tool-hook pipeline.

A *hook* is a plain callable run before (``pre``) or after (``post``) a
guarded tool call. Pre-hooks see the :class:`ToolCall` and may observe it,
rewrite its args, or :class:`Halt` before ``decide``. Post-hooks see the
:class:`ToolCall` and the :class:`ToolOutcome` and may observe or halt.
Result rewrite is a later phase (see ``tool-hooks-design.md``); returning
``Proceed(result=...)`` is rejected in v1.

The seam that runs these lives in :mod:`hexgate.hooks.runner`.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Union

from hexgate.security.decision import DecisionOutcome

if TYPE_CHECKING:
    from hexgate.runtime.context import HexgateContext

# Sentinel distinguishing "field not provided" from an explicit ``None`` (a
# real value a later result-rewrite phase must be able to set). Never compared
# by value, only by identity.
_UNSET: Any = object()


@dataclass(frozen=True, slots=True)
class Modification:
    """One recorded change a hook made to a call.

    Provenance, routed to the operator/audit channel, never echoed to the
    model in cleartext. ``summary`` must be operator-safe: name the field and
    a count, not the stripped value. A raw secret belongs nowhere here — a
    hash or a redacted form only.
    """

    plugin: str
    target: str  # "args" | "result"
    summary: str


@dataclass(frozen=True, slots=True)
class ToolCall:
    """The proposed call a hook inspects.

    ``args`` is always JSON-ish (the model emits tool arguments as JSON, so
    there is no opaque object on the args side). ``context`` is the active
    :class:`HexgateContext` (caller identity, role, attributes), the same
    source ``decide`` reads. ``scratch`` is a per-call dict shared from pre to
    post, for the rare plugin that needs paired state.
    """

    tool_name: str
    args: dict[str, Any]
    agent_name: str | None = None
    context: "HexgateContext | None" = None
    scratch: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ToolOutcome:
    """The result of running the wrapped tool, handed to post-hooks.

    ``value`` may be JSON-ish or an opaque object. In v1 post-hooks observe or
    halt; they do not rewrite it.
    """

    ok: bool
    value: Any = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Proceed:
    """Continue the pipeline.

    ``Proceed()`` continues unchanged. ``Proceed(args=...)`` rewrites the
    args a pre-hook passes downstream (to ``decide`` and the tool); the
    optional ``modification`` documents it, and the runner synthesizes a
    generic one if omitted. ``result`` is reserved for the later
    result-rewrite phase and is rejected in v1.
    """

    args: dict[str, Any] | None = None
    result: Any = _UNSET
    modification: Modification | None = None


@dataclass(frozen=True, slots=True)
class Halt:
    """Stop the call and hand the model a safe refusal.

    ``reason`` is the only field the model sees: name the rule and category,
    never the offending input, so the refusal does not leak and does not hand
    the model a substring to obfuscate and resend. ``detail`` is
    operator-only and rides the audit/observer channel. ``outcome`` is
    ``DENY`` or ``NEEDS_APPROVAL`` (the latter consults the approval handler,
    exactly like a policy ``NEEDS_APPROVAL``).
    """

    reason: str
    outcome: DecisionOutcome = DecisionOutcome.DENY
    detail: str | None = None


# A hook returns one of these (or its awaitable). ``None`` == ``Proceed()``.
PreResult = Union[Proceed, Halt, None]
PostResult = Union[Proceed, Halt, None]
PreHook = Callable[[ToolCall], "PreResult | Awaitable[PreResult]"]
PostHook = Callable[[ToolCall, ToolOutcome], "PostResult | Awaitable[PostResult]"]


@dataclass(frozen=True)
class Hook:
    """A registered hook plus its flags.

    ``observe_only`` makes the hook a pure side effect: it is fail-open (a
    raise is swallowed and logged) and its return value is ignored, so it can
    neither rewrite nor halt. A normal hook is fail-closed (a raise denies the
    call). ``matches`` scopes the hook to some tools; ``None`` means every
    tool. Bare callables passed to :class:`ToolPipeline` are wrapped in a
    default ``Hook`` (fail-closed, all tools).
    """

    fn: Callable[..., Any]
    observe_only: bool = False
    matches: Callable[[str], bool] | None = None

    @property
    def label(self) -> str:
        return getattr(self.fn, "__name__", None) or repr(self.fn)


@dataclass(frozen=True, slots=True)
class HookEvent:
    """What the pipeline reports to a :data:`HookObserver`.

    A local-process, fire-and-forget record (like ``decision_observer``): the
    call, the modifications applied, and the halt if one fired. This is the
    observer half of provenance; durable platform persistence of
    ``modifications`` is a later increment.
    """

    call: ToolCall
    modifications: tuple[Modification, ...]
    halt: Halt | None = None
    halted_by: str | None = None


HookObserver = Callable[[HookEvent], None]


def observe(
    fn: Callable[..., Any], *, matches: Callable[[str], bool] | None = None
) -> Hook:
    """Register ``fn`` as a fail-open, side-effect-only hook."""
    return Hook(fn, observe_only=True, matches=matches)


def _as_hook(hook: "Hook | Callable[..., Any]") -> Hook:
    return hook if isinstance(hook, Hook) else Hook(hook)


class ToolPipeline:
    """An ordered pre-list and post-list of hooks for one agent.

    Bare callables are coerced to default (fail-closed, all-tools)
    :class:`Hook`s. ``observer`` receives a :class:`HookEvent` per call,
    isolated so a broken observer never breaks a tool call.
    """

    __slots__ = ("pre", "post", "observer")

    def __init__(
        self,
        pre: "list[Hook | Callable[..., Any]] | tuple[Any, ...]" = (),
        post: "list[Hook | Callable[..., Any]] | tuple[Any, ...]" = (),
        observer: HookObserver | None = None,
    ) -> None:
        self.pre: tuple[Hook, ...] = tuple(_as_hook(h) for h in pre)
        self.post: tuple[Hook, ...] = tuple(_as_hook(h) for h in post)
        self.observer = observer

    @property
    def is_empty(self) -> bool:
        return not self.pre and not self.post


__all__ = [
    "Halt",
    "Hook",
    "HookEvent",
    "HookObserver",
    "Modification",
    "PostHook",
    "PostResult",
    "PreHook",
    "PreResult",
    "Proceed",
    "ToolCall",
    "ToolOutcome",
    "ToolPipeline",
    "observe",
]
