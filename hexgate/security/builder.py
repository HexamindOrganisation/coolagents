"""Ergonomic, type-checked construction of policies in Python.

``AgentPolicy.model_validate({...})`` already lets you build a policy from a
dict, but you hand-write constraint *strings*. This module adds:

* :class:`PolicyBuilder` / :class:`RolePolicyBuilder` — fluent construction of
  the same validated :class:`AgentPolicy` / :class:`PolicySet` models.
* :class:`C` — typed constraint constructors (``C("args.amount") <= 500``) that
  emit the exact constraint strings the YAML parser accepts, so there's a
  single grammar and parity is automatic. Each one is validated eagerly, so a
  malformed constraint raises at the call site, not later at enforcement.

Nothing here is a new enforcement path — it's sugar over the existing models
and grammar.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from hexgate.security.constraints import parse_constraint
from hexgate.security.models import (
    AgentPolicy,
    BaseToolPolicy,
    FileScope,
    FileToolPolicy,
    PolicyMode,
    ToolPolicy,
)
from hexgate.security.policy_set import PolicySet, load_policy_map


class _Constraint:
    """A validated constraint expression — its ``str()`` is the grammar string."""

    __slots__ = ("_text",)

    def __init__(self, text: str) -> None:
        parse_constraint(text)  # eager validation → fail at the call site
        self._text = text

    def __str__(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"C({self._text!r})"


ConstraintLike = str | _Constraint
WhenArg = ConstraintLike | Iterable[ConstraintLike]


def _render_rhs(value: Any) -> str:
    """A ``C`` on the right is a cross-field reference; anything else is JSON."""
    return value._expr if isinstance(value, C) else json.dumps(value)


class C:
    """A constraint builder over a field path, e.g. ``C("args.amount") <= 500``.

    Comparison operators return a validated :class:`_Constraint`. The right
    operand may be a literal (rendered as JSON) or another ``C`` for a
    cross-field comparison (``C("args.max") >= C("args.min")``).
    """

    __slots__ = ("_expr",)

    def __init__(self, path: str) -> None:
        self._expr = path

    def count(self) -> C:
        """Wrap this operand in ``count(...)`` — ``C("args.x").count() <= 3``."""
        return C(f"count({self._expr})")

    def _cmp(self, op: str, other: Any) -> _Constraint:
        return _Constraint(f"{self._expr} {op} {_render_rhs(other)}")

    def __le__(self, other: Any) -> _Constraint:
        return self._cmp("<=", other)

    def __lt__(self, other: Any) -> _Constraint:
        return self._cmp("<", other)

    def __ge__(self, other: Any) -> _Constraint:
        return self._cmp(">=", other)

    def __gt__(self, other: Any) -> _Constraint:
        return self._cmp(">", other)

    def __eq__(self, other: Any) -> _Constraint:  # type: ignore[override]
        return self._cmp("==", other)

    def __ne__(self, other: Any) -> _Constraint:  # type: ignore[override]
        return self._cmp("!=", other)

    # __eq__ is overloaded for the DSL, so instances are intentionally unhashable.
    __hash__ = None  # type: ignore[assignment]

    def is_in(self, values: list[Any]) -> _Constraint:
        return _Constraint(f"{self._expr} in {json.dumps(values)}")

    def not_in(self, values: list[Any]) -> _Constraint:
        return _Constraint(f"{self._expr} not in {json.dumps(values)}")

    def __repr__(self) -> str:
        return f"C({self._expr!r})"


def _normalize(when: WhenArg) -> list[str]:
    if isinstance(when, (str, _Constraint)):
        return [str(when)]
    return [str(c) for c in when]


class PolicyBuilder:
    """Fluent construction of a single :class:`AgentPolicy` (one role).

    >>> policy = (
    ...     PolicyBuilder(default="deny")
    ...     .allow("web_search")
    ...     .allow("refund_order", when=[C("args.amount") <= 500])
    ...     .approve("edit_file")
    ...     .build()
    ... )
    """

    def __init__(self, *, default: PolicyMode = "deny") -> None:
        self._default: PolicyMode = default
        self._tools: dict[str, ToolPolicy] = {}

    def allow(self, tool: str, *, when: WhenArg = ()) -> PolicyBuilder:
        self._tools[tool] = BaseToolPolicy(mode="allow", constraints=_normalize(when))
        return self

    def deny(self, tool: str) -> PolicyBuilder:
        self._tools[tool] = BaseToolPolicy(mode="deny")
        return self

    def approve(self, tool: str, *, when: WhenArg = ()) -> PolicyBuilder:
        self._tools[tool] = BaseToolPolicy(
            mode="approval_required", constraints=_normalize(when)
        )
        return self

    def files(
        self,
        tool: str,
        *,
        mode: PolicyMode = "allow",
        allow: Iterable[str] = (),
        deny: Iterable[str] = (),
        when: WhenArg = (),
    ) -> PolicyBuilder:
        """A file-oriented tool with an optional path scope (pydantic engine only)."""
        allowed, denied = list(allow), list(deny)
        scope = (
            FileScope(allowed_paths=allowed, denied_paths=denied)
            if (allowed or denied)
            else None
        )
        self._tools[tool] = FileToolPolicy(
            mode=mode, constraints=_normalize(when), file_scope=scope
        )
        return self

    def build(self) -> AgentPolicy:
        return AgentPolicy(
            default_policy=BaseToolPolicy(mode=self._default), tools=self._tools
        )


class RolePolicyBuilder:
    """Fluent construction of a role-aware :class:`PolicySet`.

    >>> ps = (
    ...     RolePolicyBuilder()
    ...     .role("default", PolicyBuilder().allow("web_search"))
    ...     .role("billing", PolicyBuilder().allow("refund_order"))
    ...     .build()
    ... )
    """

    def __init__(self) -> None:
        self._roles: dict[str, AgentPolicy] = {}

    def role(
        self,
        name: str,
        builder: PolicyBuilder,
        *,
        inherits: Iterable[str] = (),
        mixin: bool = False,
    ) -> RolePolicyBuilder:
        policy = builder.build()
        self._roles[name] = policy.model_copy(
            update={"inherits": list(inherits), "is_mixin": mixin}
        )
        return self

    def build(self, *, default: str | None = None) -> PolicySet:
        return load_policy_map(self._roles, default=default)
