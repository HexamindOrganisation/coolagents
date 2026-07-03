"""Tiny constraint expression parser + evaluator.

Constraints look like Rego conditions but parse to a flat AST so M1's
structured policy engine can evaluate them without dragging in an OPA
runtime. When we swap the evaluator for OPA in M2, the YAML doesn't
change — only the executor below.

Grammar (PEG-ish, single line per constraint):

    constraint   := lhs WS op WS rhs
    lhs          := IDENT ("." IDENT)*           # e.g. args.amount
    op           := "==" | "!=" | "<=" | ">=" | "<" | ">"
                  | "in" | "not in"
    rhs          := scalar | list
    scalar       := STRING | NUMBER | "true" | "false" | "null"
    list         := "[" (rhs ("," rhs)*)? "]"
    STRING       := double-quoted string with backslash escapes
    NUMBER       := optional sign + integer or decimal
    IDENT        := [a-zA-Z_][a-zA-Z_0-9]*

Concrete examples (all of these parse and evaluate today):

    args.amount <= 50
    args.currency == "USD"
    args.template in ["refund_confirmed", "ticket_resolved"]
    args.priority not in ["urgent", "critical"]
    args.confirmed == true
    args.region != "EU"

What we deliberately do NOT support yet:

    * Boolean composition (AND / OR) — emit multiple constraint lines; the
      policy engine ANDs them.
    * Function calls (`startswith`, `contains`, …) — wait for the OPA swap.
    * Cross-fact comparisons (``refund_limit(N) and args.amount <= N``) —
      M2's role-resolved facts will handle this directly.
    * Negation as a prefix operator — use ``!=`` or ``not in``.

The parser is a recursive-descent walker over a tiny token stream. ~40
LoC. Evaluator dispatches on the operator. Both are deliberately small so
the OPA migration is a swap, not a rewrite.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from hexgate.security.errors import PolicyDeniedError


class ConstraintParseError(ValueError):
    """Raised on malformed constraint source — surfaces at policy load."""


@dataclass(frozen=True, slots=True)
class Lit:
    """A literal operand — the parsed RHS value (str / number / bool / list / None)."""

    value: Any


@dataclass(frozen=True, slots=True)
class Ref:
    """A dotted accessor into the evaluation context, e.g. ``args.amount``."""

    path: tuple[str, ...]


Operand = Ref | Lit


@dataclass(frozen=True, slots=True)
class Cmp:
    """A comparison node — ``<operand> <op> <operand>``.

    Today the grammar only produces ``Ref <op> Lit`` (a path compared to a
    literal); later tiers add ``Ref <op> Ref`` (cross-field) and other node
    kinds alongside this one. Evaluation and Rego rendering dispatch on the
    node type, so those additions are new cases rather than rewrites.
    """

    left: Operand
    op: str
    right: Operand
    source: str  # raw text, for error messages

    @property
    def path(self) -> tuple[str, ...]:
        """Back-compat accessor — the left path (left is a ``Ref`` today)."""
        return self.left.path  # type: ignore[union-attr]

    @property
    def value(self) -> Any:
        """Back-compat accessor — the right literal (right is a ``Lit`` today)."""
        return self.right.value if isinstance(self.right, Lit) else self.right


# The evaluator and Rego compiler dispatch on ``Node``. One member today; the
# roadmap adds Call / Quant / And / Or / Not as siblings.
Node = Cmp
Constraint = Cmp  # back-compat alias for existing importers


_OP_TOKENS = ("<=", ">=", "==", "!=", "not in", "in", "<", ">")
_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]*$")


def parse_constraint(source: str) -> Node:
    """Parse one constraint line into a :class:`Node`.

    Raises :class:`ConstraintParseError` for unsupported operators, bad
    identifiers on the left, or non-literal right-hand sides.
    """
    text = source.strip()
    if not text:
        raise ConstraintParseError("empty constraint")

    # Find the first matching operator outside of any string literal. Since
    # the LHS is restricted to dotted identifiers, we can scan token-by-token
    # rather than worrying about strings on the left.
    op, op_index = _find_operator(text)
    if op is None:
        raise ConstraintParseError(
            f"no recognised operator in {source!r}; "
            f"expected one of {', '.join(_OP_TOKENS)}"
        )

    lhs_raw = text[:op_index].rstrip()
    rhs_raw = text[op_index + len(op) :].lstrip()

    path = _parse_path(lhs_raw, source)
    value = _parse_rhs(rhs_raw, source)

    if op in ("in", "not in") and not isinstance(value, list):
        raise ConstraintParseError(
            f"{op!r} requires a list on the right in {source!r}, got "
            f"{type(value).__name__}"
        )

    return Cmp(left=Ref(path), op=op, right=Lit(value), source=source)


def _find_operator(text: str) -> tuple[str | None, int]:
    """Return the first operator found in ``text`` and its start index.

    We only look outside double-quoted strings; LHS doesn't allow them, but
    being explicit keeps the function reusable if the grammar grows.
    """
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        for op in _OP_TOKENS:
            if text.startswith(op, i):
                # Skip "in"/"not in" if surrounded by identifier characters
                # (e.g. ``args.invalid``); require word boundaries on both sides.
                if op in ("in", "not in"):
                    left_ok = i == 0 or not _is_ident_char(text[i - 1])
                    right_end = i + len(op)
                    right_ok = right_end == len(text) or not _is_ident_char(
                        text[right_end]
                    )
                    if not (left_ok and right_ok):
                        continue
                return op, i
    return None, -1


def _is_ident_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _parse_path(lhs: str, source: str) -> tuple[str, ...]:
    if not lhs:
        raise ConstraintParseError(f"missing left-hand side in {source!r}")
    parts = lhs.split(".")
    for part in parts:
        if not _IDENT_RE.match(part):
            raise ConstraintParseError(
                f"invalid identifier {part!r} in left-hand side of {source!r}"
            )
    return tuple(parts)


def _parse_rhs(rhs: str, source: str) -> Any:
    """Parse the right-hand side as a JSON literal.

    Using ``json.loads`` gives us strings (with proper escape handling),
    numbers, booleans, and lists for free — at the price of requiring
    double-quoted strings on the right, which is also what Rego wants.
    Single quotes are not supported.
    """
    if not rhs:
        raise ConstraintParseError(f"missing right-hand side in {source!r}")
    try:
        return json.loads(rhs)
    except json.JSONDecodeError as exc:
        raise ConstraintParseError(
            f"right-hand side of {source!r} is not a valid JSON literal: {exc.msg}"
        ) from exc


def _resolve_path(path: tuple[str, ...], context: dict[str, Any]) -> Any:
    """Walk ``path`` over ``context``; return ``_MISSING`` if any hop misses."""
    cursor: Any = context
    for part in path:
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        else:
            return _MISSING
    return cursor


_MISSING = object()


def _resolve_operand(operand: Operand, context: dict[str, Any]) -> Any:
    """Resolve an operand to a concrete value (``_MISSING`` if a ref misses)."""
    if isinstance(operand, Lit):
        return operand.value
    return _resolve_path(operand.path, context)


def _eval(node: Node, context: dict[str, Any]) -> bool:
    """Dispatch a node to its evaluator. One node kind today (``Cmp``)."""
    if isinstance(node, Cmp):
        return _eval_cmp(node, context)
    raise ConstraintParseError(f"cannot evaluate node {node!r}")


def _eval_cmp(node: Cmp, context: dict[str, Any]) -> bool:
    """Return True when ``context`` satisfies the comparison.

    A missing operand on either side is always False — a constraint that asks
    for ``args.amount <= 50`` when the call didn't supply ``amount`` fails
    closed. The engine's default stance is "absent fact = no".
    """
    actual = _resolve_operand(node.left, context)
    expected = _resolve_operand(node.right, context)
    if actual is _MISSING or expected is _MISSING:
        return False
    op = node.op
    try:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op == "<":
            return actual < expected
        if op == "<=":
            return actual <= expected
        if op == ">":
            return actual > expected
        if op == ">=":
            return actual >= expected
        if op == "in":
            return actual in expected
        if op == "not in":
            return actual not in expected
    except TypeError:
        # Type-mismatched comparisons (e.g. str < int) → fail closed rather
        # than raise; an arg of the wrong type shouldn't crash enforcement.
        return False
    # Unreachable given _find_operator's whitelist, but keeps mypy happy.
    return False


def evaluate_constraint(node: Node, context: dict[str, Any]) -> bool:
    """Return True when ``context`` satisfies ``node`` (public entry point)."""
    return _eval(node, context)


def check_constraints(
    constraints: list[str | Node],
    arguments: dict[str, Any] | None,
    tool_name: str,
) -> None:
    """Evaluate every constraint; raise on the first failure.

    Caller passes raw source strings (typical YAML path) or pre-parsed
    nodes. Source strings are parsed once per call here for simplicity —
    caches can be added later if profiling demands it.
    """
    if not constraints:
        return
    context = {"args": dict(arguments or {})}
    for entry in constraints:
        parsed = parse_constraint(entry) if isinstance(entry, str) else entry
        if not evaluate_constraint(parsed, context):
            raise PolicyDeniedError(
                f'Policy on "{tool_name}" denied: constraint failed — {parsed.source}'
            )
