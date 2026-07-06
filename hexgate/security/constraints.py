"""Tiny constraint expression parser + evaluator.

Constraints look like Rego conditions but parse to a flat AST so M1's
structured policy engine can evaluate them without dragging in an OPA
runtime. When we swap the evaluator for OPA in M2, the YAML doesn't
change — only the executor below.

Grammar (PEG-ish, single line per constraint):

    constraint   := or_expr
    or_expr      := and_expr ("or" and_expr)*     # boolean OR (2c)
    and_expr     := not_expr ("and" not_expr)*    # boolean AND (2c)
    not_expr     := "not" not_expr | primary      # boolean NOT (2c)
    primary      := "(" or_expr ")" | quant | call | comparison
    comparison   := operand WS op WS operand
    op           := "==" | "!=" | "<=" | ">=" | "<" | ">"
                  | "in" | "not in"
    operand      := count | path | elem | constref | literal
    count        := "count(" path ")"            # element count (2d)
    constref     := "consts." IDENT              # named policy constant (2f)
    call         := FUNC "(" (path|elem) "," WS STRING ")"   # string function (2b)
    FUNC         := "startswith" | "endswith" | "contains" | "matches"
    quant        := ("every"|"any") "(" (path|elem) "," WS constraint ")"   # (2e)
    elem         := "." | "." IDENT ("." IDENT)*   # current element, in a quant body
    path         := IDENT ("." IDENT)*           # e.g. args.amount (a field ref)
    literal      := STRING | NUMBER | "true" | "false" | "null" | list
    list         := "[" (literal ("," literal)*)? "]"
    STRING       := double-quoted string with backslash escapes
    NUMBER       := optional sign + integer or decimal
    IDENT        := [a-zA-Z_][a-zA-Z_0-9]*

For ``in`` / ``not in`` the right-hand side must be a list *literal*.
A bare identifier on the right is a field reference (cross-field, 2a), so a
forgotten-quotes typo (``== USD``) reads as a ref to an (absent) field and
fails closed rather than erroring. ``matches`` is an RE2 regex and is
*unanchored* — use ``^…$`` for a full-string match. ``.`` is the current
element inside a quantifier body and is rejected elsewhere. ``every`` over an
empty list is vacuously true; ``any`` over an empty list is false.

Besides ``args.*``, two call-scope facts are in scope: ``role`` (the caller's
role) and ``tool`` (the tool being invoked) — mirroring Rego's ``input.role``
/ ``input.tool``. E.g. ``role == "admin"`` or ``tool == "refund_order"``.

Concrete examples (all of these parse and evaluate today):

    args.amount <= 50
    args.currency == "USD"
    args.max >= args.min                         # cross-field (2a)
    count(args.recipients) <= 10                 # count (2d)
    startswith(args.file_path, "src/")           # string function (2b)
    matches(args.id, "^inv_[0-9]+$")             # regex (2b)
    every(args.files, startswith(., "/tmp/"))    # quantifier (2e)
    any(args.items, .price <= 100)               # quantifier over sub-field
    args.amount <= consts.max_refund             # named constant (2f)
    args.repo in consts.managed_repos            # constant list
    args.role_admin == true or args.amount <= 100    # boolean OR (2c)
    not (args.env == "prod" and args.force == false)  # grouping + not (2c)
    args.template in ["refund_confirmed", "ticket_resolved"]
    args.priority not in ["urgent", "critical"]

What we deliberately do NOT support yet:

    * Boolean composition (and/or/not) *inside* a quantifier body — e.g.
      ``every(args.x, .a == 1 or .b == 2)`` — rejected on both engines.
    * ``in`` against a field reference (``args.x in args.allowed``) — the
      right of ``in`` must be a list literal or ``consts.<name>`` for now.

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


@dataclass(frozen=True, slots=True)
class Count:
    """The element count of a collection, e.g. ``count(args.recipients)``.

    Evaluates to ``len`` of a list / string / object; anything else is
    treated as missing (fail closed). Mirrors Rego's ``count`` builtin.
    """

    ref: Ref


@dataclass(frozen=True, slots=True)
class Elem:
    """The current element inside a quantifier body — ``.`` or ``.field``.

    ``path`` is empty for the element itself (``.``) or a dotted accessor into
    it (``.price`` → ``("price",)``). Only meaningful within a :class:`Quant`.
    """

    path: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConstRef:
    """A reference to a named policy constant, e.g. ``consts.max_refund``.

    Resolves to the constant's value (number / string / list / …) defined in
    the policy's ``consts`` block. Unknown at eval time → fails closed.
    """

    name: str


Operand = Ref | Count | Lit | Elem | ConstRef


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


@dataclass(frozen=True, slots=True)
class Call:
    """A boolean function over a field, e.g. ``startswith(args.id, "inv_")``.

    ``fn`` is one of ``startswith`` / ``endswith`` / ``contains`` / ``matches``;
    each maps 1:1 onto a Rego builtin. ``value`` is always a string literal.
    ``matches`` is an RE2 regex (unanchored — use ``^…$`` for a full match).
    """

    fn: str
    arg: Ref | Elem
    value: Lit
    source: str  # raw text, for error messages


@dataclass(frozen=True, slots=True)
class Quant:
    """A quantifier over a list-valued operand — ``every`` / ``any``.

    ``ref`` is the collection (a :class:`Ref`, or :class:`Elem` when nested
    inside another quantifier); ``body`` is a sub-constraint evaluated with
    ``.`` bound to each element. ``every`` over an empty list is vacuously
    true; ``any`` over an empty list is false.
    """

    kind: str  # "every" | "any"
    ref: Ref | Elem
    body: Node
    source: str


@dataclass(frozen=True, slots=True)
class And:
    """Boolean AND of sub-constraints — all must hold."""

    parts: tuple["Node", ...]
    source: str


@dataclass(frozen=True, slots=True)
class Or:
    """Boolean OR of sub-constraints — at least one must hold."""

    parts: tuple["Node", ...]
    source: str


@dataclass(frozen=True, slots=True)
class Not:
    """Boolean negation of a sub-constraint."""

    inner: "Node"
    source: str


# The evaluator and Rego compiler dispatch on ``Node``.
Node = Cmp | Call | Quant | And | Or | Not
Constraint = Cmp  # back-compat alias for existing importers


_OP_TOKENS = ("<=", ">=", "==", "!=", "not in", "in", "<", ">")
_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z_0-9]*$")
_COUNT_RE = re.compile(r"^count\((.+)\)$")
_QUANT_RE = re.compile(r"^(every|any)\((.*)\)$", re.DOTALL)
_CONST_RE = re.compile(r"^consts\.([a-zA-Z_][a-zA-Z_0-9]*)$")
_ELEM_KEY = "$elem"
_CONSTS_KEY = "$consts"
_JSON_KEYWORDS = ("true", "false", "null")

_FUNCS = ("startswith", "endswith", "contains", "matches")
_FUNC_RE = re.compile(r"^([a-z]+)\((.*)\)$", re.DOTALL)
# RE2 (Go regexp, what Rego runs) lacks backreferences and lookaround; reject
# them so a pattern can't evaluate one way in pydantic (Python re) and another
# in a WASM bundle.
_RE2_INCOMPATIBLE = re.compile(r"\\[1-9]|\(\?[=!]|\(\?<[=!]")


def parse_constraint(source: str) -> Node:
    """Parse one constraint line into a :class:`Node`.

    Each side is an *operand*: a JSON literal, a field path (``args.amount``),
    ``count(<path>)``, or — inside a quantifier — the element ``.``. A path on
    the right is a cross-field comparison (``args.max >= args.min``). Raises
    :class:`ConstraintParseError` for unsupported operators, bad identifiers,
    malformed operands, or an element ref (``.``) used outside a quantifier.
    """
    node = _parse_node(source)
    _reject_unscoped_elem(node, source, in_quant=False)
    return node


def _parse_node(source: str) -> Node:
    """Parse a constraint into a node, without the top-level element-scope check
    (so quantifier bodies can recurse and use ``.`` freely)."""
    if not source.strip():
        raise ConstraintParseError("empty constraint")
    return _parse_expr(source, source)


def _parse_expr(text: str, source: str) -> Node:
    """``or_expr`` — the lowest-precedence level."""
    parts = _split_bool(text.strip(), "or")
    if len(parts) > 1:
        return Or(tuple(_parse_and_expr(p, source) for p in parts), source=text.strip())
    return _parse_and_expr(text, source)


def _parse_and_expr(text: str, source: str) -> Node:
    """``and_expr`` — binds tighter than ``or``."""
    parts = _split_bool(text.strip(), "and")
    if len(parts) > 1:
        return And(
            tuple(_parse_not_expr(p, source) for p in parts), source=text.strip()
        )
    return _parse_not_expr(text, source)


def _parse_not_expr(text: str, source: str) -> Node:
    """``not_expr`` — a leading ``not`` negates the rest; else a primary."""
    stripped = text.strip()
    if re.match(r"^not(\s|\()", stripped):
        return Not(_parse_not_expr(stripped[3:], source), source=stripped)
    return _parse_primary(stripped, source)


def _parse_primary(text: str, source: str) -> Node:
    """A parenthesised group, a quantifier, a function call, or a comparison."""
    text = text.strip()
    if not text:
        raise ConstraintParseError(f"empty sub-expression in {source!r}")
    if _is_wholly_parenthesized(text):
        return _parse_expr(text[1:-1], source)

    # A whole quantifier (every/any) or function call is a boolean on its own.
    quant = _try_parse_quant(text, source)
    if quant is not None:
        return quant
    call = _try_parse_call(text, source)
    if call is not None:
        return call

    # Find the first matching operator outside of any string literal. Operands
    # never contain a bare operator token (paths are identifiers, literals are
    # JSON), so a left-to-right scan is unambiguous.
    op, op_index = _find_operator(text)
    if op is None:
        raise ConstraintParseError(
            f"no recognised operator in {source!r}; "
            f"expected one of {', '.join(_OP_TOKENS)}"
        )

    lhs_raw = text[:op_index].rstrip()
    rhs_raw = text[op_index + len(op) :].lstrip()

    left = _parse_operand(lhs_raw, source, "left-hand side")
    right = _parse_operand(rhs_raw, source, "right-hand side")

    if op in ("in", "not in") and not (
        (isinstance(right, Lit) and isinstance(right.value, list))
        or isinstance(right, ConstRef)
    ):
        raise ConstraintParseError(
            f"{op!r} requires a list literal or consts.<name> on the right "
            f"in {source!r}"
        )

    return Cmp(left=left, op=op, right=right, source=source)


def _split_bool(text: str, keyword: str) -> list[str]:
    """Split ``text`` on top-level ``keyword`` (``and``/``or``) occurrences.

    Respects double-quoted strings and ``()``/``[]``/``{}`` nesting, and
    requires word boundaries so ``and``/``or`` inside identifiers (``args.brand``,
    ``args.order``) aren't split points. Returns a single-element list when the
    keyword doesn't appear at the top level.
    """
    parts: list[str] = []
    depth = 0
    in_string = escape = False
    start = i = 0
    n, klen = len(text), len(keyword)
    while i < n:
        ch = text[i]
        if escape:
            escape = False
        elif ch == "\\" and in_string:
            escape = True
        elif ch == '"':
            in_string = not in_string
        elif in_string:
            pass
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif (
            depth == 0
            and text.startswith(keyword, i)
            and (i == 0 or not _is_ident_char(text[i - 1]))
            and (i + klen == n or not _is_ident_char(text[i + klen]))
        ):
            parts.append(text[start:i])
            start = i = i + klen
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _is_wholly_parenthesized(text: str) -> bool:
    """True when the whole string is one ``(...)`` group (not e.g. ``(a) or (b)``)."""
    if not (text.startswith("(") and text.endswith(")")):
        return False
    depth = 0
    in_string = escape = False
    for i, ch in enumerate(text):
        if escape:
            escape = False
        elif ch == "\\" and in_string:
            escape = True
        elif ch == '"':
            in_string = not in_string
        elif in_string:
            pass
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(text) - 1:
                return False  # the opening paren closed before the end
    return depth == 0


def _parse_operand(text: str, source: str, side: str) -> Operand:
    """Parse one side of a comparison into an operand.

    Precedence: ``count(<path>)`` → a field path → a JSON literal. An
    identifier-shaped token (starts with a letter/underscore, not a JSON
    keyword) is read as a field reference so cross-field comparisons work;
    everything else is a JSON literal. A forgotten-quotes typo like
    ``== USD`` therefore becomes a reference to a (usually absent) field,
    which fails closed at evaluation rather than parsing.
    """
    text = text.strip()
    if not text:
        raise ConstraintParseError(f"missing {side} in {source!r}")

    # ``.`` / ``.field`` — the current quantifier element.
    if text.startswith("."):
        rest = text[1:]
        return Elem(_parse_path(rest, source)) if rest else Elem(())

    # ``consts.<name>`` — a named policy constant (reserved prefix).
    if text.startswith("consts."):
        m = _CONST_RE.match(text)
        if m is None:
            raise ConstraintParseError(
                f"invalid constant reference {text!r} in {source!r}"
            )
        return ConstRef(m.group(1))

    m = _COUNT_RE.match(text)
    if m:
        return Count(Ref(_parse_path(m.group(1).strip(), source)))

    if (text[0].isalpha() or text[0] == "_") and text not in _JSON_KEYWORDS:
        return Ref(_parse_path(text, source))

    try:
        return Lit(json.loads(text))
    except json.JSONDecodeError as exc:
        raise ConstraintParseError(
            f"{side} of {source!r} is not a valid JSON literal: {exc.msg}"
        ) from exc


def _try_parse_quant(text: str, source: str) -> Quant | None:
    """Parse a whole-line ``every(collection, condition)`` / ``any(...)``.

    Returns None when ``text`` isn't a quantifier. The collection is a path
    (or ``.field`` when nested); the condition is a full sub-constraint parsed
    recursively, with ``.`` bound to each element.
    """
    m = _QUANT_RE.match(text)
    if m is None:
        return None
    kind = m.group(1)
    ref_raw, sep, body_raw = m.group(2).partition(",")
    if not sep:
        raise ConstraintParseError(
            f"{kind}() expects 'collection, condition' arguments in {source!r}"
        )
    ref_text = ref_raw.strip()
    if ref_text.startswith("."):
        rest = ref_text[1:]
        ref: Ref | Elem = Elem(_parse_path(rest, source)) if rest else Elem(())
    else:
        ref = Ref(_parse_path(ref_text, source))
    body = _parse_node(body_raw)
    if _has_bool(body):
        raise ConstraintParseError(
            f"boolean composition (and/or/not) inside a quantifier body is not "
            f"supported yet, in {source!r}"
        )
    return Quant(kind=kind, ref=ref, body=body, source=source)


def _has_bool(node: Node) -> bool:
    """True if ``node`` contains a boolean node (And/Or/Not), looking through
    a nested quantifier body."""
    if isinstance(node, (And, Or, Not)):
        return True
    if isinstance(node, Quant):
        return _has_bool(node.body)
    return False


def _reject_unscoped_elem(node: Node, source: str, *, in_quant: bool) -> None:
    """Raise if an element ref (``.`` / ``.field``) appears outside a quantifier.

    ``.`` only means "the current element", so it's only valid inside a
    quantifier body (a quantifier's *collection* may be an element only when
    that quantifier is itself nested inside another).
    """

    def bad() -> None:
        raise ConstraintParseError(
            f"'.' element reference is only valid inside a quantifier, in {source!r}"
        )

    if isinstance(node, Quant):
        if isinstance(node.ref, Elem) and not in_quant:
            bad()
        _reject_unscoped_elem(node.body, source, in_quant=True)
    elif isinstance(node, Cmp):
        if not in_quant and (
            isinstance(node.left, Elem) or isinstance(node.right, Elem)
        ):
            bad()
    elif isinstance(node, Call):
        if not in_quant and isinstance(node.arg, Elem):
            bad()
    elif isinstance(node, And | Or):
        for part in node.parts:
            _reject_unscoped_elem(part, source, in_quant=in_quant)
    elif isinstance(node, Not):
        _reject_unscoped_elem(node.inner, source, in_quant=in_quant)


def _try_parse_call(text: str, source: str) -> Call | None:
    """Parse a whole-line ``fn(field, "literal")`` call, or return None.

    Returns None when ``text`` isn't a call to a known function, so the caller
    falls through to comparison parsing.
    """
    m = _FUNC_RE.match(text)
    if m is None or m.group(1) not in _FUNCS:
        return None
    fn = m.group(1)
    arg_raw, value_raw = _split_call_args(m.group(2), source, fn)
    arg = _parse_operand(arg_raw.strip(), source, f"{fn}() first argument")
    if not isinstance(arg, (Ref, Elem)):
        raise ConstraintParseError(
            f"{fn}() first argument must be a field path or '.' in {source!r}"
        )
    value = _parse_operand(value_raw.strip(), source, f"{fn}() second argument")
    if not isinstance(value, Lit) or not isinstance(value.value, str):
        raise ConstraintParseError(
            f"{fn}() requires a string literal as its second argument in {source!r}"
        )
    if fn == "matches":
        _validate_re2(value.value, source)
    return Call(fn=fn, arg=arg, value=value, source=source)


def _split_call_args(inner: str, source: str, fn: str) -> tuple[str, str]:
    """Split ``field, value`` on the first comma.

    The field is always a bare path (no comma), so the first comma is the
    separator; commas inside the value's string literal sit after it and are
    handled by the JSON parse of the value.
    """
    field, sep, value = inner.partition(",")
    if not sep:
        raise ConstraintParseError(
            f"{fn}() expects 'field, value' arguments in {source!r}"
        )
    return field, value


def _validate_re2(pattern: str, source: str) -> None:
    """Reject a regex that Python accepts but Rego's RE2 engine can't run."""
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ConstraintParseError(
            f"invalid regex {pattern!r} in {source!r}: {exc}"
        ) from exc
    if _RE2_INCOMPATIBLE.search(pattern):
        raise ConstraintParseError(
            f"regex {pattern!r} in {source!r} uses features RE2 does not support "
            "(backreferences or lookaround)"
        )


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


def _parse_path(text: str, source: str) -> tuple[str, ...]:
    """Parse a dotted field path into identifier segments (validated)."""
    if not text:
        raise ConstraintParseError(f"empty path in {source!r}")
    parts = text.split(".")
    for part in parts:
        if not _IDENT_RE.match(part):
            raise ConstraintParseError(f"invalid identifier {part!r} in {source!r}")
    return tuple(parts)


_MISSING = object()


def _walk(base: Any, path: tuple[str, ...]) -> Any:
    """Walk a dotted ``path`` from ``base``; ``_MISSING`` if any hop misses."""
    cursor: Any = base
    for part in path:
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        else:
            return _MISSING
    return cursor


def _resolve_path(path: tuple[str, ...], context: dict[str, Any]) -> Any:
    """Walk ``path`` over the evaluation ``context``."""
    return _walk(context, path)


def _resolve_operand(operand: Operand, context: dict[str, Any]) -> Any:
    """Resolve an operand to a concrete value (``_MISSING`` if a ref misses)."""
    if isinstance(operand, Lit):
        return operand.value
    if isinstance(operand, Count):
        seq = _resolve_path(operand.ref.path, context)
        # count() of a sized collection → len; anything else fails closed.
        return len(seq) if isinstance(seq, (list, str, dict)) else _MISSING
    if isinstance(operand, Elem):
        element = context.get(_ELEM_KEY, _MISSING)
        return _MISSING if element is _MISSING else _walk(element, operand.path)
    if isinstance(operand, ConstRef):
        consts = context.get(_CONSTS_KEY, {})
        return consts.get(operand.name, _MISSING)
    return _resolve_path(operand.path, context)


def _eval(node: Node, context: dict[str, Any]) -> bool:
    """Dispatch a node to its evaluator."""
    if isinstance(node, Cmp):
        return _eval_cmp(node, context)
    if isinstance(node, Call):
        return _eval_call(node, context)
    if isinstance(node, Quant):
        return _eval_quant(node, context)
    if isinstance(node, And):
        return all(_eval(p, context) for p in node.parts)
    if isinstance(node, Or):
        return any(_eval(p, context) for p in node.parts)
    if isinstance(node, Not):
        return not _eval(node.inner, context)
    raise ConstraintParseError(f"cannot evaluate node {node!r}")


def _eval_quant(node: Quant, context: dict[str, Any]) -> bool:
    """Evaluate a quantifier. Non-list collection fails closed.

    ``every`` over [] is vacuously true; ``any`` over [] is false — matching
    Rego's ``every`` / ``some``.
    """
    seq = _resolve_operand(node.ref, context)
    if not isinstance(seq, list):
        return False
    results = (_eval(node.body, {**context, _ELEM_KEY: el}) for el in seq)
    return all(results) if node.kind == "every" else any(results)


def _eval_call(node: Call, context: dict[str, Any]) -> bool:
    """Evaluate a string function. Non-string / missing target fails closed.

    ``matches`` uses ``re.search`` (unanchored) to mirror Rego's
    ``regex.match``; a full-string match needs explicit ``^…$`` anchors.
    """
    x = _resolve_operand(node.arg, context)
    if not isinstance(x, str):
        return False
    v = node.value.value
    if node.fn == "startswith":
        return x.startswith(v)
    if node.fn == "endswith":
        return x.endswith(v)
    if node.fn == "contains":
        return v in x
    if node.fn == "matches":
        return re.search(v, x) is not None
    return False  # unreachable given the _FUNCS whitelist


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
    *,
    role: str | None = None,
    consts: dict[str, Any] | None = None,
) -> None:
    """Evaluate every constraint; raise on the first failure.

    Caller passes raw source strings (typical YAML path) or pre-parsed
    nodes. Source strings are parsed once per call here for simplicity —
    caches can be added later if profiling demands it.

    ``role`` and the tool name are exposed to constraints as top-level
    ``role`` / ``tool`` facts, mirroring Rego's ``input.role`` / ``input.tool``.
    ``consts`` supplies the policy's named constants for ``consts.<name>``.
    """
    if not constraints:
        return
    context = {
        "args": dict(arguments or {}),
        "role": role,
        "tool": tool_name,
        _CONSTS_KEY: consts or {},
    }
    for entry in constraints:
        parsed = parse_constraint(entry) if isinstance(entry, str) else entry
        if not evaluate_constraint(parsed, context):
            raise PolicyDeniedError(
                f'Policy on "{tool_name}" denied: constraint failed — {parsed.source}'
            )
