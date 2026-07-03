"""Adversarial tests for the constraint grammar — parser, AST, evaluator, check.

The grammar is a security surface: a parser bug is a policy bypass or a crash
at enforcement time. So this suite is deliberately exhaustive —

  * operator recognition + disambiguation (``<=`` vs ``<``, ``not in`` vs ``in``,
    word boundaries so ``args.min`` isn't read as ``in``),
  * every literal type the RHS accepts, including strings that *contain*
    operators,
  * whitespace tolerance,
  * a wide battery of malformed inputs that must raise ``ConstraintParseError``
    and never any other exception ("no-crash" guarantee),
  * evaluator truth tables across types + fail-closed edges (missing path,
    type mismatch, non-dict traversal),
  * the ``check_constraints`` caller surface (AND semantics, short-circuit,
    pre-parsed nodes, ``None`` args).
"""

from __future__ import annotations

import pytest

from hexgate.security import PolicyDeniedError
from hexgate.security.constraints import (
    Cmp,
    ConstraintParseError,
    Lit,
    Ref,
    check_constraints,
    evaluate_constraint,
    parse_constraint,
)


def _eval(src: str, args: dict) -> bool:
    return evaluate_constraint(parse_constraint(src), {"args": args})


# ---------------------------------------------------------------------------
# Operator recognition + disambiguation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "op"),
    [
        ("args.x == 1", "=="),
        ("args.x != 1", "!="),
        ("args.x < 1", "<"),
        ("args.x <= 1", "<="),
        ("args.x > 1", ">"),
        ("args.x >= 1", ">="),
        ("args.x in [1]", "in"),
        ("args.x not in [1]", "not in"),
    ],
)
def test_parse_recognises_every_operator(src: str, op: str) -> None:
    assert parse_constraint(src).op == op


@pytest.mark.parametrize(
    ("src", "op"),
    [
        ("args.x <= 1", "<="),  # not "<"
        ("args.x >= 1", ">="),  # not ">"
        ("args.x != 1", "!="),
        ("args.x < 1", "<"),
        ("args.x > 1", ">"),
        ("args.x not in [1]", "not in"),  # not "in"
    ],
)
def test_parse_operator_disambiguation(src: str, op: str) -> None:
    """Two-char / two-word operators win over their single prefixes."""
    assert parse_constraint(src).op == op


@pytest.mark.parametrize(
    "src",
    [
        "args.min == 1",  # "in" inside an identifier
        "args.within == 1",
        "args.invalid == 1",
        "args.coin >= 1",
        "args.integer <= 1",
        "args.bin != 1",
    ],
)
def test_parse_in_not_matched_inside_identifiers(src: str) -> None:
    """``in`` requires word boundaries — it must not fire inside a field name."""
    assert parse_constraint(src).op != "in"


@pytest.mark.parametrize(
    "src",
    [
        "args.x<=1",
        "args.x==1",
        "args.x !=1",
        "args.x>= 1",
        "args.x<1",
        "args.x   <=   1",
        "  args.x <= 1  ",
        "args.x in[1]",
    ],
)
def test_parse_whitespace_tolerance(src: str) -> None:
    """Spacing around the operator is optional / flexible."""
    parse_constraint(src)  # must not raise


def test_parse_source_preserved_verbatim() -> None:
    """The node keeps the original text (spaces included) for error messages."""
    raw = "  args.x   <=   5 "
    assert parse_constraint(raw).source == raw


# ---------------------------------------------------------------------------
# Literal (RHS) parsing — every value type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "value"),
    [
        ("args.x == 5", 5),
        ("args.x == -5", -5),
        ("args.x == 0", 0),
        ("args.x == 5.5", 5.5),
        ("args.x == -5.5", -5.5),
        ("args.x == 1e3", 1000.0),
        ('args.x == "hi"', "hi"),
        ('args.x == ""', ""),
        ('args.x == "hello world"', "hello world"),
        ('args.x == "a\\"b"', 'a"b'),  # escaped double-quote inside string
        ('args.x == "café ☕"', "café ☕"),  # unicode
        ("args.x == true", True),
        ("args.x == false", False),
        ("args.x == null", None),
        ("args.x in []", []),
        ("args.x in [1]", [1]),
        ('args.x in [1, "a", true, null]', [1, "a", True, None]),
        ('args.x in ["a,b", "c in d"]', ["a,b", "c in d"]),  # commas/ops in strings
    ],
)
def test_parse_literal_types(src: str, value: object) -> None:
    node = parse_constraint(src)
    assert node.value == value
    assert type(node.value) is type(value)  # 5 vs 5.0, True vs 1


@pytest.mark.parametrize(
    ("src", "value"),
    [
        ('args.name == "a <= b"', "a <= b"),  # operator chars inside string
        ('args.name == ">="', ">="),
        ('args.name == "=="', "=="),
        ('args.name == "in"', "in"),
        ('args.name == "not in"', "not in"),
        ('args.name != "a != b"', "a != b"),
    ],
)
def test_parse_operators_inside_string_literals(src: str, value: str) -> None:
    """The first operator *outside* a string wins; ops inside quotes are data."""
    assert parse_constraint(src).value == value


# ---------------------------------------------------------------------------
# Path parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "path"),
    [
        ("args.x == 1", ("args", "x")),
        ("role == 1", ("role",)),  # single segment is legal grammar
        ("args.a.b.c.d == 1", ("args", "a", "b", "c", "d")),
        ("args.my_field == 1", ("args", "my_field")),
        ("args._x == 1", ("args", "_x")),
        ("args.field2 == 1", ("args", "field2")),
        ("args.x1y == 1", ("args", "x1y")),
    ],
)
def test_parse_paths(src: str, path: tuple[str, ...]) -> None:
    assert parse_constraint(src).path == path


# ---------------------------------------------------------------------------
# AST node shape (PR 1 operand model)
# ---------------------------------------------------------------------------


def test_parse_builds_cmp_of_ref_and_lit() -> None:
    node = parse_constraint("args.payment.amount <= 100")
    assert isinstance(node, Cmp)
    assert isinstance(node.left, Ref)
    assert node.left.path == ("args", "payment", "amount")
    assert node.op == "<="
    assert isinstance(node.right, Lit)
    assert node.right.value == 100


def test_backcompat_accessors_match_operands() -> None:
    node = parse_constraint('args.currency in ["USD", "EUR"]')
    assert node.path == node.left.path
    assert node.value == node.right.value


def test_node_is_frozen() -> None:
    node = parse_constraint("args.x == 1")
    with pytest.raises((AttributeError, TypeError)):
        node.op = "!="  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Malformed input — must raise ConstraintParseError (never another exception)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "match"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("args.amount", "no recognised operator"),
        ("args.amount ~~ 50", "no recognised operator"),
        ("== 5", "left-hand side"),
        ("<= 5", "left-hand side"),
        ("args.amount <=", "right-hand side"),
        ("args.amount <= ", "right-hand side"),
        ("args.0bad <= 50", "invalid identifier"),
        ("args. == 5", "invalid identifier"),
        ("args..x == 5", "invalid identifier"),
        (".x == 5", "invalid identifier"),
        ("args x == 5", "invalid identifier"),  # space in a path segment
        ("args.x == USD", "JSON literal"),  # unquoted string
        ("args.x == 'single'", "JSON literal"),  # single quotes
        ("args.x == 5x", "JSON literal"),
        ("args.x == [1, 2", "JSON literal"),  # unterminated list
        ('args.x == "unterminated', "JSON literal"),
        ("args.x in 5", "requires a list"),
        ('args.x in "str"', "requires a list"),
        ("args.x not in 42", "requires a list"),
    ],
)
def test_parse_rejects_malformed(src: str, match: str) -> None:
    with pytest.raises(ConstraintParseError, match=match):
        parse_constraint(src)


@pytest.mark.parametrize(
    "src",
    [
        "",
        " ",
        "\t\n",
        "==",
        "in",
        "not in",
        "args.x ==",
        "args.x == == 5",
        "args.x <= <= 5",
        'args.x == "no close',
        "args.x == [",
        "args.x == ]",
        "args.x in in [1]",
        "args.x not  in [1]",  # double space breaks the two-word operator
        "😀 == 1",
        "args.x == 😀",
        "args.x == {",
        "1 == 2",
        "() == 1",
        "a" * 5000 + " == 1",
        "args.x == " + "9" * 400,  # huge number literal
        "args.\tx == 1",
        "args.x\n== 1",
    ],
)
def test_parse_never_crashes(src: str) -> None:
    """Fuzz-ish battery: any input either parses or raises ConstraintParseError.

    No IndexError / ValueError / TypeError / recursion may escape — the parser
    must be total over arbitrary strings (this is the "sans-faute" guarantee).
    """
    try:
        parse_constraint(src)
    except ConstraintParseError:
        pass  # acceptable, expected failure mode
    except Exception as exc:  # pragma: no cover - this failing IS the bug
        pytest.fail(f"parse_constraint({src!r}) raised {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# Evaluator — operator truth tables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        # numeric comparisons at + around the boundary
        ("args.x <= 50", {"x": 49}, True),
        ("args.x <= 50", {"x": 50}, True),
        ("args.x <= 50", {"x": 51}, False),
        ("args.x < 50", {"x": 50}, False),
        ("args.x < 50", {"x": 49}, True),
        ("args.x >= 50", {"x": 50}, True),
        ("args.x >= 50", {"x": 49}, False),
        ("args.x > 50", {"x": 50}, False),
        ("args.x == 50", {"x": 50}, True),
        ("args.x != 50", {"x": 51}, True),
        # int / float equivalence
        ("args.x == 5", {"x": 5.0}, True),
        ("args.x <= 5", {"x": 5.0}, True),
        ("args.x == 5.0", {"x": 5}, True),
        # negatives
        ("args.x >= -5", {"x": -5}, True),
        ("args.x < -5", {"x": -6}, True),
        # strings
        ('args.x == "USD"', {"x": "USD"}, True),
        ('args.x == "USD"', {"x": "usd"}, False),  # case sensitive
        ('args.x != "USD"', {"x": "EUR"}, True),
        ('args.x < "b"', {"x": "a"}, True),  # lexicographic
        # booleans
        ("args.x == true", {"x": True}, True),
        ("args.x == false", {"x": True}, False),
        ("args.x != false", {"x": True}, True),
        # null
        ("args.x == null", {"x": None}, True),
        ("args.x == null", {"x": 0}, False),
        ("args.x != null", {"x": 1}, True),
        # membership
        ('args.x in ["a", "b"]', {"x": "a"}, True),
        ('args.x in ["a", "b"]', {"x": "c"}, False),
        ("args.x in [1, 2, 3]", {"x": 2}, True),
        ('args.x in [1, "a", true]', {"x": True}, True),
        ("args.x in []", {"x": 1}, False),  # empty set → nothing matches
        ('args.x not in ["urgent"]', {"x": "low"}, True),
        ('args.x not in ["urgent"]', {"x": "urgent"}, False),
        ("args.x not in []", {"x": 1}, True),  # empty set → everything passes
        # actual value is itself a list (membership of a list in a list-of-lists)
        ("args.tags in [[1, 2], [3]]", {"tags": [1, 2]}, True),
    ],
)
def test_evaluate_truth_table(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


# ---------------------------------------------------------------------------
# Evaluator — fail-closed edges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("src", "args"),
    [
        ("args.amount <= 50", {}),  # arg absent entirely
        ("args.a.b <= 5", {"a": {}}),  # nested arg absent
        ("args.a.b <= 5", {}),  # whole branch absent
        ("args.a.b <= 5", {"a": 5}),  # non-dict mid-path (5 has no "b")
        ("args.a.b <= 5", {"a": None}),  # None mid-path
        ("args.a.b <= 5", {"a": [1, 2]}),  # list mid-path (no str keys)
    ],
)
def test_evaluate_missing_or_untraversable_path_denies(src: str, args: dict) -> None:
    assert _eval(src, args) is False


@pytest.mark.parametrize(
    ("src", "args"),
    [
        ("args.x <= 50", {"x": "fifty"}),  # str vs int
        ("args.x <= 50", {"x": None}),  # None vs int
        ("args.x <= 50", {"x": [1]}),  # list vs int
        ("args.x < 50", {"x": {"n": 1}}),  # dict vs int
        ('args.x < "b"', {"x": 5}),  # int vs str
    ],
)
def test_evaluate_type_mismatch_fails_closed(src: str, args: dict) -> None:
    """Ordered comparisons across incompatible types must deny, never raise."""
    assert _eval(src, args) is False


def test_evaluate_equality_never_raises_on_odd_types() -> None:
    """== / != tolerate any operand types without raising."""
    assert _eval("args.x == 5", {"x": {"nested": 1}}) is False
    assert _eval("args.x != 5", {"x": [1, 2, 3]}) is True


def test_evaluate_deep_path_present() -> None:
    assert _eval("args.a.b.c <= 5", {"a": {"b": {"c": 3}}}) is True
    assert _eval("args.a.b.c <= 5", {"a": {"b": {"c": 9}}}) is False


# ---------------------------------------------------------------------------
# check_constraints — caller surface (AND semantics, short-circuit, inputs)
# ---------------------------------------------------------------------------


def test_check_empty_is_noop() -> None:
    check_constraints([], None, "any_tool")
    check_constraints([], {}, "any_tool")


def test_check_all_satisfied_returns_silently() -> None:
    check_constraints(
        ["args.amount <= 50", 'args.currency == "USD"'],
        {"amount": 30, "currency": "USD"},
        "refund",
    )


def test_check_is_implicit_and_first_failure_raises() -> None:
    with pytest.raises(PolicyDeniedError, match="args.currency"):
        check_constraints(
            ["args.amount <= 50", 'args.currency == "USD"'],
            {"amount": 30, "currency": "EUR"},  # second constraint fails
            "refund",
        )


def test_check_short_circuits_before_parsing_later_entries() -> None:
    """A failing early constraint raises before a later (garbage) one is parsed."""
    with pytest.raises(PolicyDeniedError, match="args.amount <= 50"):
        check_constraints(
            ["args.amount <= 50", "THIS WOULD NOT PARSE"],
            {"amount": 999},
            "refund",
        )


def test_check_none_args_denies_arg_constraints() -> None:
    """No arguments at all → an arg constraint fails closed (raises)."""
    with pytest.raises(PolicyDeniedError):
        check_constraints(["args.amount <= 50"], None, "refund")


def test_check_accepts_pre_parsed_nodes_and_strings_mixed() -> None:
    parsed = parse_constraint("args.amount <= 50")
    check_constraints(
        [parsed, 'args.currency == "USD"'],
        {"amount": 10, "currency": "USD"},
        "refund",
    )


def test_check_error_message_carries_verbatim_source() -> None:
    raw = "args.amount   <=   50"  # unusual spacing preserved in the message
    with pytest.raises(PolicyDeniedError, match="args.amount   <=   50"):
        check_constraints([raw], {"amount": 999}, "refund")
