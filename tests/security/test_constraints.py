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
    And,
    Call,
    Cmp,
    ConstRef,
    ConstraintParseError,
    Count,
    Elem,
    Lit,
    Not,
    Or,
    Quant,
    Ref,
    check_constraints,
    evaluate_constraint,
    iter_cmp_operands,
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


def test_parse_string_literal_on_left() -> None:
    """A string literal may sit on the left — the operator scan must skip past
    it to find the real operator (not the ``==`` inside the string)."""
    node = parse_constraint('"a==b" == args.x')
    assert node.left == Lit("a==b")
    assert node.op == "=="
    assert node.right == Ref(("args", "x"))


def test_parse_string_literal_on_left_with_escaped_quote() -> None:
    node = parse_constraint(r'"a\"b" != args.x')
    assert node.left == Lit('a"b')
    assert node.op == "!="


def test_evaluate_string_literal_on_left() -> None:
    assert _eval('"USD" == args.currency', {"currency": "USD"}) is True
    assert _eval('"USD" == args.currency', {"currency": "EUR"}) is False


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


def test_backcompat_path_accessor_survives_pathless_left_operand() -> None:
    # count(...) / consts.x have no field path — the legacy `.path` accessor
    # must return () rather than raising AttributeError on new node kinds.
    assert parse_constraint("count(args.items) <= 3").path == ()
    assert parse_constraint("args.amount <= consts.max").path == ("args", "amount")


def test_node_is_frozen() -> None:
    node = parse_constraint("args.x == 1")
    with pytest.raises((AttributeError, TypeError)):
        node.op = "!="  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Cross-field references (2a) — a path on the right-hand side
# ---------------------------------------------------------------------------


def test_parse_cross_field_builds_ref_on_both_sides() -> None:
    node = parse_constraint("args.max >= args.min")
    assert isinstance(node.left, Ref) and node.left.path == ("args", "max")
    assert node.op == ">="
    assert isinstance(node.right, Ref) and node.right.path == ("args", "min")


def test_parse_bare_unquoted_word_is_rejected() -> None:
    """A forgotten-quotes typo (``== USD``) errors at load rather than parsing
    as a ref to an absent field ``USD`` (which would silently fail closed)."""
    with pytest.raises(ConstraintParseError, match="did you forget quotes"):
        parse_constraint("args.currency == USD")


def test_parse_bare_fact_identifier_is_allowed() -> None:
    """role / tool are the only valid bare (undotted) identifiers — as a fact on
    either side of a comparison."""
    node = parse_constraint("args.owner == role")
    assert isinstance(node.right, Ref) and node.right.path == ("role",)
    node2 = parse_constraint('role == "admin"')
    assert isinstance(node2.left, Ref) and node2.left.path == ("role",)


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        ("args.max >= args.min", {"max": 10, "min": 5}, True),
        ("args.max >= args.min", {"max": 5, "min": 5}, True),
        ("args.max >= args.min", {"max": 3, "min": 5}, False),
        ("args.a == args.b", {"a": "x", "b": "x"}, True),
        ("args.a == args.b", {"a": "x", "b": "y"}, False),
        ("args.max >= args.min", {"max": 10}, False),  # right ref missing
        ("args.max >= args.min", {"min": 5}, False),  # left ref missing
        ("args.max >= args.min", {}, False),  # both missing
    ],
)
def test_evaluate_cross_field(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


# ---------------------------------------------------------------------------
# count() operand (2d)
# ---------------------------------------------------------------------------


def test_parse_count_builds_count_operand() -> None:
    node = parse_constraint("count(args.recipients) <= 10")
    assert isinstance(node.left, Count)
    assert node.left.ref.path == ("args", "recipients")
    assert node.op == "<="
    assert node.right.value == 10


def test_parse_count_rejects_bad_inner_path() -> None:
    with pytest.raises(ConstraintParseError, match="invalid identifier"):
        parse_constraint("count(args.0bad) <= 3")


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        ("count(args.items) <= 3", {"items": [1, 2, 3]}, True),
        ("count(args.items) <= 3", {"items": [1, 2, 3, 4]}, False),
        ("count(args.items) <= 3", {"items": []}, True),  # empty → 0
        ("count(args.items) == 0", {"items": []}, True),
        ("count(args.items) <= 3", {}, False),  # missing → fail closed
        ("count(args.items) <= 3", {"items": 5}, False),  # not sized → fail closed
        ("count(args.name) <= 5", {"name": "abcd"}, True),  # string length
        ("count(args.a) >= count(args.b)", {"a": [1, 2], "b": [1]}, True),  # both count
    ],
)
def test_evaluate_count(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


# ---------------------------------------------------------------------------
# String functions (2b) — startswith / endswith / contains / matches
# ---------------------------------------------------------------------------


def test_parse_call_builds_call_node() -> None:
    node = parse_constraint('startswith(args.id, "inv_")')
    assert isinstance(node, Call)
    assert node.fn == "startswith"
    assert node.arg == Ref(("args", "id"))
    assert node.value == Lit("inv_")


def test_parse_call_string_arg_may_contain_comma_and_parens() -> None:
    node = parse_constraint('contains(args.s, "a, b (c)")')
    assert node.value == Lit("a, b (c)")


def test_parse_call_value_with_escaped_quote() -> None:
    """An escaped quote inside the function value is handled by the splitter."""
    node = parse_constraint(r'contains(args.s, "a\"b")')
    assert node.value == Lit('a"b')


@pytest.mark.parametrize("src", ["count( ) <= 1", 'startswith( , "x")'])
def test_parse_rejects_empty_field_path(src: str) -> None:
    with pytest.raises(ConstraintParseError):
        parse_constraint(src)


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        ('startswith(args.id, "inv_")', {"id": "inv_9"}, True),
        ('startswith(args.id, "inv_")', {"id": "x_inv_"}, False),
        ('startswith(args.id, "inv_")', {"id": 42}, False),  # non-string → closed
        ('startswith(args.id, "inv_")', {}, False),  # missing → closed
        ('endswith(args.f, ".md")', {"f": "notes.md"}, True),
        ('endswith(args.f, ".md")', {"f": "notes.txt"}, False),
        ('contains(args.s, "ab")', {"s": "xabx"}, True),
        ('contains(args.s, "ab")', {"s": "xyz"}, False),
        ('contains(args.s, "ab")', {"s": ["ab"]}, False),  # list ≠ string contains
        # matches is unanchored (re.search / regex.match)
        ('matches(args.v, "[0-9]+")', {"v": "abc123"}, True),
        ('matches(args.v, "[0-9]+")', {"v": "abc"}, False),
        ('matches(args.v, "^inv_[0-9]+$")', {"v": "inv_9"}, True),
        ('matches(args.v, "^inv_[0-9]+$")', {"v": "xinv_9"}, False),  # anchored
    ],
)
def test_evaluate_functions(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


@pytest.mark.parametrize(
    "src",
    [
        "startswith(args.id)",  # missing second arg
        "startswith(args.id, 5)",  # non-string literal
        'startswith(args.0bad, "x")',  # bad field path
        'matches(args.v, "(?=lookahead)")',  # RE2-incompatible lookaround
        r'matches(args.v, "(a)\1")',  # RE2-incompatible backreference
        'matches(args.v, "[unclosed")',  # invalid regex
        # These parse + match in Python re but are undefined under RE2 (verified
        # against `opa eval`) — must be rejected so the engines can't diverge.
        r'matches(args.v, "abc\\Z")',  # Python \Z end-anchor (RE2 uses \z)
        'matches(args.v, "(?P<n>x)(?P=n)")',  # named backreference
        'matches(args.v, "ab(?#comment)")',  # inline comment
        'matches(args.v, "(a)(?(1)b)")',  # conditional
    ],
)
def test_parse_rejects_bad_calls(src: str) -> None:
    with pytest.raises(ConstraintParseError):
        parse_constraint(src)


def test_matches_allows_re2_named_groups() -> None:
    # Named group *definitions* work on both Python re and RE2 (only the
    # backreference (?P=n) is RE2-incompatible) → must not be rejected.
    parse_constraint('matches(args.v, "(?P<n>[0-9]+)")')


# ---------------------------------------------------------------------------
# Quantifiers (2e) — every / any over list args
# ---------------------------------------------------------------------------


def test_parse_quantifier_builds_quant_node() -> None:
    node = parse_constraint('every(args.files, startswith(., "/tmp/"))')
    assert isinstance(node, Quant)
    assert node.kind == "every"
    assert node.ref == Ref(("args", "files"))
    assert isinstance(node.body, Call)
    assert node.body.arg == Elem(())  # "." → the element


def test_parse_quantifier_element_subfield() -> None:
    node = parse_constraint("every(args.items, .price <= 100)")
    assert node.body.left == Elem(("price",))
    assert node.body.op == "<="


def test_parse_nested_quantifier() -> None:
    node = parse_constraint('every(args.groups, any(.members, . == "admin"))')
    assert isinstance(node, Quant) and node.kind == "every"
    assert isinstance(node.body, Quant) and node.body.kind == "any"
    assert node.body.ref == Elem(("members",))  # nested collection is element-relative


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        (
            'every(args.files, startswith(., "/tmp/"))',
            {"files": ["/tmp/a", "/tmp/b"]},
            True,
        ),
        (
            'every(args.files, startswith(., "/tmp/"))',
            {"files": ["/tmp/a", "/etc/b"]},
            False,
        ),
        ('every(args.files, startswith(., "/tmp/"))', {"files": []}, True),  # vacuous
        (
            'every(args.files, startswith(., "/tmp/"))',
            {"files": "nope"},
            False,
        ),  # non-list
        ('every(args.files, startswith(., "/tmp/"))', {}, False),  # missing
        ('any(args.roles, . == "admin")', {"roles": ["user", "admin"]}, True),
        ('any(args.roles, . == "admin")', {"roles": ["user"]}, False),
        ('any(args.roles, . == "admin")', {"roles": []}, False),  # empty → false
        (
            "every(args.items, .price <= 100)",
            {"items": [{"price": 50}, {"price": 80}]},
            True,
        ),
        ("every(args.items, .price <= 100)", {"items": [{"price": 200}]}, False),
        (
            "every(args.items, .price <= 100)",
            {"items": [{"name": "x"}]},
            False,
        ),  # sub-field missing
        ("any(args.nums, . <= 10)", {"nums": [50, 5]}, True),
        (
            'every(args.groups, any(.members, . == "admin"))',
            {"groups": [{"members": ["a", "admin"]}, {"members": ["admin"]}]},
            True,
        ),
        (
            'every(args.groups, any(.members, . == "admin"))',
            {"groups": [{"members": ["a"]}, {"members": ["admin"]}]},
            False,
        ),
    ],
)
def test_evaluate_quantifier(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


@pytest.mark.parametrize(
    "src",
    [
        "every(args.files)",  # missing body
        "any(args.files)",  # missing body
        "every(args.0bad, . == 1)",  # bad collection path
        "every(args.files, startswith(., 5))",  # bad body (non-string fn arg)
        "every(args.files, . <=)",  # malformed body
    ],
)
def test_parse_rejects_bad_quantifiers(src: str) -> None:
    with pytest.raises(ConstraintParseError):
        parse_constraint(src)


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
        (".x == 5", "quantifier"),  # element ref only valid inside every/any
        ("args x == 5", "invalid identifier"),  # space in a path segment
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


def test_check_exposes_role_and_tool_as_facts() -> None:
    """role / tool are top-level facts, mirroring Rego's input.role / input.tool."""
    check_constraints(['role == "admin"'], {}, "any_tool", role="admin")  # passes
    with pytest.raises(PolicyDeniedError):
        check_constraints(['role == "admin"'], {}, "any_tool", role="user")
    check_constraints(['tool == "refund"'], {}, "refund", role="x")  # tool from name
    with pytest.raises(PolicyDeniedError):
        check_constraints(['tool == "refund"'], {}, "other", role="x")


def test_check_role_none_denies_role_constraint() -> None:
    with pytest.raises(PolicyDeniedError):
        check_constraints(['role == "admin"'], {}, "t", role=None)


# ---------------------------------------------------------------------------
# ctx.* — advisory ABAC attributes, mirroring Rego's input.ctx
# ---------------------------------------------------------------------------


def test_check_exposes_attributes_under_ctx_namespace() -> None:
    """ctx.<key> resolves against the attributes bag, like role/tool facts."""
    attrs = {"department": "finance", "clearance_level": 3}
    check_constraints(
        ['ctx.department == "finance"', "ctx.clearance_level >= 3"],
        {},
        "refund",
        attributes=attrs,
    )
    with pytest.raises(PolicyDeniedError, match="ctx.department"):
        check_constraints(
            ['ctx.department == "finance"'],
            {},
            "refund",
            attributes={"department": "sales"},
        )


def test_check_missing_ctx_attribute_fails_closed() -> None:
    """A ctx.* ref with no matching attribute denies, same as any missing ref."""
    with pytest.raises(PolicyDeniedError, match="ctx.department"):
        check_constraints(['ctx.department == "finance"'], {}, "refund", attributes={})


def test_check_no_attributes_bag_denies_ctx_constraint() -> None:
    """No attributes at all (None) → ctx.* fails closed."""
    with pytest.raises(PolicyDeniedError):
        check_constraints(['ctx.region in ["EU"]'], {}, "t", attributes=None)


def test_check_ctx_cross_type_ordered_fails_closed() -> None:
    """A string attribute against a numeric gate fails closed (no coercion)."""
    with pytest.raises(PolicyDeniedError):
        check_constraints(
            ["ctx.clearance_level >= 3"],
            {},
            "t",
            attributes={"clearance_level": "3"},
        )


def test_bare_ctx_identifier_is_rejected_at_parse() -> None:
    """``ctx`` alone is not a fact — only the dotted ``ctx.<key>`` form is valid."""
    with pytest.raises(ConstraintParseError):
        parse_constraint('ctx == "x"')


# ---------------------------------------------------------------------------
# run.* — the invocation's own fact record, mirroring Rego's input.run
# ---------------------------------------------------------------------------


def test_check_exposes_run_facts_under_run_namespace() -> None:
    run = {"agent": "billing", "tool_calls": 3, "elapsed_seconds": 12.5}
    check_constraints(
        ['run.agent == "billing"', "run.tool_calls < 20", "run.elapsed_seconds < 300"],
        {},
        "refund",
        run=run,
    )
    with pytest.raises(PolicyDeniedError, match="run.tool_calls"):
        check_constraints(["run.tool_calls < 3"], {}, "refund", run=run)


def test_check_missing_run_path_fails_closed() -> None:
    """A ``run.*`` ref the namespace does not carry denies, same as any missing
    ref. This is why the SDK passes the detached record's zeros rather than
    nothing when a decision happens outside a run scope."""
    with pytest.raises(PolicyDeniedError, match="run.tool_calls"):
        check_constraints(["run.tool_calls < 20"], {}, "refund", run={"agent": "a"})


def test_check_no_run_namespace_denies_run_constraint() -> None:
    with pytest.raises(PolicyDeniedError):
        check_constraints(["run.tool_calls < 20"], {}, "t", run=None)


def test_check_run_cross_type_ordered_fails_closed() -> None:
    """A stringly-typed counter against a numeric gate fails closed, matching
    the WASM engine's type guard."""
    with pytest.raises(PolicyDeniedError):
        check_constraints(["run.tool_calls < 20"], {}, "t", run={"tool_calls": "3"})


def test_check_run_list_path_supports_count_and_quantifiers() -> None:
    """The three shapes the load-time linter leaves alone — and the only
    correct ways to read a list-valued path."""
    run = {"tools_used": ["shell", "search"]}
    check_constraints(["count(run.tools_used) <= 6"], {}, "t", run=run)
    check_constraints(['any(run.tools_used, . == "shell")'], {}, "t", run=run)
    check_constraints(['every(run.tools_used, . != "delete")'], {}, "t", run=run)


def test_run_list_path_with_not_in_silently_passes() -> None:
    """The footgun the linter exists to reject, pinned as behaviour: ``not in``
    asks whether the *left* value is an element of the right list, and a list is
    never an element of a list of strings — so the exclusion never fires. If
    this ever starts raising, the linter's Rule C can be dropped."""
    check_constraints(
        ['run.tools_used not in ["shell"]'],
        {},
        "t",
        run={"tools_used": ["shell"]},
    )


def test_bare_run_identifier_is_rejected_at_parse() -> None:
    """``run`` alone is not a fact — only the dotted ``run.<name>`` form is
    valid. The load-time linter relies on this: it only checks depth 2 and up."""
    with pytest.raises(ConstraintParseError):
        parse_constraint('run == "x"')


def test_membership_against_a_run_ref_is_rejected_at_parse() -> None:
    """``"shell" in run.tools_used`` reads naturally but the grammar requires a
    literal or a const on the right of ``in``. Pinned so the linter's Rule C can
    keep assuming a list-valued ref only ever appears on the left."""
    with pytest.raises(ConstraintParseError, match="list literal"):
        parse_constraint('"shell" in run.tools_used')


# ---------------------------------------------------------------------------
# Named constants (2f) — consts.<name>
# ---------------------------------------------------------------------------


def test_parse_const_ref() -> None:
    assert parse_constraint("args.amount <= consts.max_refund").right == ConstRef(
        "max_refund"
    )


def test_parse_const_ref_on_in_rhs() -> None:
    node = parse_constraint("args.repo in consts.repos")
    assert node.op == "in"
    assert node.right == ConstRef("repos")


@pytest.mark.parametrize("src", ["args.x == consts.", "args.x == consts.a.b"])
def test_parse_rejects_bad_const_ref(src: str) -> None:
    with pytest.raises(ConstraintParseError):
        parse_constraint(src)


def test_check_resolves_consts() -> None:
    check_constraints(
        ["args.amount <= consts.cap"], {"amount": 100}, "t", consts={"cap": 500}
    )
    with pytest.raises(PolicyDeniedError):
        check_constraints(
            ["args.amount <= consts.cap"], {"amount": 999}, "t", consts={"cap": 500}
        )


def test_check_const_membership() -> None:
    check_constraints(
        ["args.repo in consts.repos"], {"repo": "a"}, "t", consts={"repos": ["a", "b"]}
    )
    with pytest.raises(PolicyDeniedError):
        check_constraints(
            ["args.repo in consts.repos"], {"repo": "z"}, "t", consts={"repos": ["a"]}
        )


def test_check_unknown_const_denies() -> None:
    # Missing const → fails closed (the WASM compiler rejects it loudly).
    with pytest.raises(PolicyDeniedError):
        check_constraints(["args.x == consts.nope"], {"x": 1}, "t", consts={})


# ---------------------------------------------------------------------------
# Boolean composition (2c) — or / and / not / grouping
# ---------------------------------------------------------------------------


def test_parse_or_and_not_structure() -> None:
    assert isinstance(parse_constraint("args.a == 1 or args.b == 2"), Or)
    assert isinstance(parse_constraint("args.a == 1 and args.b == 2"), And)
    assert isinstance(parse_constraint("not args.a == 1"), Not)


def test_parse_precedence_or_binds_loosest() -> None:
    # A or B and C  ==  A or (B and C)
    node = parse_constraint("args.a == 1 or args.b == 2 and args.c == 3")
    assert isinstance(node, Or)
    assert isinstance(node.parts[1], And)


def test_parse_parens_override_precedence() -> None:
    node = parse_constraint("(args.a == 1 or args.b == 2) and args.c == 3")
    assert isinstance(node, And)
    assert isinstance(node.parts[0], Or)


def test_parse_and_or_not_matched_inside_identifiers() -> None:
    # "and"/"or" inside field names must not be split points.
    assert isinstance(parse_constraint("args.brand == 1 or args.order == 2"), Or)
    assert isinstance(parse_constraint("args.brand == 1"), Cmp)


@pytest.mark.parametrize(
    ("src", "args", "expected"),
    [
        ("args.a == 1 or args.b == 2", {"a": 1, "b": 9}, True),
        ("args.a == 1 or args.b == 2", {"a": 9, "b": 2}, True),
        ("args.a == 1 or args.b == 2", {"a": 9, "b": 9}, False),
        ("args.a == 1 and args.b == 2", {"a": 1, "b": 2}, True),
        ("args.a == 1 and args.b == 2", {"a": 1, "b": 9}, False),
        # precedence: A or (B and C)
        ("args.a==1 or args.b==2 and args.c==3", {"a": 1, "b": 9, "c": 9}, True),
        ("args.a==1 or args.b==2 and args.c==3", {"a": 9, "b": 2, "c": 9}, False),
        # grouping
        ("(args.a==1 or args.b==2) and args.c==3", {"a": 1, "b": 9, "c": 3}, True),
        ("(args.a==1 or args.b==2) and args.c==3", {"a": 1, "b": 9, "c": 9}, False),
        # not + De Morgan
        ("not args.a == 1", {"a": 2}, True),
        ("not args.a == 1", {"a": 1}, False),
        ("not (args.a==1 or args.b==2)", {"a": 9, "b": 9}, True),
        ("not (args.a==1 or args.b==2)", {"a": 1, "b": 9}, False),
        # not with a not-in comparison inside
        ("not args.x not in [1, 2]", {"x": 1}, True),
    ],
)
def test_evaluate_boolean(src: str, args: dict, expected: bool) -> None:
    assert _eval(src, args) is expected


def test_parse_rejects_bool_inside_quantifier_body() -> None:
    # Deferred: boolean composition inside a quantifier body (both engines).
    with pytest.raises(ConstraintParseError, match="quantifier body"):
        parse_constraint("every(args.items, .a == 1 or .b == 2)")


# ---------------------------------------------------------------------------
# iter_cmp_operands — operator + side, which iter_arg_refs discards
# ---------------------------------------------------------------------------


def test_iter_cmp_operands_yields_both_sides_with_the_operator() -> None:
    node = parse_constraint("args.max >= args.min")
    assert [(op, side) for _, op, side in iter_cmp_operands(node)] == [
        (">=", "left"),
        (">=", "right"),
    ]


def test_iter_cmp_operands_keeps_count_wrapped() -> None:
    """The reason this exists: ``iter_arg_refs`` unwraps ``Count`` to the inner
    path, so a caller cannot tell the legitimate ``count(x) <= 6`` from the
    silently-wrong ``x <= 6`` when ``x`` is list-valued."""
    (left, _, _), _ = iter_cmp_operands(parse_constraint("count(args.files) <= 6"))
    assert isinstance(left, Count)


def test_iter_cmp_operands_skips_a_quantifier_collection_but_walks_its_body() -> None:
    """A quantifier's collection is required to be a list, so it is never in a
    scalar position; only its body carries comparisons."""
    operands = list(iter_cmp_operands(parse_constraint("every(args.items, .n <= 5)")))
    assert [op for _, op, _ in operands] == ["<=", "<="]
    assert all(
        not isinstance(o, Ref) or o.path != ("args", "items") for o, _, _ in operands
    )


def test_iter_cmp_operands_recurses_through_boolean_composition() -> None:
    node = parse_constraint("not (args.a == 1 or args.b <= 2)")
    assert {op for _, op, _ in iter_cmp_operands(node)} == {"==", "<="}


def test_iter_cmp_operands_yields_nothing_for_a_string_call() -> None:
    """``startswith(args.p, "src/")`` takes a single typed argument, not a
    comparison pair — so there is no scalar position to police."""
    assert not list(iter_cmp_operands(parse_constraint('startswith(args.p, "src/")')))
