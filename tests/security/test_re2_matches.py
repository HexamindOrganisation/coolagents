"""`matches` runs on RE2, the engine a compiled bundle already uses.

Rego evaluates `regex.match` with RE2. The pydantic engine used to evaluate the
same constraint with Python's `re`, so the two agreed only as far as a
hand-maintained list of Python features to avoid (`_RE2_INCOMPATIBLE`) went, and
they never agreed on *cost*: `re` backtracks, RE2 does not.

Running RE2 on both sides makes the agreement structural. This suite covers what
that buys, and the one place where behaviour changes.

The corpus below is adversarial on purpose: every pattern in `LINEAR_UNDER_RE2`
is one Python's engine takes exponential time on, so a regression to `re` would
not fail these tests subtly — it would hang them.
"""

from __future__ import annotations

import json
import time

import pytest

from hexgate.security.constraints import (
    ConstraintParseError,
    check_constraints,
    parse_constraint,
)
from hexgate.security.errors import PolicyDeniedError

# Patterns that send a backtracking engine exponential. Under `re`, deciding one
# call on a 28-character argument took 8.7s; the same pattern on RE2 is linear.
LINEAR_UNDER_RE2 = [
    "^(a+)+$",
    "^([a-z]+)*$",
    r"^(\d+)+$",
    "^([a-zA-Z0-9_-]+)*@corp[.]com$",
    "^(a|aa)+$",
    "^(a|a)+$",
    "^(ab|a|b)+$",
    "(x+x+)+y",
    "^(a*)*$",
    "^(a*)+$",
    "^([a-z]*)*$",
    r"^(\w+\s?)*$",
    "^(a{1,10}){1,10}$",
    "^a*a*a*$",  # polynomial rather than exponential, same conclusion
]

# Syntax RE2 has no equivalent for. RE2 itself is the judge now, which is why
# atomic groups and possessive quantifiers are on the list: they are undefined
# under RE2 and used to pass, because a source-text rule cannot tell `a*+` from
# `\++` (a repeated literal plus).
REFUSED_BY_RE2 = [
    r"(a)\1",  # backreference
    "(?=lookahead)",
    "(?<=lookbehind)",
    r"abc\Z",  # RE2 spells this \z
    "(?P<n>x)(?P=n)",  # named backreference
    "ab(?#comment)",
    "(a)(?(1)b)",  # conditional
    "(?>a+)+",  # atomic group
    "a*+",  # possessive quantifier
    "[unclosed",
]

# Ordinary patterns, including every `matches` pattern this repo ships.
ACCEPTED = [
    "^inv_[0-9]+$",
    "^INC-[0-9]+$",
    r"^\d+$",
    "[0-9]+",
    "^(web|api)-[a-z0-9]+$",
    r"^https://drive\.hexamind\.ai/",
    "(?P<n>[0-9]+)",  # a named group *definition* is fine under RE2
    "^([a-z0-9-]+[.])+corp[.]com$",
    "^[A-Z]{2,4}-[0-9]{1,6}$",
    r"^(\d{1,3}\.){3}\d{1,3}$",
    "^[a-f0-9]{64}$",
]


def _constraint(pattern: str) -> str:
    return f"matches(args.v, {json.dumps(pattern)})"


@pytest.mark.parametrize("pattern", LINEAR_UNDER_RE2)
def test_backtracking_patterns_are_decided_quickly(pattern: str) -> None:
    """A pattern that used to hang the engine now decides in milliseconds.

    The bound is deliberately loose (one second against a measured ~0.1ms) so
    the test asserts "linear time" rather than a machine-specific number. Under
    Python's `re` the same call does not finish: `^a*a*a*$` on this input took
    67s before, and `^(a+)+$` grows by a factor of four every two characters.
    """
    constraint = _constraint(pattern)
    parse_constraint(constraint)  # must load: the pattern is legal under RE2
    argument = "a" * 4000 + "!"
    started = time.perf_counter()
    try:
        check_constraints([constraint], {"v": argument}, "tool", role="support")
    except PolicyDeniedError:
        pass  # the verdict is beside the point here; the cost is what is tested
    assert time.perf_counter() - started < 1.0, pattern


@pytest.mark.parametrize("pattern", REFUSED_BY_RE2)
def test_syntax_re2_cannot_run_is_refused_at_load(pattern: str) -> None:
    # RE2 decides this, so the check cannot drift from the engine the way a
    # hand-maintained list of forbidden constructs did.
    with pytest.raises(ConstraintParseError, match="invalid regex"):
        parse_constraint(_constraint(pattern))


@pytest.mark.parametrize("pattern", ACCEPTED)
def test_ordinary_patterns_still_load(pattern: str) -> None:
    parse_constraint(_constraint(pattern))


def test_error_carries_re2s_own_reason_as_text() -> None:
    """The message must read, not print bytes.

    RE2 reports through the C++ layer, so the reason arrives as `bytes`;
    rendering the exception directly would put `b'missing ]'` in front of a
    policy author.
    """
    with pytest.raises(ConstraintParseError) as excinfo:
        parse_constraint(_constraint("[unclosed"))
    message = str(excinfo.value)
    assert "missing ]" in message
    assert "b'" not in message


def test_dollar_no_longer_matches_before_a_trailing_newline() -> None:
    """A behaviour change that closes a divergence rather than opening one.

    Python's `$` matches at the end of the string *or* just before a final
    newline; RE2's matches only at the end. So `^abc$` on `"abc\n"` was true on
    the pydantic engine and false in a compiled bundle — verified with
    `opa eval 'regex.match("^abc$", "abc\n")'`, which returns false. The two
    engines now agree.
    """
    constraint = _constraint("^abc$")
    with pytest.raises(PolicyDeniedError):
        check_constraints([constraint], {"v": "abc\n"}, "tool", role="support")
    check_constraints([constraint], {"v": "abc"}, "tool", role="support")


def test_ascii_classes_keep_their_meaning() -> None:
    # `re.ASCII` used to pin `\d` and `\w` to ASCII so Python would agree with
    # Rego. RE2 is ASCII for these by default, so the agreement now costs
    # nothing to maintain.
    digits = _constraint(r"^\d+$")
    check_constraints([digits], {"v": "123"}, "tool", role="support")
    with pytest.raises(PolicyDeniedError):
        check_constraints([digits], {"v": "١٢٣"}, "tool", role="support")


def test_an_invalid_pattern_is_an_error_not_a_silent_deny() -> None:
    """A typo must surface, not quietly refuse every call.

    RE2 can be built with error logging off, which also makes an invalid pattern
    compile into an object that simply never matches. That would turn a typo
    into a policy that denies everything for a reason nobody can see, so the
    default (raise) is what this code relies on.
    """
    with pytest.raises(ConstraintParseError):
        parse_constraint(_constraint("(unbalanced"))


def test_reason_falls_back_to_text_when_re2_reports_a_string() -> None:
    """The bytes decode has a fallback, and it should not rot untested.

    RE2 reports through the C++ layer, so today the reason always arrives as
    `bytes`. The binding is free to change that, and an error message is a bad
    place to discover a `TypeError`.
    """
    from hexgate.security.constraints import _re2_reason

    assert _re2_reason(ValueError(b"missing ]")) == "missing ]"  # today's shape
    assert _re2_reason(ValueError("missing ]")) == "missing ]"  # if it ever is str
    assert isinstance(_re2_reason(ValueError()), str)  # and never raises


def test_an_unencodable_argument_denies_instead_of_raising() -> None:
    """A tool argument that is not valid UTF-8 must fail closed.

    RE2 matches over UTF-8 bytes, and `json.loads` accepts strings that have no
    encoding: an emoji is a surrogate pair, and a truncated payload can deliver
    only its first half. Python's `re` evaluated such a value and the constraint
    failed; RE2 cannot encode it at all. The constraint must still deny rather
    than raise, since `evaluate_tool_call` only catches `PolicyDeniedError` and
    anything else escapes the enforcer.
    """
    lone_surrogate = chr(0xD83D)  # the first half of a surrogate pair
    args = json.loads(json.dumps({"ticket": "INC-42 " + lone_surrogate}))
    with pytest.raises(PolicyDeniedError):
        check_constraints(
            [_constraint("^INC-[0-9]+$")],
            {"v": args["ticket"]},
            "update_ticket",
            role="support",
        )


def test_an_unencodable_pattern_is_refused_at_load() -> None:
    # The same encoding limit on the pattern side is a malformed policy, not a
    # denial, so it belongs at load with the rest of the regex errors.
    with pytest.raises(ConstraintParseError, match="not valid UTF-8"):
        parse_constraint(_constraint("^INC-" + chr(0xD83D)))


def test_vertical_tab_is_not_whitespace_under_re2() -> None:
    """The second behaviour change, in the same direction as the `$` one.

    RE2 counts tab, newline, form feed, carriage return and space as
    whitespace; Python's ASCII class also counts the vertical tab. A pattern
    relying on the class therefore stops matching a vertical tab here -- and
    starts agreeing with the compiled bundle, which never matched it.

    Written with `chr` so the characters under test are unambiguous.
    """
    constraint = _constraint(r"^\s$")
    vertical_tab = chr(0x0B)
    with pytest.raises(PolicyDeniedError):
        check_constraints([constraint], {"v": vertical_tab}, "tool", role="support")
    for code in (0x09, 0x0A, 0x0C, 0x0D, 0x20):  # tab, LF, FF, CR, space
        check_constraints([constraint], {"v": chr(code)}, "tool", role="support")
