"""Exponential-ambiguity detection — the linear-time half of RE2 parity.

``_validate_re2`` keeps a policy's regexes to syntax RE2 can run. This suite
covers the other half: a pattern both engines accept but only one of them
finishes. The evaluator matches with ``re.search`` (backtracking) while a WASM
bundle runs RE2 (linear), so an exponentially ambiguous pattern hangs the engine
that decides whether a tool call is allowed — on arguments a model writes.

Both error directions are covered, because both are expensive:

  * a **miss** leaves the hang in place, so every blow-up shape is here (nested
    quantifier, ambiguous alternation, nullable loop body, and the "two epsilon
    routes to the same edge" case a syntactic rule cannot see);
  * a **false alarm** refuses a policy that was always fine, so the linear
    corpus holds every ``matches`` pattern this repo ships plus the shapes a
    naive "nested quantifier" rule would wrongly reject — above all
    ``^([a-z0-9-]+[.])+corp[.]com$``, which is nested *and* linear because the
    mandatory ``[.]`` forces one split per iteration.
"""

from __future__ import annotations

import json
import re

import pytest

from hexgate.security.constraints import ConstraintParseError, parse_constraint
from hexgate.security.regex_safety import (
    AmbiguityWitness,
    UnsupportedRegex,
    find_exponential_ambiguity,
)

# Each entry blows up for a different reason, so a detector that special-cases
# one shape fails the rest.
EXPONENTIAL = [
    "^(a+)+$",  # the textbook nested quantifier
    "^([a-z]+)*$",  # star of plus
    r"^(\d+)+$",  # the same, over a category
    "^([a-zA-Z0-9_-]+)*@corp[.]com$",  # a plausible email allowlist
    "^(a|aa)+$",  # branches that overlap
    "^(a|a)+$",  # duplicated branches: one word, two edges
    "^(ab|a|b)+$",  # branches overlapping after one char
    "(x+x+)+y",  # two inner loops sharing an alphabet
    "^(a*)*$",  # nullable body, iterations of any length
    "^(_?/*)*$",  # the same, spelled less obviously
    "^(a*)+$",
    "^([a-z]*)*$",
    r"^(\w+\s?)*$",  # trailing optional frees the seam
    "^([^,]+)+$",  # a negated class, the shape a CSV-ish rule reaches for
]

# Must keep working. First block: every ``matches`` pattern the repo ships
# (docs, tests, examples). Second: shapes a syntactic rule would wrongly reject.
LINEAR = [
    "^inv_[0-9]+$",
    "^INC-[0-9]+$",
    r"^\d+$",
    "[0-9]+",
    "^(web|api)-[a-z0-9]+$",
    r"^https://drive\.hexamind\.ai/",
    "(?P<n>[0-9]+)",
    "^([a-z0-9-]+[.])+corp[.]com$",  # nested, but each iteration is forced
    "^[a-z]+(_[a-z]+)*$",
    "^(/[a-z]+)+/data$",
    "^v[0-9]+([.][0-9]+)*$",
    "^(foo|bar)+$",
    "^(?:abc)+$",
    "^(a?b)*$",
    "^a{2,4}$",
    "^[A-Z]{2,4}-[0-9]{1,6}$",
    "^[a-f0-9]{64}$",
    "^[a-z]*[0-9]*$",
    "^[a-z]+@[a-z]+[.]com$",
    "^/api/v[0-9]+/[a-z]+$",
    r"^\w+$",
    # An epsilon cycle is not enough on its own: every iteration of `(a?)+`
    # matches exactly one character, so there is only one way to split the
    # input and the empty iterations are pruned. Contrast `^(a*)*$` above,
    # where an iteration can absorb one character or several.
    "^(a?)+$",
    "^(x?)+$",
    "^(a?b?)+$",
    # Wildcards and negated classes are ordinary policy material; only the
    # nested forms above are a problem.
    "^.+$",
    "^.*x$",
    "^[^,]+$",
    "^([^,]+,)+[^,]+$",  # forced by the mandatory comma, like the domain case
]


def _constraint(pattern: str) -> str:
    """The constraint line carrying ``pattern``, escaped as the grammar wants."""
    return f"matches(args.v, {json.dumps(pattern)})"


@pytest.mark.parametrize("pattern", EXPONENTIAL)
def test_exponential_patterns_are_detected(pattern: str) -> None:
    witness = find_exponential_ambiguity(pattern)
    assert isinstance(witness, AmbiguityWitness), pattern
    assert witness.pump, "a witness must name the segment that can be split"


@pytest.mark.parametrize("pattern", LINEAR)
def test_linear_patterns_are_not_flagged(pattern: str) -> None:
    # A false alarm refuses a policy that was always fine, so this is the more
    # important half of the suite.
    assert find_exponential_ambiguity(pattern) is False, pattern


@pytest.mark.parametrize("pattern", EXPONENTIAL)
def test_witness_example_is_a_failing_match(pattern: str) -> None:
    """The reported string must be one the engine cannot match.

    A witness that matched would return on the first success and demonstrate
    nothing; a failing match is what obliges the engine to work through the
    combinations. Wall-clock assertions would be flaky in CI, and the witness is
    deliberately not claimed to be the worst input for the pattern (see
    :class:`AmbiguityWitness`), so the assertion is the structural property the
    example is built to have.
    """
    witness = find_exponential_ambiguity(pattern)
    assert isinstance(witness, AmbiguityWitness)
    assert witness.pump in witness.example
    assert re.compile(pattern, re.ASCII).search(witness.example) is None, pattern


@pytest.mark.parametrize("pattern", EXPONENTIAL)
def test_policy_load_refuses_exponential_regex(pattern: str) -> None:
    # End-to-end contract: such a policy never loads, so it cannot reach a
    # deployment where one engine hangs and the other does not.
    with pytest.raises(ConstraintParseError, match="backtrack exponentially"):
        parse_constraint(_constraint(pattern))


@pytest.mark.parametrize("pattern", LINEAR)
def test_policy_load_still_accepts_linear_regex(pattern: str) -> None:
    parse_constraint(_constraint(pattern))


def test_error_names_the_pattern_and_how_to_fix_it() -> None:
    with pytest.raises(ConstraintParseError) as excinfo:
        parse_constraint(_constraint("^(a+)+$"))
    message = str(excinfo.value)
    assert "^(a+)+$" in message
    # An actionable error says what to do, not only what is wrong.
    assert "Rewrite" in message


def test_budget_exhaustion_is_undecided_rather_than_a_guess() -> None:
    # Running out of budget must report "unknown" so the caller can fail closed,
    # never False — which would wave a bomb through.
    assert find_exponential_ambiguity("^(a+)+$", budget=1) is None


def test_undecided_pattern_is_refused_at_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "hexgate.security.constraints.find_exponential_ambiguity",
        lambda pattern, *args, **kwargs: None,
    )
    parse_constraint.cache_clear()
    with pytest.raises(ConstraintParseError, match="too complex to verify"):
        parse_constraint(_constraint("^[a-z]+$"))
    parse_constraint.cache_clear()


def test_realistic_patterns_stay_far_inside_the_budget() -> None:
    # The check runs at policy load, not per decision, but it still must not
    # become the new slow path: a tight budget suffices for everything shipped.
    for pattern in LINEAR:
        assert find_exponential_ambiguity(pattern, budget=20_000) is not None, pattern


def test_unsupported_construct_is_reported_not_swallowed() -> None:
    # Backreferences are already refused by `_validate_re2`; if one ever reached
    # this module it must say so rather than silently answering "linear".
    with pytest.raises(UnsupportedRegex):
        find_exponential_ambiguity(r"(a)\1")


# Constructs Python's `re` accepts that RE2 has no equivalent for. Verified with
# `opa eval`: both are undefined under RE2 while Python matches, so they are the
# same engine-divergence class `_validate_re2` already refuses — they simply
# were not on its list, because a source-text rule cannot tell `a*+` from `\++`.
RE2_MISSING = ["(?>a+)+", "a*+", "(?>[a-z]+)", "a{2,3}+"]


@pytest.mark.parametrize("pattern", RE2_MISSING)
def test_re2_missing_constructs_are_refused(pattern: str) -> None:
    with pytest.raises(ConstraintParseError, match="RE2 does not have"):
        parse_constraint(_constraint(pattern))


def test_no_construct_escapes_as_an_unexpected_exception() -> None:
    """The grammar's no-crash guarantee: only ConstraintParseError comes out.

    A construct the analysis cannot model must be refused as a config error, not
    surface as an internal exception from the regex checker.
    """
    for pattern in RE2_MISSING + EXPONENTIAL + ["(?i)abc", r"\w+", "[[]+"]:
        try:
            parse_constraint(_constraint(pattern))
        except ConstraintParseError:
            pass


def test_case_insensitive_patterns_are_still_analysed() -> None:
    # `(?i)` is folded into the character sets by the parser, so the analysis
    # sees the real alphabet rather than silently under-approximating it.
    assert find_exponential_ambiguity("(?i)(a+)+") is not False
    assert find_exponential_ambiguity("(?i)abc") is False


# Bounded repeats. A wide bound behaves like an unbounded one for any argument
# long enough to matter — `^(a{1,10}){1,10}$` spans 100 characters and takes 14.7s
# on a 40-character argument — while a narrow one can only ever span a few
# characters and is harmless. Both must be judged on that difference, not on the
# fact that they are bounded.
BOUNDED_RUNAWAY = ["^(a{1,10}){1,10}$", "^([a-z]{1,8}){1,8}$", "^(a{1,5})+$"]
BOUNDED_HARMLESS = [
    "^(a{1,2}){1,2}$",
    "^(a{1,4}){1,4}$",
    "^a{2,4}$",
    "^[a-f0-9]{64}$",
    "^[A-Z]{2,4}-[0-9]{1,6}$",
    r"^(\d{1,3}\.){3}\d{1,3}$",  # an IPv4 rule
    r"^(\w{1,63}\.){1,10}[a-z]{2,6}$",  # a hostname rule
]


@pytest.mark.parametrize("pattern", BOUNDED_RUNAWAY)
def test_wide_bounds_are_not_proved_safe_by_their_bound(pattern: str) -> None:
    """A wide bound must not certify a pattern as linear.

    Unrolling a bound exactly leaves an automaton with no cycle, and "a state
    reachable from itself two ways" is what the analysis looks for — so exact
    modelling would prove every bounded pattern safe by construction, however
    slow it really is. Wide bounds are therefore read as unbounded.
    """
    assert find_exponential_ambiguity(pattern), pattern


@pytest.mark.parametrize("pattern", BOUNDED_HARMLESS)
def test_narrow_bounds_are_left_alone(pattern: str) -> None:
    # The other half: reading *every* bound as unbounded would refuse patterns
    # that can only ever span a handful of characters, including the ordinary
    # IPv4 and hostname shapes.
    assert find_exponential_ambiguity(pattern) is False, pattern


def test_wildcard_repetition_is_detected() -> None:
    """``^(.+)+$`` is exponential too, and needs its own case.

    ``.`` accepts every character, so no trailing character can make the match
    fail and :func:`_rejecting_char` returns nothing. The witness therefore
    cannot be a failing string the way it is for every other shape, which is why
    this pattern is not in ``EXPONENTIAL`` (that list also asserts the example
    fails to match). The ambiguity is real regardless: on an input that does
    fail — a newline in the middle, which ``.`` cannot cross — matching takes
    0.002s at 16 characters, 0.034s at 20 and 0.582s at 24.
    """
    assert isinstance(find_exponential_ambiguity("^(.+)+$"), AmbiguityWitness)
    with pytest.raises(ConstraintParseError, match="backtrack exponentially"):
        parse_constraint(_constraint("^(.+)+$"))
