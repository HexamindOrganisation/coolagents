"""Reject regexes that a backtracking engine runs in exponential time.

:mod:`hexgate.security.constraints` already refuses regex *syntax* RE2 cannot
run (backreferences, lookaround, ...) so a policy tested on the pydantic engine
compiles to an equivalent WASM bundle. That covers what the two engines can
*express*; it says nothing about what they *cost*.

The gap this module closes: Python's ``re`` backtracks, RE2 does not. A pattern
like ``^(a+)+$`` is accepted by both, runs in linear time under RE2, and takes
exponential time under ``re`` — about four times longer per two characters
added. Since the tool arguments a constraint tests are attacker-influenced (a
model writes them, and the caller influences the model), a policy carrying such
a pattern lets a 34-character argument hold a CPU for ten minutes *in the engine
whose job is to decide whether that call is allowed* — measured, and still
quadrupling every two characters. So this is the same divergence
``_validate_re2`` exists to prevent, one level down: not "the WASM engine would
disagree" but "the WASM engine would finish".

Detection is exact rather than a syntactic heuristic, because both error
directions are expensive: a missed pattern leaves the hang in place, and a
wrongly rejected pattern refuses a policy that was fine. "Nested quantifier"
would be the easy rule and it is wrong — ``^([a-z0-9-]+[.])+corp[.]com$`` is
nested and linear, because the mandatory ``[.]`` forces one split per
iteration. What actually matters is **exponential ambiguity (EDA)**: whether
some state of the automaton can be reached from itself, over one word, by two
*distinct* paths. If it can, a failing match must try every combination of
those paths and the cost doubles per repetition; if it cannot, the match is
linear. That property is exactly what RE2's construction rules out, which is
why RE2 can promise linear time — so testing for it is testing for the
divergence itself, not for a syntax that correlates with it.

The check runs at policy load (inside the cached
:func:`~hexgate.security.constraints.parse_constraint`), never per tool call,
so it costs nothing at decision time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The parse tree has no public API. ``re._parser`` is the module the stdlib
# itself parses with; the old public alias ``sre_parse`` is deprecated. Only the
# parse tree is used here, never the compiler.
import re._parser as sre_parse

MAX_CODEPOINT = 0x10FFFF

# Product-automaton steps before the search gives up. A policy regex explores a
# few hundred; the cap exists so a pathological pattern cannot turn the *check*
# into the hang it is meant to prevent. Exhausting it returns "undecided", and
# the caller refuses the pattern rather than guessing.
DEFAULT_BUDGET = 200_000

# Edge-disjoint epsilon routes explored per state pair before the count is
# abandoned. Reached only by pathological nesting; realistic patterns finish
# in a handful of steps.
_ROUTE_BUDGET = 4_000

# How many times the ambiguous segment is repeated in the example string.
# Enough to show the shape and to be visibly slow, small enough that the
# example stays readable in an error message and cheap to run.
_EXAMPLE_REPEATS = 4

# Characters preferred when rendering a charset in the example string.
_WITNESS_PREFERENCE = "abxyz01_-./@ "


# Constructs Python's `re` accepts that RE2 (Go regexp, what Rego runs) has no
# equivalent for. Verified with `opa eval`: `regex.match("(?>a+)+", "aaa")` and
# `regex.match("a*+", "aaa")` are both undefined, while Python matches. They are
# named here rather than pattern-matched on the source text because `\++` (a
# repeated literal plus) is not a possessive quantifier and must stay legal.
RE2_MISSING_CONSTRUCTS = frozenset({"ATOMIC_GROUP", "POSSESSIVE_REPEAT"})


class UnsupportedRegex(Exception):
    """A construct this analysis does not model, so the verdict is unknown.

    ``re2_incompatible`` marks the ones RE2 cannot run either, which the caller
    reports as an engine-divergence problem rather than an analysis limit.
    """

    def __init__(self, construct: str) -> None:
        super().__init__(construct)
        self.construct = construct
        self.re2_incompatible = construct in RE2_MISSING_CONSTRUCTS


# --------------------------------------------------------------------------
# character sets, as sorted disjoint codepoint intervals
# --------------------------------------------------------------------------


def _normalise(intervals: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return tuple(out)


def _intersect(
    a: tuple[tuple[int, int], ...], b: tuple[tuple[int, int], ...]
) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return tuple(out)


def _invert(a: tuple[tuple[int, int], ...]) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []
    prev = 0
    for lo, hi in a:
        if lo > prev:
            out.append((prev, lo - 1))
        prev = hi + 1
    if prev <= MAX_CODEPOINT:
        out.append((prev, MAX_CODEPOINT))
    return tuple(out)


_DIGIT = ((48, 57),)
_WORD = _normalise([(48, 57), (65, 90), (95, 95), (97, 122)])
_SPACE = _normalise([(9, 13), (32, 32)])

# `re.ASCII` is how the evaluator runs `matches` (to mirror RE2's Go engine),
# so the classes are pinned to their ASCII meaning here too.
_CATEGORIES = {
    sre_parse.CATEGORY_DIGIT: _DIGIT,
    sre_parse.CATEGORY_NOT_DIGIT: _invert(_DIGIT),
    sre_parse.CATEGORY_WORD: _WORD,
    sre_parse.CATEGORY_NOT_WORD: _invert(_WORD),
    sre_parse.CATEGORY_SPACE: _SPACE,
    sre_parse.CATEGORY_NOT_SPACE: _invert(_SPACE),
}


def _construct_name(op: object) -> str:
    """The parser's name for a construct, e.g. ``ATOMIC_GROUP``."""
    return str(getattr(op, "name", op))


def _charset(op: object, av: object) -> tuple[tuple[int, int], ...]:
    """The set of codepoints one atom can consume."""
    if op is sre_parse.LITERAL:
        return ((av, av),)  # type: ignore[misc]
    if op is sre_parse.NOT_LITERAL:
        return _invert(((av, av),))  # type: ignore[misc]
    if op is sre_parse.ANY:
        return ((0, MAX_CODEPOINT),)
    if op is sre_parse.IN:
        items = list(av)  # type: ignore[call-overload]
        negated = bool(items) and items[0][0] is sre_parse.NEGATE
        if negated:
            items = items[1:]
        acc: list[tuple[int, int]] = []
        for item_op, item_av in items:
            if item_op is sre_parse.LITERAL:
                acc.append((item_av, item_av))
            elif item_op is sre_parse.RANGE:
                acc.append((item_av[0], item_av[1]))
            elif item_op is sre_parse.CATEGORY:
                if item_av not in _CATEGORIES:
                    raise UnsupportedRegex(_construct_name(item_av))
                acc.extend(_CATEGORIES[item_av])
            else:
                raise UnsupportedRegex(_construct_name(item_op))
        merged = _normalise(acc)
        return _invert(merged) if negated else merged
    raise UnsupportedRegex(_construct_name(op))


# --------------------------------------------------------------------------
# Thompson automaton
# --------------------------------------------------------------------------


class _Automaton:
    """A Thompson NFA: epsilon edges plus one charset per consuming edge.

    Built structurally, so a path through it corresponds to a way the
    backtracking engine can match — which is what the ambiguity search needs.
    Kept canonical (no redundant epsilon edge for the zero-iteration case):
    a duplicated route would read as ambiguity that the engine never has.
    """

    __slots__ = ("epsilon", "moves", "size")

    def __init__(self) -> None:
        self.epsilon: dict[int, set[int]] = {}
        self.moves: dict[int, list[tuple[tuple[tuple[int, int], ...], int]]] = {}
        self.size = 0

    def state(self) -> int:
        s = self.size
        self.size += 1
        self.epsilon[s] = set()
        self.moves[s] = []
        return s

    def link(self, src: int, dst: int) -> None:
        self.epsilon[src].add(dst)

    def consume(self, src: int, charset: tuple[tuple[int, int], ...], dst: int) -> None:
        self.moves[src].append((charset, dst))

    def closure(self, start: int) -> set[int]:
        seen = {start}
        stack = [start]
        while stack:
            for nxt in self.epsilon[stack.pop()]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen


# Bounds this small are modelled exactly; wider ones are read as unbounded.
#
# A fully unrolled bound has no cycle, and "a state reachable from itself two
# ways" is the whole basis of the analysis — so modelling a wide bound exactly
# would prove every such pattern safe by construction, however slow it really
# is. `(a{1,10}){1,10}` spans 100 characters and takes 14.7s on a 40-character
# argument. Reading a wide bound as unbounded restores the cycle and catches it;
# the price is treating `{1,10}` like `+`, which is what it amounts to for any
# argument long enough to matter. Small bounds stay exact, so `(a{1,2}){1,2}`
# (four characters at most, genuinely harmless) is not swept up.
_UNROLL_CAP = 4

# An exact repeat (`{n}`) adds no ambiguity of its own, so it is unrolled
# straight up to here — `[a-f0-9]{64}` costs 64 states and stays precise.
_EXACT_CAP = 128


def _build(seq: object, nfa: _Automaton, start: int) -> int:
    """Compile a parsed subpattern, returning the state it ends in."""
    cur = start
    for op, av in seq:  # type: ignore[attr-defined]
        if op is sre_parse.AT:
            continue  # anchors consume nothing
        if op in (
            sre_parse.LITERAL,
            sre_parse.NOT_LITERAL,
            sre_parse.ANY,
            sre_parse.IN,
        ):
            nxt = nfa.state()
            nfa.consume(cur, _charset(op, av), nxt)
            cur = nxt
        elif op is sre_parse.SUBPATTERN:
            cur = _build(av[3], nfa, cur)  # type: ignore[index]
        elif op is sre_parse.BRANCH:
            end = nfa.state()
            for branch in av[1]:  # type: ignore[index]
                entry = nfa.state()
                nfa.link(cur, entry)
                nfa.link(_build(branch, nfa, entry), end)
            cur = end
        elif op in (sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT):
            minimum, maximum, body = av  # type: ignore[misc]
            bounded = maximum is not sre_parse.MAXREPEAT
            if bounded and maximum <= _UNROLL_CAP:
                # Narrow bound: exact, so a pattern that can only ever span a
                # few characters is not reported as a runaway.
                for _ in range(minimum):
                    cur = _build(body, nfa, cur)
                end = nfa.state()
                nfa.link(cur, end)
                for _ in range(maximum - minimum):
                    cur = _build(body, nfa, cur)
                    nfa.link(cur, end)
                cur = end
            elif bounded and minimum == maximum and maximum <= _EXACT_CAP:
                for _ in range(minimum):
                    cur = _build(body, nfa, cur)
            else:
                # Unbounded, or a bound wide enough to behave like one. Read
                # as "at least `minimum`": an over-approximation, but the
                # honest direction here, since the alternative proves wide
                # bounds safe by construction (see `_UNROLL_CAP`).
                for _ in range(min(minimum, _UNROLL_CAP)):
                    cur = _build(body, nfa, cur)
                split = nfa.state()
                nfa.link(cur, split)
                entry = nfa.state()
                nfa.link(split, entry)
                nfa.link(_build(body, nfa, entry), split)
                end = nfa.state()
                nfa.link(split, end)
                cur = end
        else:
            raise UnsupportedRegex(_construct_name(op))
    return cur


def _route_multiplicity(
    nfa: _Automaton, src: int, dst: int, budget: int = _ROUTE_BUDGET
) -> int:
    """Distinct epsilon routes from ``src`` to ``dst``: 0, 1, or 2 ("several").

    Two epsilon routes between the same pair of consumed characters are already
    two distinct paths — this is why ``(a+)+`` is exponential while ``a+`` is
    not: after each ``a`` the engine may stay in the inner loop or close it and
    open a new outer iteration.

    A route may not reuse an edge. Reusing one means going round a loop without
    consuming anything — an empty iteration, which engines prune — so it is not
    a route the engine would actually take. That distinction is the whole
    difference between ``(a*)*``, where an iteration can absorb one character or
    several and the routes are genuinely different, and ``(a?)+``, where every
    iteration matches exactly one character and the only extra "route" is the
    empty loop. Both have an epsilon cycle; only the first is exponential.
    """
    found = 0
    spent = 0

    def walk(node: int, used: frozenset[tuple[int, int]]) -> None:
        nonlocal found, spent
        if found >= 2 or spent > budget:
            return
        spent += 1
        if node == dst:
            found += 1
            return
        for nxt in nfa.epsilon[node]:
            edge = (node, nxt)
            if edge not in used:
                walk(nxt, used | {edge})

    walk(src, frozenset())
    return min(found, 2)


@dataclass(frozen=True, slots=True)
class _Step:
    """One consuming step available from a state, after epsilon moves."""

    charset: tuple[tuple[int, int], ...]
    target: int
    edge: tuple[int, int]
    ambiguous_route: bool


def _steps(nfa: _Automaton) -> dict[int, list[_Step]]:
    table: dict[int, list[_Step]] = {}
    for src in range(nfa.size):
        out: list[_Step] = []
        for mid in nfa.closure(src):
            several = _route_multiplicity(nfa, src, mid) >= 2
            for index, (charset, target) in enumerate(nfa.moves[mid]):
                out.append(_Step(charset, target, (mid, index), several))
        table[src] = out
    return table


def _reachable_states(nfa: _Automaton, steps: dict[int, list[_Step]]) -> set[int]:
    """States the engine can actually be in, walking from the start state.

    An ambiguous loop sitting in a part of the automaton no input can reach is
    never explored, so flagging it would refuse a pattern that is fine in
    practice. Only reachable states are candidates.
    """
    seen = set(nfa.closure(0))
    stack = [0]
    while stack:
        for step in steps[stack.pop()]:
            if step.target not in seen:
                seen.add(step.target)
                seen |= nfa.closure(step.target)
                stack.append(step.target)
    return seen


def _pick_char(charset: tuple[tuple[int, int], ...]) -> str:
    """A readable representative of a charset, for the example string."""
    for candidate in _WITNESS_PREFERENCE:
        point = ord(candidate)
        for lo, hi in charset:
            if lo <= point <= hi:
                return candidate
    lo = charset[0][0]
    return chr(lo) if 32 <= lo < 127 else "?"


@dataclass(frozen=True, slots=True)
class AmbiguityWitness:
    """Where a pattern's repetition can match the same text two ways.

    ``prefix`` reaches the ambiguous state, ``pump`` is the segment matchable by
    two distinct paths from there, and ``example`` puts them together with a
    trailing character that cannot continue the match — a failing match being
    what makes an engine explore combinations instead of stopping at the first
    success.

    It is a witness, not a worst case: it shows *that* the pattern is ambiguous,
    and the ambiguity is what makes the pattern exponential, but some other
    input may drive the cost up faster than this one does. Messages built from
    it should point at the construct, not promise a timing.
    """

    prefix: str
    pump: str
    example: str


def _reconstruct(
    parents: dict[tuple[int, int, bool], tuple[tuple[int, int, bool], str]],
    node: tuple[int, int, bool],
    last: str,
) -> str:
    chars = [last]
    while node in parents:
        node, char = parents[node]
        chars.append(char)
    return "".join(reversed(chars))


def _prefix_to(nfa: _Automaton, steps: dict[int, list[_Step]], goal: int) -> str:
    """Shortest word taking the automaton from its start state to ``goal``."""
    if goal == 0:
        return ""
    seen = {0}
    queue: list[tuple[int, str]] = [(0, "")]
    while queue:
        state, word = queue.pop(0)
        for step in steps[state]:
            if step.target == goal:
                return word + _pick_char(step.charset)
            if step.target not in seen:
                seen.add(step.target)
                queue.append((step.target, word + _pick_char(step.charset)))
    return ""


def _rejecting_char(steps: dict[int, list[_Step]], state: int) -> str:
    """A character no continuation accepts, so the match must fail and unwind.

    Taken from the complement of what the state can consume rather than a fixed
    shortlist: a negated class like ``[^,]`` accepts every character a shortlist
    would offer, and the only one that stops it is the comma it excludes.
    Returns ``""`` when every character is accepted (a bare ``.``), in which case
    no example can be made to fail.
    """
    accepted: list[tuple[int, int]] = []
    for step in steps[state]:
        accepted.extend(step.charset)
    remaining = _invert(_normalise(accepted)) if accepted else ((0, MAX_CODEPOINT),)
    for lo, hi in remaining:
        for point in range(lo, min(hi, 0x7E) + 1):
            if 0x21 <= point <= 0x7E:  # printable ASCII, so the example reads
                return chr(point)
    return ""


def find_exponential_ambiguity(
    pattern: str, budget: int = DEFAULT_BUDGET
) -> AmbiguityWitness | None | bool:
    """Look for two distinct paths that leave a state and return to it.

    Returns an :class:`AmbiguityWitness` when the pattern can backtrack
    exponentially, ``False`` when it provably cannot, and ``None`` when the
    search ran out of budget and the answer is unknown.

    Two matches are walked in lock-step over the same word from ``(q, q)``.
    They diverge when they take different edges, or when one of them reaches
    its edge by an epsilon route that is itself ambiguous. Coming back to
    ``(q, q)`` after diverging exhibits one word with two distinct paths, which
    is the exponential-ambiguity condition.
    """
    parsed = sre_parse.parse(pattern, re.ASCII)
    nfa = _Automaton()
    _build(parsed, nfa, nfa.state())
    steps = _steps(nfa)
    reachable = _reachable_states(nfa, steps)
    spent = 0
    for start in range(nfa.size):
        if start not in reachable or not steps[start]:
            continue
        origin = (start, start, False)
        seen = {origin}
        parents: dict[tuple[int, int, bool], tuple[tuple[int, int, bool], str]] = {}
        stack = [origin]
        while stack:
            node = stack.pop()
            left, right, diverged = node
            spent += 1
            if spent > budget:
                return None
            for a in steps[left]:
                for b in steps[right]:
                    shared = _intersect(a.charset, b.charset)
                    if not shared:
                        continue
                    now = (
                        diverged
                        or a.edge != b.edge
                        or a.ambiguous_route
                        or b.ambiguous_route
                    )
                    char = _pick_char(shared)
                    if a.target == start and b.target == start and now:
                        pump = _reconstruct(parents, node, char)
                        prefix = _prefix_to(nfa, steps, start)
                        tail = _rejecting_char(steps, start)
                        return AmbiguityWitness(
                            prefix=prefix,
                            pump=pump,
                            example=prefix + pump * _EXAMPLE_REPEATS + tail,
                        )
                    nxt = (a.target, b.target, now)
                    if nxt not in seen:
                        seen.add(nxt)
                        parents[nxt] = (node, char)
                        stack.append(nxt)
    return False
