# R-CONSTRAINT-001: `matches` regexes must be linear-time, not just RE2-shaped

**Status:** Accepted · 2026-08-24
**Applies to:** `hexgate/security/constraints.py`, `hexgate/security/regex_safety.py`

## Decision

A constraint's `matches` pattern is refused at **policy load** when it is
**exponentially ambiguous** — when some state of its automaton can be reached
from itself, over one word, by two distinct paths. Detection is exact (a search
over the product automaton), not a syntactic "nested quantifier" rule, and the
error carries a concrete example string plus the rewrite to apply.

Three verdicts, and each has a defined outcome:

| verdict | meaning | outcome |
|---|---|---|
| witness | two distinct paths found | refuse, showing the example |
| `False` | provably linear | accept |
| `None` | search budget exhausted | refuse as unverifiable |

## Why

`_validate_re2` already refuses regex *syntax* RE2 cannot run, so a policy
cannot mean one thing on the pydantic engine and another in a WASM bundle. That
covers what the engines can **express**; it says nothing about what they
**cost**.

Python's `re` backtracks. RE2 does not. `^(a+)+$` is accepted by both, is linear
under RE2, and is exponential under `re`. Measured on the evaluator's own entry
point (`check_constraints`), with the pattern as an email allowlist
`^([a-zA-Z0-9_-]+)*@corp[.]com$`:

| argument length | 20 | 24 | 26 | 28 | 30 | 32 | 34 |
|---|---|---|---|---|---|---|---|
| decision time | 0.04 s | 0.54 s | 2.21 s | 8.74 s | 37.8 s | 149 s | 596 s |

Lengths 20-28 were timed through `check_constraints`; 30 and beyond with the
same `re.search` call `_eval_call` makes, since with this change in place the
pattern no longer loads. The rate holds across the whole range at roughly four
times longer per two characters added (x4.1, x3.9, x4.0), so a 34-character
argument already costs ten minutes. Continuing that slope puts the low forties
in the hours — that last step is an extrapolation, not a measurement.

The arguments a constraint tests are written by a model and influenced by the
caller, and `hexgate/security/` carries no timeout or argument-size cap — so
the component deciding whether a tool call is allowed can be stalled by the
input it exists to filter. The local and pydantic-fallback modes are supported
deployment shapes (`source.py`), not just dev conveniences, so this is reachable
in production.

Exponential ambiguity is the right property to test because it is *exactly* what
RE2's construction rules out — which is why RE2 can promise linear time. Testing
for it tests the divergence itself rather than a syntax that correlates with it.

## Not covered

Cost that grows *polynomially* rather than by doubling is **out of scope here**,
and deliberately so rather than by oversight.

Measured, on the same engine entry point:

| pattern | 1 000 chars | 2 000 chars | 4 000 chars |
|---|---|---|---|
| `^a*a*a*$` | 1.06s | 8.55s | 67.6s |

Two different repetitions can absorb the same text, so the engine tries every
way to divide the input between them. It needs no crafted string, only a long
argument, and RE2 stays linear on it, so it is the same parity gap one tier
down.

A detector for it was written and then dropped from this change, because it
could not be shown to be precise: it reports the *structure*, and the structure
is not always reachable as a slow input. `^.*foo.*$` has it and runs in linear
time (measured flat to 8 000 characters) because the pattern matches as soon as
`foo` appears, so no input both exercises the ambiguity and fails. Reporting it
would mean warning about patterns that are fine.

Closing that gap needs the automaton to model *acceptance*, so the analysis can
require a failing continuation after the pumped section. That is a larger change
and belongs in its own review, not bundled here.

## Consequences

- A pattern that is safe under RE2 but exponential under `re` no longer loads,
  even for a deployment that only ever runs the WASM engine. Deliberate: one
  policy language, one behaviour, whichever engine is underneath. The rewrite is
  usually trivial (`(a+)+` → `a+`).
- The check runs inside the already-cached `parse_constraint`, so it costs
  nothing per decision.
- `None` (budget exhausted) fails closed. No policy pattern in this repo comes
  near the budget — every shipped pattern resolves under 20 000 steps against a
  200 000 default.
- An epsilon cycle alone does not make a pattern exponential and is not treated
  as ambiguity. `(a?)+` has one (an empty iteration) but every iteration matches
  exactly one character, so there is a single way to split the input and it runs
  linearly; `(a*)*` has the same cycle *and* iterations that can absorb any
  number of characters, so it is exponential. Routes are therefore counted
  without reusing an edge, which is what separates the two.
- A repetition bound wider than 4 is read as unbounded. Unrolling a bound
  exactly leaves an automaton with no cycle, and the analysis looks for a state
  reachable from itself — so exact modelling would certify every bounded pattern
  as linear however slow it is (`^(a{1,10}){1,10}$` spans 100 characters and
  takes 14.7s on a 40-character argument). Narrow bounds stay exact, so
  `^(a{1,4}){1,4}$`, `^(\d{1,3}\.){3}\d{1,3}$` and `^(\w{1,63}\.){1,10}[a-z]{2,6}$`
  are not swept up.
- The analysis models the RE2 subset the grammar allows. A construct it cannot
  model raises `UnsupportedRegex` rather than answering "linear".

## Rejected alternatives

- **A syntactic "nested quantifier" rule.** Wrong in both directions. It rejects
  `^([a-z0-9-]+[.])+corp[.]com$`, which is nested *and* linear because the
  mandatory `[.]` forces one split per iteration; and it misses `^(a|aa)+$`,
  which has no nesting at all and is exponential. Both are in the test corpus.
- **A runtime timeout.** Python's `re` cannot be interrupted from another
  thread, `signal.alarm` is Unix-only, and a subprocess per constraint would
  dominate decision latency. It would also convert a policy bug into a runtime
  failure on the enforcement path, which is the worst place to discover it.
- **Capping argument length before matching.** Changes semantics for legitimate
  long arguments, and the cap would have to be brutal to help: 30 characters
  already costs 38 seconds.
- **Swapping `re` for a linear-time engine** (`google-re2`, or a Thompson
  simulation of the supported subset). The soundest fix and the largest: a new
  dependency or a second regex engine to keep in parity with RE2 forever. Worth
  revisiting if `matches` ever needs to accept patterns this ADR refuses; until
  then, refusing them is the smaller and more reviewable change.

## Verify

```
pytest tests/security/test_regex_safety.py
```

passes: every blow-up shape is refused, every `matches` pattern this repo ships
still loads, and each reported example is a string the engine genuinely fails to
match (which is what forces it to try every split).
