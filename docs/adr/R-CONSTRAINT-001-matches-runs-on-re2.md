# R-CONSTRAINT-001: `matches` is evaluated with RE2 on both engines

**Status:** Accepted · 2026-08-26
**Applies to:** `hexgate/security/constraints.py`

## Decision

The pydantic engine evaluates `matches` with **RE2** (`google-re2`), the engine
Rego already runs, instead of Python's `re`. A pattern is compiled when the
policy loads, so a regex RE2 cannot run is refused there with RE2's own reason,
and the compiled object is cached for evaluation.

`_RE2_INCOMPATIBLE` — the hand-maintained list of Python constructs to reject —
is removed. RE2 is now the judge.

## Why

Rego evaluates `regex.match` with RE2. The pydantic engine used to evaluate the
same constraint with Python's `re`, so the two agreed only as far as that list
went, and never on cost.

**Syntax.** The list had to enumerate what RE2 lacks, and it was incomplete:
atomic groups `(?>a+)+` and possessive quantifiers `a*+` passed it while being
undefined under RE2 (`opa eval 'regex.match("(?>a+)+", "aaa")'` returns
undefined; Python matches). A source-text rule cannot reliably catch those —
`a*+` and `\++` differ only by parse. Compiling with RE2 closes the gap by
construction and cannot drift.

**Cost.** `re` backtracks, RE2 does not, so a pattern both engines accept could
still take exponential time on one of them. Timed through `check_constraints`
with `^([a-zA-Z0-9_-]+)*@corp[.]com$`, deciding one call took 0.04s on a
20-character argument, 8.74s at 28 and 596s at 34 — roughly four times longer
per two characters. Under RE2 the same pattern decides a 4 000-character
argument in about 0.1ms. Since tool arguments are model-written and there is no
timeout on the decision path, that difference is the one that matters.

**Dependency.** `google-re2` publishes prebuilt wheels for the Python versions
this project supports, alongside the native packages already shipped
(`wasmtime`, `cryptography`, `biscuit-python`), so contributors compile nothing.

## Consequences

- `$` now means end-of-value only. Python's `$` also matches just before a
  trailing newline, so `^abc$` against `"abc\n"` was true on the pydantic engine
  and false in a compiled bundle (`opa eval` confirms false). The change removes
  that divergence rather than introducing one, but it is a behaviour change for
  anyone relying on the Python reading.
- `re.ASCII` is no longer needed to keep `\d` / `\w` ASCII: RE2 is ASCII for
  these by default.
- Error logging stays on. RE2 can be built with it off, but that also makes an
  invalid pattern compile into an object that never matches — turning a typo
  into a policy that silently denies everything. Raising is worth the log line.

## Rejected alternatives

- **Detecting exponential patterns statically and refusing them.** Tried first
  (PR #135): it needs an ambiguity analysis, still misses polynomial blow-ups
  like `^a*a*a*$`, is itself super-linear on adversarial input, and it refuses
  patterns on WASM-only deployments where they were never a problem.
- **A timeout around the match.** Python's `re` cannot be interrupted from
  another thread, and a per-constraint subprocess would dominate decision
  latency.
- **Keeping `re` and extending `_RE2_INCOMPATIBLE`.** Leaves the cost gap open
  and keeps a list that has already proven incomplete.

## Verify

```
pytest tests/security/test_re2_matches.py
```

Every pattern in that suite's `LINEAR_UNDER_RE2` corpus is one Python's engine
takes exponential time on, so a regression to `re` would hang the suite rather
than fail it quietly.
