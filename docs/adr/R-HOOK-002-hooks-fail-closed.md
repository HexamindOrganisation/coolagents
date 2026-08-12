# R-HOOK-002: Hooks fail closed; observe-only hooks fail open

**Status:** Accepted · 2026-08-12
**Applies to:** `hexgate/hooks/**`

## Decision

A hook that can rewrite or halt a call MUST fail closed: if it raises, the call is
denied. A hook registered `observe_only` MUST fail open: if it raises, the
exception is swallowed and logged and the call proceeds. Fail-closed is the
default; `observe_only` is the explicit opt-in.

## Why

A hook that can block a call is a security control. If a crashing security control
silently let the call through, a bug in a hook would become a hole in enforcement,
exactly when you least want one, so an error on that path must deny. The cost is
that a broken side-effect hook (a metrics or logging hook whose socket blipped)
would take down every tool call, which is worse than a missing metric.
`observe_only` names that trade explicitly: a pure side-effect hook opts into
fail-open and can never break a call, and in exchange it cannot rewrite or halt.

## Consequences

- An `observe_only` hook's return value is ignored; a `Halt` or `Proceed` it
  returns is discarded with a warning, so "observe" cannot quietly become
  "enforce".
- On the sync path an `observe_only` hook mistakenly written async is also
  swallowed, not raised, to keep the fail-open promise. A non-observe async hook
  on a sync path still raises, because that is a wiring bug the author must fix.

## Rejected alternatives

- **Fail open by default.** A crashing enforcement hook would silently allow the
  call, the worst failure mode for a security layer.
- **One tier, always fail-closed.** A flaky metrics hook could break tool calls,
  pushing authors to wrap every hook in their own try/except.

## Verify

```
pytest tests/hooks/test_runner.py -k "fails_closed or observe_only"
```

passes.
