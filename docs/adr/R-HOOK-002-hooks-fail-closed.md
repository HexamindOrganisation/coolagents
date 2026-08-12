# R-HOOK-002: Guards fail closed; observe guards fail open

**Status:** Accepted · 2026-08-12
**Applies to:** `hexgate/hooks/**`

## Decision

A guard that can rewrite or halt a call MUST fail closed: if it raises, the call
is denied. A guard marked `observe` (`@before_tool(..., observe=True)`) MUST fail
open: if it raises, the exception is swallowed and logged and the call proceeds.
Fail-closed is the default; `observe` is the explicit opt-in.

## Why

A guard that can block a call is a security control. If a crashing security
control silently let the call through, a bug in a guard would become a hole in
enforcement, exactly when you least want one, so an error on that path must deny.
The cost is that a broken side-effect guard (a metrics or logging guard whose
socket blipped) would take down every tool call, which is worse than a missing
metric. `observe` names that trade explicitly: a pure side-effect guard opts into
fail-open and can never break a call, and in exchange it cannot rewrite or halt.

## Consequences

- An observe guard's return value is ignored; a `Halt` or `Proceed` it returns is
  discarded with a warning, so "observe" cannot quietly become "enforce".
- On the sync path an observe guard mistakenly written async is also swallowed,
  not raised, to keep the fail-open promise. A non-observe async guard on a sync
  path still raises, because that is a wiring bug the author must fix.

## Rejected alternatives

- **Fail open by default.** A crashing enforcement guard would silently allow the
  call, the worst failure mode for a security layer.
- **One tier, always fail-closed.** A flaky metrics guard could break tool calls,
  pushing authors to wrap every guard in their own try/except.

## Verify

```
pytest tests/hooks/test_runner.py -k "fails_closed or observe_guard"
```

passes.
