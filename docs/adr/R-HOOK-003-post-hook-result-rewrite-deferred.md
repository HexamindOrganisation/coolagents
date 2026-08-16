# R-HOOK-003: Post-hooks may not rewrite results in v1

**Status:** Accepted · 2026-08-12
**Applies to:** `hexgate/hooks/**`

## Decision

Post-tool hooks MAY observe or halt in v1; they MUST NOT rewrite the result. The
runner MUST reject a post-hook that returns `Proceed(result=...)`. Result rewrite
lands in a later phase behind a projection rule, not before.

## Why

Tool arguments are always JSON, because the model emits them, so a pre-hook can
rewrite them with a clean recursive walk. A tool result is an arbitrary Python
object: a pydantic model, a dataframe, a bare string. Redacting one generically is
not well-defined, and the only safe target is its serialized projection, which
needs a rule (walk JSON-ish structures in place, flag opaque objects rather than
mutate them) that v1 does not build. Shipping a naive result rewrite would either
mangle objects or round-trip them through text, both lossy. Reserving the shape
now, via the `_UNSET` sentinel on `Proceed`, keeps the contract stable so the
later phase is an implementation, not a breaking change.

## Consequences

- A result-scanning plugin ships observe-only in v1 (it flags a leak) and becomes
  a redactor when the projection rule lands.
- Post-hooks still run when a tool raises, with `ToolOutcome(ok=False, error=...)`,
  so a watcher sees failures too; it simply cannot rewrite them.
- The "MUST NOT rewrite" is enforced, not just documented, for a dict result: when
  post-hooks exist, the value handed to them is wrapped in a read-only
  `MappingProxyType` (gated on `pipeline.post` so the no-hooks path stays zero-cost),
  and the runner returns the original object, so an in-place mutation raises rather
  than escaping into the tool's real return. This is an O(1) seal, the same one
  `_new_call` puts on args; an earlier version deep-copied the whole result, which
  cloned a large response on the hot path even for an observe-only watcher. Lists and
  opaque objects pass through unenforced in v1 (no cheap read-only view exists for
  them), and a nested dict inside a sealed dict is the same shallow residual as on
  args — the same boundary as the projection rule above.

## Rejected alternatives

- **Naive string-replace on the result.** Mangles any non-string result.
- **Serialize, redact the text, hand text back.** A double pass, and it changes
  the result's type out from under the caller.

## Verify

```
pytest tests/hooks/test_runner.py -k post_hook_result_rewrite_is_rejected
```

passes (a post-hook returning `Proceed(result=...)` raises in v1).
