# R-GUARD-001: Pre-tool guards run before the policy check

**Status:** Accepted · 2026-08-12
**Applies to:** `hexgate/guards/**`, `hexgate/adapters/**/tools.py`

## Decision

Pre-tool guards MUST run before `PolicyEnforcer.decide`, and `decide` MUST
evaluate the exact arguments the tool will execute. A guard that rewrites
arguments MUST do so before `decide`, never after. The guarded-call order is
fixed: pre-guards, `decide`, invoke, post-guards.

## Why

A pre-guard can rewrite a tool call's arguments. If it ran after `decide`, the
policy engine would have authorized the old arguments while the tool runs the new
ones, which is a straight policy bypass: a guard could clear a denied call by
editing its arguments after the check. Running pre-guards first, and letting
`decide` re-authorize whatever they produce, gives the invariant that guards can
only ever narrow a call (rewrite it or refuse it), never widen it past the policy.
This ordering is the whole reason arg rewrite is safe to allow at all. Reorder it
and the security model breaks silently, with nothing failing unless a test pins
the order.

## Consequences

- A pre-guard that rewrites arguments sits inside the trust boundary: it can coerce
  arguments into policy compliance. That is intended, and the `Modification`
  provenance record makes a coercing guard visible in the audit trail.
- `ToolCall.args` is a read-only `MappingProxyType`, so `Proceed(args=...)` (which
  records a `Modification`) is the only channel that can change the args a guard
  passes downstream. An in-place write raises rather than slipping a change past
  the provenance / observe tier. The proxy is shallow: a nested dict stays
  mutable, the documented residual (a deep freeze isn't worth the cost).
- A post-authorization slot (a guard that sees the `Decision` but cannot change
  arguments) does not exist yet; add it as a distinct step if a real need appears.

## Rejected alternatives

- **Pre-guards after `decide`.** Simpler to bolt on, but it is exactly the bypass
  above.
- **Forbid arg rewrite entirely.** Removes the bypass, but also removes the
  strip-a-secret-from-args use, the main reason guards exist. Re-authorizing the
  rewritten call keeps both the feature and the guarantee.

## Verify

```
pytest tests/guards/test_runner.py -k pre_rewrite_is_what_decide_and_the_tool_see
```

passes: the arguments `decide` sees equal the arguments the tool runs.
