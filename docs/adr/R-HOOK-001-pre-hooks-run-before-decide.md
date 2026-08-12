# R-HOOK-001: Pre-tool hooks run before the policy check

**Status:** Accepted · 2026-08-12
**Applies to:** `hexgate/hooks/**`, `hexgate/adapters/**/tools.py`

## Decision

Pre-tool hooks MUST run before `PolicyEnforcer.decide`, and `decide` MUST
evaluate the exact arguments the tool will execute. A hook that rewrites
arguments MUST do so before `decide`, never after. The guarded-call order is
fixed: pre-hooks, `decide`, invoke, post-hooks.

## Why

A pre-hook can rewrite a tool call's arguments. If it ran after `decide`, the
policy engine would have authorized the old arguments while the tool runs the new
ones, which is a straight policy bypass: a hook could clear a denied call by
editing its arguments after the check. Running pre-hooks first, and letting
`decide` re-authorize whatever they produce, gives the invariant that hooks can
only ever narrow a call (rewrite it or refuse it), never widen it past the policy.
This ordering is the whole reason arg rewrite is safe to allow at all. Reorder it
and the security model breaks silently, with nothing failing unless a test pins
the order.

## Consequences

- A pre-hook that rewrites arguments sits inside the trust boundary: it can coerce
  arguments into policy compliance. That is intended, and the `Modification`
  provenance record makes a coercing hook visible in the audit trail.
- A post-authorization slot (a hook that sees the `Decision` but cannot change
  arguments) does not exist yet; add it as a distinct step if a real need appears.

## Rejected alternatives

- **Pre-hooks after `decide`.** Simpler to bolt on, but it is exactly the bypass
  above.
- **Forbid arg rewrite entirely.** Removes the bypass, but also removes the
  strip-a-secret-from-args use, the main reason hooks exist. Re-authorizing the
  rewritten call keeps both the feature and the guarantee.

## Verify

```
pytest tests/hooks/test_runner.py -k pre_rewrite_is_what_decide_and_the_tool_see
```

passes: the arguments `decide` sees equal the arguments the tool runs.
