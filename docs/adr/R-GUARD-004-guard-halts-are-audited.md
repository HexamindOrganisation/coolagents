# R-GUARD-004: Guard halts are recorded to the audit trail, distinctly

**Status:** Accepted · 2026-08-14
**Applies to:** `hexgate/guards/**`, `hexgate/security/enforcer.py`

## Decision

A guard `Halt` MUST reach the same audit sender and decision observer a policy
denial does — whether the halt blocked the call or was approved and let it proceed.
A before-guard halt is recorded even though `decide` never ran; an after-guard halt
is recorded **in addition to** the tool's genuine ALLOW, not in place of it; a
`NEEDS_APPROVAL` halt that the handler grants is recorded too, mirroring how
`decide` records a policy `NEEDS_APPROVAL` — the human sign-off on a privileged call
is exactly the event worth keeping. A guard-denied halt MUST carry the
`guard_denied` marker so it is distinguishable from a real policy denial. Emission is
factored into `PolicyEnforcer.record`, which `decide` and the guard runner both call.

## Why

Audit emission used to live inside `decide` (`AuditSender.emit` + the
`decision_observer`), but a guard halt builds its own `Decision` via
`_halt_to_decision` and never calls `decide`, so guard halts were invisible to the
trail. Two failures: a before-guard halt left no record at all, and an after-guard
halt left the trail saying ALLOW while the model was handed a block. For a product
whose value is the audit trail, a missing entry is bad and an actively misleading
one is worse, and both happened on the correct, documented usage path. The
after-halt ALLOW is genuine, the tool did run and its side effect landed, so the
fix is to add the halt event, not to suppress the ALLOW: the trail should read
"the tool ran, then its result was withheld by a guard." The distinct
`guard_denied` marker keeps a guard refusal from masquerading as a policy denial
to both the model and any trail consumer.

## Consequences

- The guards-only path (`enforce_policy(None, guards=...)`, no policy engine) has no
  audit sender, so guard halts there are not recorded. Acceptable: no policy engine
  means no audit sink to record to.
- The halt `Decision` carries `arguments` for the audit record, but
  `as_error_payload` / `as_error_message` still never render them, so the model
  never sees the input the guard objected to.

## Rejected alternatives

- **Suppress the ALLOW on an after-halt.** The tool genuinely executed; hiding that
  would make the trail lie in the other direction.
- **Leave guard halts out of the trail.** The reviewer's point stands: the trail is
  the product, and a guard-blocked call must leave a trace.

## Verify

```
pytest tests/guards/test_runner.py -k "pre_halt_is_recorded or post_halt_records_both or approved_pre_halt_is_recorded"
```

passes.
