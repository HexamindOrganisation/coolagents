# R-AGENT-001: Agent-gate defaults — admission opt-in, reach closed-world-when-declared

**Status:** Superseded by R-AGENT-002 (2026-08-26) · originally Accepted for PR #124's first iteration
**Applies to:** `hexgate/security/policy.py`, `hexgate/security/rego.py`, `hexgate/security/agent_gate.py`, `hexgate/security/bundle.py`

> **Superseded.** The admission opt-in-*allow* rule below was found fail-open in self-review and is replaced by R-AGENT-002 (every agent key is closed-world; opt-in moved to *engagement*, derived from whether the policy declares the block). This ADR is retained so the supersedes-chain resolves and the original reasoning is on record. Only the engagement-flag and manifest mechanism it introduced survive, now uniform for admission and reach.

## Decision (original, now superseded)

The fallback for an unlisted synthetic agent key depended on the key kind, and each gate engaged only when its own block was declared:

- **Admission (`agent.run`) was opt-in-allow.** No `admission:` block → the gate no-ops; an unlisted `agent.run` fell through to *allow*. So within a policy that used admission, a role declaring none still admitted, keeping the multi-role union monotonic (adding admission to one role never locked out the others).
- **Reach (`agent.tool:` / `agent.handoff:`) was closed-world, but only once declared.** No `agents:` block → the reach gate did not engage → delegation was ungated; an `agents:` block present → an unlisted target/via denied.
- **Admission and reach engaged independently**, each derived from the presence of its own block — never author-set (a manual flag would drift). For a WASM bundle the derived signal rode a signed field in the bundle manifest, surfaced via `PolicyEngine.declares_admission()`.

## Why (original)

Absent-means-ungated for reach resolves the ambiguity of an empty `agents:` block ("delegate to no one" vs "delegation not policed") toward least surprise. Admission opt-in-allow was chosen so that adding admission to one role could never lock out roles that declared none.

## Why superseded

The opt-in-*allow* for admission was the fail-open: an unknown/no-role caller was admitted unless `default` denied, and an `admission: deny` on one role was defeated by any admission-silent co-role (the silent role opt-in-allowed, and `ALLOW` won the runtime union). R-AGENT-002 makes every agent key closed-world and moves opt-in to *engagement* (`declares_admission()` / `declares_reach()`), which removes both fail-opens structurally while keeping agents that declare nothing untouched.

## Consequences

- Superseded by R-AGENT-002 for the fallback semantics.
- The engagement-flag concept and the signed-manifest mechanism introduced here carry forward unchanged (and now apply uniformly to admission and reach).
