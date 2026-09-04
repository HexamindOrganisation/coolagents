# R-AGENT-002: Agent-level rules compose through the boundary/capability linker; agent keys are closed-world

**Status:** Accepted · 2026-08-26 · supersedes the opt-in/closed-world portion of R-AGENT-001
**Applies to:** `hexgate/security/policy.py`, `hexgate/security/rego.py`, `hexgate/security/linker.py`, `hexgate/security/policy_set.py`, `hexgate/security/bundle.py`, `hexgate/security/agent_gate.py`

## Decision

Agent-level rules (`admission` / `agents`, lowered to `agent.run` / `agent.tool:<t>` / `agent.handoff:<t>` keys) MUST compose through the same model as tools (R-POL-001), not a separate runtime fold.

- **Agent keys fold through the linker.** `_fold_tool` and `_tool_names` MUST operate over `effective_tools`, so an `agent.*` key composes exactly like a tool key: a boundary deny wins absolutely and is role-independent; a ceiling boundary makes an unlisted key ineligible; capabilities grant and union; a capability that denies an agent key is a `LinkError`, same as any tool. `admission` / `agents` become allowed module fields.
- **Agent keys are closed-world.** An unlisted `agent.*` key (admission *and* reach) MUST deny, regardless of `default_policy`. This replaces R-AGENT-001's `agent.run` opt-in-allow: a role that is not granted admission is denied, so a silent co-role can neither admit an unknown caller nor defeat an explicit deny.
- **Engagement is opt-in and derived, separate from composition.** The agent gate MUST fire only when the policy configures the block — `PolicyEngine.declares_admission()` (and the reach equivalent), derived from whether any resolved role carries the key, and carried in the signed bundle manifest for WASM. An agent whose policy declares no admission is never gated and runs exactly as before. This is what keeps closed-world from locking out agents that don't use admission.
- **Authoritative, role-independent deny is a boundary.** A per-role rule (single-file or a capability) is per-role and composes by union like a tool rule; to bar a caller regardless of their other roles, the deny MUST be a boundary. Single-file agent rules are not special-cased: a single-file per-role `deny` behaves exactly like a single-file per-role tool `deny`.

## Why

Agent-level enforcement had grown a second composition model — per-role blocks folded by the runtime permissive union — and it leaked two fail-opens: unknown callers were admitted unless `default` denied, and an `admission: deny` was defeated by any admission-silent co-role. Both were artifacts of `agent.run` opt-in-allow (a silent role *granted* admission). The policy system already has the model that fixes them: boundaries are role-independent and deny-wins, so a boundary deny cannot be co-role-defeated, and a ceiling denies the unlisted. Making agent keys closed-world and folding them through the linker removes the fail-opens structurally instead of papering over them with a lint.

Closed-world reintroduces the lockout R-AGENT-001's opt-in avoided (a role not granted admission is denied), but that is the correct fail-closed posture for a gate — and the engagement flag confines it to agents that actually configure admission. An agent that never mentions admission is untouched; one that does must grant it where it wants callers admitted (e.g. `admission: allow` on `default` for broad access). Fail-closed-with-explicit-grants beats fail-open-by-default for a security layer.

Composition and engagement are deliberately separate: engagement answers "is this gate configured at all" (opt-in, backward-compatible), composition answers "how do the rules combine" (the linker fold). Tangling them was the original mistake.

## Consequences

- The two review fail-opens are fixed by construction: unknown/unrecognized callers deny (closed-world), and a silent co-role denies rather than admitting, so it cannot override a deny.
- The engine simplifies: `agent.run` joins the reach keys as plain closed-world, so the opt-in-allow branch in `get_tool_policy`, the per-role `agent.run` rule in the Rego compiler, and its golden-fixture churn all go away.
- Agent-level rules gain ceilings and authoritative role-independent denies once authored in the modular layout; single-file policies keep per-role semantics identical to tools.
- Enforcement is still the WASM for bundles; `declares_admission()` (manifest flag) only tells the gate whether to fire.
- Supersedes R-AGENT-001's opt-in-allow and the `agents:`-presence reach-engagement wording; R-AGENT-001's engagement-flag and manifest mechanism survive, now uniform for admission and reach.

## Rejected alternatives

- **Keep the single-file opt-in model, add a `permissive-admission` lint.** Ships the fail-opens behind lint-only mitigation and keeps a second composition model contradicting R-POL-001.
- **A bespoke deny-wins multi-role fold for admission only.** Re-invents what role-independent boundaries already provide, and only for one gate.
- **Reject single-file per-role agent `deny`.** Inconsistent — a single-file tool `deny` is allowed and per-role; agent keys should match. Authoritative denies are boundaries, by the same rule as tools.

## Verify

```
pytest tests/security/test_agent_policy.py tests/security/test_linker.py tests/security/test_agent_gate.py -q
# unlisted agent.run denies; a boundary agent deny is role-independent; a capability
# that denies an agent key is a LinkError; declares_admission drives engagement.
```
