# R-POL-001: Policies compose from project-scoped modules; roles are bindings

**Status:** Accepted · 2026-08-11
**Applies to:** `hexgate/security/**`, `platform/api/hexgate_api/features/policy_modules/**`, policy authoring under `policies/boundaries/**`, `policies/capabilities/**`, `roles.yaml`

## Decision

An effective policy MUST be composed from small modules by the linker, not authored as one file per agent.

- Modules MUST live in two tiers, decided by the top-level folder, not a field: `policies/boundaries/` (security ceilings and hard denies) and `policies/capabilities/` (grants only). A capability MUST NOT `deny`.
- The tier folders MUST be at `<root>/policies/boundaries/` and `<root>/policies/capabilities/`. Files MAY nest to any depth inside them; the subpath becomes the module name. `roles.yaml` MUST be at the repo root, outside `policies/`.
- A role MUST be a binding (`role -> [capability names]`), not a policy block with `inherits`. Boundaries MUST apply to every role and MUST NOT be listed in a role.
- On the platform, modules MUST be scoped to the project. Agent-scoped modules MUST NOT be added until a compile path consumes them.
- The reconciliation fold MUST stay unchanged: fences intersect, grants union, denies win. The resolved policy compiles to Rego then WASM then a signed bundle exactly as a single policy does.

## Why

An agent's policy grows two ways at once. Security wants org-wide ceilings that every agent inherits and no team can loosen; teams want reusable tool grants. One file per agent forces both into one place, so the org ceiling is copied into every agent and drifts, and a shared capability has no single home. Scoping modules to the project fixes both: a boundary exists once and is inherited, a capability exists once and is imported.

Roles are bindings, not inheritance, for two reasons that bite at scale. Authored role blocks duplicate across agents, so "what can billing do" has no single definition. And `inherits` is a DAG whose effective permission set you have to compute, which is where multi-role permission bugs hide. A flat `role -> [capabilities]` list has neither problem.

Boundaries are role-independent on purpose: every role folds against the same boundaries, so a misconfigured role binding can never exceed a ceiling. Role escalation past a boundary is structurally impossible, not merely discouraged.

Full narrative (the worked examples, the store shape, the alternatives) lives in the design doc and the authoring guide; this ADR is the citable decision, not a copy. See `../../policy-modules-phase3-design.md` and `../../how-to-structure-policy-modules.md`, and the Notion "Multi-module policy: structure and design decisions".

## Consequences

- Capabilities become the reusable, reviewable unit; a role is a one-line list. Change a capability once and every role that imports it updates.
- The manifest keeps its separate job: it is the drift cross-check (`unknown-tool` / `unknown-arg` lints), not the grant source. Presence is not permission.
- Migration is coexistence, not a big-bang: classic single-file and modular resolve to the same compiled bundle, so agents move over one at a time.
- No `roles.yaml` resolves as a single `default` role importing every capability, so an un-migrated bundle keeps working.

## Rejected alternatives

- **Store keyed by agent.** Copies the org ceiling per agent and lets copies drift. The right key is the project.
- **Authored roles with `inherits`.** Rebuilds the duplication and the DAG this decision removes.
- **Capabilities derived from the agent/tool manifest.** Makes every wired tool automatically permitted (fail-open), and cannot express conditions, roles, or denies of tools that exist. The manifest describes the code; the capability authorizes it.
- **Attribute-based gating in constraints instead of roles.** The constraint engine sees only `{args, role, tool}` today; feeding verified caller facts in is a larger change, kept as a later option.

## Verify

```
# tier is by folder, never a field:
grep -rn "kind:" deploy/demo_policies/policies/   # returns nothing

# the modules compose per role:
hexgate policy resolve --dir deploy/demo_policies --role billing
hexgate policy check   --dir deploy/demo_policies

# the fold and role assembly are covered:
pytest tests/security/test_linker.py tests/security/test_analyzer.py -q
```
