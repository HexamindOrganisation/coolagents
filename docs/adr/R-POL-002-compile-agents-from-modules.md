# R-POL-002: Compile modular agents' bundles from resolved modules

**Status:** Accepted · 2026-08-17
**Applies to:** `platform/api/hexgate_api/features/policy_modules/**`, `platform/api/hexgate_api/features/agents/**`

## Decision

A project is **modular** iff it has at least one role binding. Follows from R-POL-001; this ADR covers how a modular project's agents are enforced.

- A modular agent's signed bundle MUST be compiled from the project's *resolved* role-keyed policy (`resolve` → inline-`roles:` YAML → `build_signed_bundle`), not from `agent.policy_yaml`. A classic project (no bindings) MUST keep compiling from `policy_yaml`, unchanged.
- Editing a module or a role binding MUST recompile every agent in the project (fan-out). Each agent is resolved for its own column of the `(role, agent)` matrix and compiled to its **own** bundle; agents that resolve to identical policy share a single `opa` compile (memoized). *(This superseded the original single-shared-bundle design once the `(role, agent)` matrix landed — see `agent-policy-dimension-design.md`.)*
- A recompile that can't resolve, or resolves but can't compile (e.g. `opa` absent), MUST leave existing bundles untouched. A broken or work-in-progress edit MUST NOT blank agents that were working.
- Modular MUST be inferred from the presence of a role binding. There MUST NOT be a `policy_mode` column in this phase.
- The serve path MUST NOT change: the bundle stays on the `Agent` row and the SDK fetches it as today.

## Why

Enforcement has to come from the composed modules, or the whole module system is inert (it only fed inspection before this). The one real question is *when* a project switches from `policy_yaml` to modules, and how not to break live agents doing it.

Inferring modular from a role binding, rather than adding a `policy_mode` column, is deliberate on two counts. First, it needs no migration: the platform has no Alembic, and `create_all` can add tables but not columns to a populated DB, so a column would force that decision now for no functional gain. Second, binding a role is the meaningful opt-in — you have decided which roles map to which capabilities. Uploading a capability or boundary module alone must *not* flip enforcement, or dropping in a single boundary would resolve every agent to a deny-all default and brick them.

Fan-out is required because the policy is project-level: one module edit changes every agent's effective policy, so every agent must recompile. Each agent resolves its own `(role, agent)` column into its own bundle; agents whose columns resolve identically are compiled once (memoized), so a project whose agents all share the generic `*` column still pays a single `opa` call per edit.

Leaving *compiled bundles* untouched when an edit can't **build** (e.g. `opa` absent) is the safety property: clearing bundles on a transient build failure would turn it into an enforcement outage across every agent. Failing safe means the last good bundle keeps enforcing while `check` surfaces the problem.

A later refinement tightened this: a write whose result is **semantically unresolvable** (a role importing an unknown capability, a capability with a `deny`) is now **rejected at write time** (409), not silently stored. The roles PUT validates the proposed bindings *before* writing; the module PUT/DELETE reject and roll back an edit that breaks resolution. So the store no longer holds an uncomposable state that keeps the old bundle with no signal — only a *transient* build failure (opa down) leaves the last-good bundle in place.

## Consequences

- No schema change, no migration. Additive code only.
- Each modular agent compiles to its own bundle from its `(role, agent)` column; agents that resolve to the same policy dedupe the `opa` compile (memoized). *(Originally all agents shared one bundle; the `(role, agent)` matrix made bundles per-agent so each carries only its own authority.)*
- For a modular agent, `agent.policy_yaml` is no longer what's enforced (the resolved modules are). The dashboard must edit modules, not per-agent `policy_yaml`, for modular projects.
- A saved-but-unresolvable project keeps enforcing its last good bundle; the divergence is visible through `check`, never silent.

## Rejected alternatives

- **A `policy_mode` column on `Project`.** Forces Alembic now (the column can't be added to a live DB by `create_all`) for no behavior a role binding doesn't already imply.
- **A per-project compiled-bundle table.** Removes the redundant per-agent bytes but changes the serve path (agents would fetch a project bundle). Deferred; not worth the serve-path risk yet.
- **Clearing bundles when a project won't resolve.** A one-character typo would blank every agent in the project. Fail-safe (leave last good) is mandatory for a product whose value is uninterrupted enforcement.

## Verify

```
cd platform/api && pytest tests/features/policy_modules/ -q
```

Covers: `is_modular` flips on the first binding; `bundle_for_agent` routes classic vs modular; `recompile_project` fans out to every agent; an unresolvable edit leaves bundles untouched; and (with `opa`) a modular agent's bundle equals compiling the resolved YAML.
