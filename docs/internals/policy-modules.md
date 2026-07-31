# Multi-module policy — composition and reconciliation

*How a stack of policy files becomes one enforced policy, and the exact rules
that reconcile them when they overlap.*

> Status: reflects the first slice (modules + linker, `hexgate/security/`).
> The analyzer (lints) and dashboard editor are later PRs; durable versioning
> and the platform-side module store are deferred. This doc describes what the
> linker does today, and flags what is not built yet.

## The shift

An agent's policy used to be a single `policy.yaml`. It now composes from a
**stack of modules** — independently-authored fragments — folded into one
effective `AgentPolicy` by the **linker**. The effective policy then compiles to
Rego → WASM → a signed bundle exactly as a single file did:

```
many *.yaml modules            link()                 one effective policy
  boundaries  (caps + denies) ──────▶  fold  ──────▶  AgentPolicy  ──▶ rego ──▶ wasm ──▶ signed bundle
  capabilities (grants)          (the new step)                        (all unchanged)
```

Composition happens at the **model layer**, not in Rego. The engines only ever
see one resolved `AgentPolicy`, so the pydantic-vs-WASM parity gate is untouched.
This is the load-bearing invariant: *resolve, then compile.*

## Two tiers

Every module is one of two kinds, and the kind decides what it is allowed to say.

- **Boundary** — caps and hard denies. Security-owned. Its `allow` is a
  *ceiling* (permit up to a constraint), **not** a grant.
- **Capability** — additive grants. Team-owned. It may only `allow` /
  `approval_required`; a capability that tries to `deny` is a hard error.

| Mode | Boundary | Capability |
| --- | --- | --- |
| `deny` | ✓ absolute (or a conditional region) | ✗ `LinkError` |
| `allow` | ✓ — a ceiling (permits, does **not** grant) | ✓ — a grant |
| `approval_required` | ✓ | ✓ |
| `default_policy: deny` (a fence) | ✓ (ceiling posture) | ignored |

The one subtlety worth internalising: **a boundary `allow` never turns a tool
on.** It only says "if this tool is granted, it may not exceed this constraint."
A tool becomes usable only when a **capability** grants it. So a boundary alone
grants nothing; a capability alone is bounded by whatever boundaries permit.

## Reconciliation rules

For a single `(tool, arguments)`, every layer votes an outcome and the resolver
takes the **most restrictive**:

```
DENY  >  APPROVAL_REQUIRED  >  ALLOW  >  implicit-deny
```

The per-tool algorithm (`_fold_tool` in `hexgate/security/linker.py`):

1. A capability that denies the tool → **`LinkError`** (capabilities may only grant).
2. An **unconditional** boundary deny → **DENY**, absolute. Nothing below can undo it.
3. A **ceiling** boundary (`default_policy: deny`) that does not list the tool →
   **implicit deny** (the tool is ineligible); the exclusion is recorded so the
   analyzer can later flag any capability grant for it as shadowed.
4. No capability grants the tool → **implicit deny** (eligible but ungranted).
5. Otherwise → **ALLOW** (or **APPROVAL_REQUIRED** if any contributing grant or
   ceiling requires approval), with the effective constraint being *every
   contributing layer's constraint combined*.

Summarised in one line:

> **Fences intersect. Grants union. Denies win.**

- **boundary + boundary** on one tool → intersection (all caps bind; the
  stricter wins; any deny wins).
- **capability + capability** on one tool → union (either grant's condition
  suffices).
- **boundary ∩ capability** → the ceiling constraint AND the grant condition.

### Ceiling vs floor

A boundary's `default_policy` sets its posture:

- **Ceiling** (`default_policy: deny`) — an allowlist. A tool it does not name is
  ineligible, so a capability grant for it has no effect.
- **Floor** (`default_policy: allow`, the less-surprising default today) — only
  subtracts what it names; unlisted tools pass through to the capabilities.

Both use the same machinery; only step 3 above differs.

### Constraint algebra

The linker reuses the existing constraint DSL (`hexgate/security/constraints.py`)
and only builds trees over its nodes — no new grammar:

- **Intersection** is list concatenation. `AgentPolicy.tools[t].constraints` is a
  `list[str]` that is already implicit-AND, so combining ceilings + a grant is
  just appending strings.
- **Union** is a top-level `or` expression: `(A) or (B)`.
- **Deny-region subtraction** (a *conditional* boundary deny) becomes
  `and not (region)` appended to the grant.

Every assembled expression is re-parsed with `parse_constraint` to validate it
against the live grammar, so an unrenderable combination fails loud at link time,
not at evaluation.

### Constants

`consts` (referenced from constraints as `consts.<name>`) are merged across
layers with **boundaries winning**. A capability that redefines a boundary's
constant to a *different* value is a `LinkError` — otherwise a lower-authority
layer could loosen a boundary cap expressed as `args.amount <= consts.max` by
shadowing `max`. A capability-only constant, or one that matches the boundary's
value, merges normally.

## Worked example

Boundary `org_core` (floor): `deny delete_database`, `allow refund_order`
capped at `args.amount <= 1000`. Capability `payments`:
`allow refund_order when currency in [USD, EUR]`, `allow lookup_order`.
Capability leaf: `allow send_email`, `approval_required escalate`.

| Call | Outcome | Why |
| --- | --- | --- |
| `refund_order(800, USD)` | allow | in ceiling (≤1000) ∧ granted (USD) |
| `refund_order(1200, USD)` | deny | over the boundary cap |
| `refund_order(800, GBP)` | deny | inside the ceiling, but no grant for GBP |
| `delete_database()` | deny | absolute boundary deny |
| `lookup_order()` | allow | floor lets it through; capability grants |
| `send_email()` | allow (floor) / deny (ceiling) | eligible only if the boundary is a floor |
| `escalate()` | approval | granted, gated on a human |

If `org_core` were a **ceiling** instead of a floor, `lookup_order` and
`send_email` would be denied (ineligible — not named by the ceiling), and both
recorded as shadowed.

## Attachment & authority

- **Capabilities** are opted into by the agent (imported).
- **Boundaries** are inherited from the agent's scope (org → project), so an
  agent cannot opt out of them. Rule of thumb: *it's a boundary if the agent
  didn't get to choose it.*
- Authority is not a field in the file. It is enforced by **where the file lives**
  (a protected path + review) and, ultimately, by **signing** — the platform
  enforces a layer as a boundary only if its content hash is signed by the
  security key. *(Signing + scope-attachment are platform-side and not in this
  first slice; the SDK loads boundary and capability modules from local
  directories.)*

## Invariants

- **Parity untouched.** The linker emits one `AgentPolicy`; both engines evaluate
  the resolved policy, and the existing parity suite runs over it.
- **Capabilities can only tighten.** Enforced structurally: capabilities cannot
  deny, cannot set a fence, and cannot override a boundary constant.
- **Fail-closed.** The effective `default_policy` is `deny`; a tool no layer
  grants is denied.
- **Provenance is preserved.** Every resolved rule records the layers that fed it
  and any shadowing ceiling (`RuleTrace`), so errors can be attributed to a file.

## Where it lives

| Concern | Code |
| --- | --- |
| Data model (`ModuleContent`, `Provenance`, `RuleTrace`, `LinkResult`) | `hexgate/security/modules.py` |
| The fold | `hexgate/security/linker.py` (`link`, `link_policy_set`, `_fold_tool`) |
| Local-files loader (the seam a platform store swaps later) | `hexgate/security/module_loader.py` |
| Inspection | `hexgate policy resolve --dir <root>` |

## Not built yet

- **Signing + scope-attached boundaries + a platform module store** — the loader
  is local-files only; the platform-store loader is a later PR.
- **Durable versioning** — modules carry a content hash (identity) today, but
  there is no version history, pinning, or fan-out yet.
- **Per-role module scoping** — the linker folds into the single `default` role.
- **`file_scope` in modules** — a module tool using `file_scope` is a `LinkError`
  rather than being silently dropped; composing it is a later addition.
- **Agent-level rules** (`agents:` — can A invoke B) — reuses this same linker;
  a later PR.
- **The analyzer + editor** — lints (dead / shadowed / conflicting) and the
  dashboard view are the next two PRs; the `RuleTrace` provenance here is what
  they consume.
