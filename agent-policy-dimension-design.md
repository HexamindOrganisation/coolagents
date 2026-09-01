# Agent dimension for modular policy — design

*Adding per-agent policy to the modular `(boundaries + capabilities + role bindings)`
model, so agents in one project can differ without splitting into separate
projects — and reconciling the three different "agent" notions currently in
flight into one.*

> Status: design proposal. Grounded in the code as of the `agent-admission-gate`
> (#124, which carries the merged #122 agent model) and `modular-policy-compile`
> (#121) branches. Not implemented; no PR yet.

## The problem

Modular policy today resolves to a **role-keyed** policy set: `{role: AgentPolicy}`.
Every agent in a project enforces the **same** resolved bundle — on the platform,
`recompile_project` builds one bundle and assigns it to every agent. So two agents
in one project (a `triage_bot` and a `billing_bot`, say) cannot differ in policy;
the only way to differentiate them today is to put them in **separate projects**,
which duplicates boundaries and role bindings and fragments a single logical
multi-agent system across projects.

We want per-agent policy **within** a project: "for caller role R, `billing_bot`
may refund but `triage_bot` may not," expressed once, composed the same way roles
already are.

## Three "agent" notions — and which we keep

The word "agent" already means three different things in the codebase. Untangling
them is the core of this design.

1. **#121 — `agent_leaf` / `agent_boundaries` (ad-hoc, name-less).**
   `resolve_for_project(..., *, agent_leaf=(), agent_boundaries=())` appends an
   agent's own modules to the fold: `fences = [*boundaries, *agent_boundaries]`,
   `caps = [*role_caps, *agent_leaf]`. There is **no agent name** — the identity
   lives in whoever calls `resolve`. It is unwired (nothing on the platform
   populates it). **Verdict: retire it.** It is the right *intent* (per-agent tool
   policy) expressed the wrong way.

2. **#122 / #124 — agent as first-class named keys (lowered to synthetic tools).**
   The agent policy model lowers agent-level rules into reserved tool keys that
   **both engines decide on the existing tool path, with no engine change**
   (`AgentPolicy.effective_tools`):
   - `agent.run` — **admission** (ingress). *Opt-in*: absence admits. Decided with
     `{"agent": <executing agent name>}` as args, so a policy can gate on
     `args.agent`.
   - `agent.tool:<target>` / `agent.handoff:<target>` — **reach** (egress).
     *Closed-world*: an unlisted target denies regardless of `default_policy`.
     `via ∈ {tool, handoff}`.
   **Verdict: keep it, unchanged.** This is the correct model for the
   *who-can-run / who-can-reach-whom* dimension, which is inherently runtime
   (the handoff target is only known at decision time).

3. **New — the `(role, agent)` tool-policy matrix (this doc).** Per-agent *tool*
   policy: "what tools does this agent get, per caller role." Distinct from both
   above. **Verdict: add it, resolved away at compile time (see Path A).**

The unification is not "merge #121's seam with #124's keys." It is:

> **Delete #121's ad-hoc seam. Keep #124's key model for admission/reach. Add a
> `(role, agent)` matrix for per-agent tool policy. Make all three agree on one
> agent identity — the agent's name (default `"main"`).**

## The model

**Role is the umbrella.** Everything hangs off the caller `role`: a generic
baseline that applies to every agent, plus per-agent refinements, plus (later)
other resource dimensions. The role's binding stops being a flat capability list
and becomes a **structured value** — an open set of sections under the role:

```yaml
# roles.yaml  (role -> { generic baseline, per-agent overrides }).
# "*" = the generic default; a bare list stays valid (back-compat).
roles:
  member:
    "*":                                  # generic baseline for any agent
      capabilities: [read_only]
    billing_bot:                          # a first-class agent under this role
      capabilities: [read_only, payments]
      handoffs: [refund_bot]              # sugar for agents: {refund_bot: {via: [handoff]}}
    triage_bot:
      capabilities: [read_only]           # more restricted than payments-holders
      handoffs: [billing_bot]
    refund_bot:                           # a SIBLING node, never nested under billing_bot
      capabilities: [read_only, refunds]
    # mcp: [...]        # a later resource section, added without a schema change
```

The `agent` here is the **generalization** of #122's sub-agent concept: the same
identity that governs handoff / agent-as-tool now also governs *first-level*
agents. `billing_bot` is just an agent under the role, whether it's the main agent
or reached by handoff.

Design rules (each carried over from the existing modular model or decided here):

- **Boundaries stay global ceilings** — role- *and* agent-independent, and
  distinct from the role's generic capability baseline. The safety invariant is
  unchanged: no role or agent can exceed the org/project ceiling. (Don't conflate
  the generic `"*"` capability baseline with boundaries — the baseline is grants,
  boundaries are the ceiling above all cells.)
- **Capabilities stay the only authored, reusable unit.** A `(role, agent)` node
  *selects* capabilities; it never inlines tool policy. Reuse (`read_only`
  everywhere) comes from importing the same capability, not from magic.
- **A named agent *replaces* the generic, so it can be *more restricted*.** The
  `"*"` section is the generic baseline; a named agent's section **fully specifies
  that agent** (it does not inherit-and-merge the baseline). This is the reading
  that lets an agent do *less* than the role generally allows — e.g. `triage_bot`
  omits `payments`, so it is strictly more restricted than a payments-holder —
  which capability-selection alone could not express under a merge/inherit reading
  (capabilities only ever *grant*, never tighten). Specificity wins at the
  granularity of the whole agent cell; the cost is repeating a baseline
  capability, which is a one-word import. It stays two levels (generic → agent),
  so it never reintroduces the inheritance-DAG hazard rejected for roles.
- **`"*"` is the generic default agent.** A flat `role: [caps]` stays valid as
  sugar for `role: {"*": {capabilities: [caps]}}`, so **every existing
  `roles.yaml` and every existing project keeps its exact meaning** (additive, no
  migration of meaning).
- **No recursion.** Sub-agents are **sibling nodes referenced by name** in
  `handoffs`, never nested subtrees with their own `tools`. This is enforced
  structurally: `handoffs` is a **list of names**, so there is no slot to hang a
  sub-agent's tools off — the illegal shape is unrepresentable, not policed. Each
  agent's tool policy has exactly one definition — its own node.
- **`handoffs` reuses the #122 `agents:` grammar.** `handoffs: [refund_bot]` is
  shorthand for `agents: {refund_bot: {via: [handoff]}}`; agent-as-tool is
  `{via: [tool]}`. Admission is the existing `admission:` block. No new agent-key
  grammar is introduced.
- **The role value is an open, extensible object.** `capabilities` + `agents`
  today; `mcp` and other resource dimensions can be added later as new sections
  under the role — and because the value is stored as JSON under `(project_id,
  role)` (see Storage), each new dimension is a value-shape change with **no DB
  migration**.

### Why no path-dependence is needed

The reason to want path-dependent policy ("`refund_bot` should be weaker when
reached via an untrusted path") is the confused-deputy case. It is covered by the
**reach edges controlling the graph**: if only `billing_bot` lists `refund_bot`
in `handoffs`, then `triage_bot` cannot reach it at all — the restriction comes
from the edge, not from keying `refund_bot`'s tools by caller path. Reach (control
the graph) + per-agent capabilities (control each node) together cover it, without
a computed closure.

## Resolution — Path A (resolve per agent; the bundle stays role-keyed)

This is the load-bearing decision. There are two ways to make `(role, agent)`
selection real, and they cost wildly differently.

**Path A (chosen).** The `(role, agent)` matrix is authoring/storage only. At
**resolve time**, each agent gets **its own role-keyed bundle** — that agent's
column merged over `"*"`, folded once per `(role)` exactly as today. Then:

- `PolicySet`, `policy_for(role)`, the Rego template, the enforcer, and the
  pydantic↔WASM parity gate are **unchanged** — the served agent still enforces a
  plain role-keyed bundle; the agent dimension is compiled away first. This is the
  "resolve, then compile" invariant roles already follow.
- It fits what already exists: every wrapped agent already loads its own artifact
  by name, and the platform already stores `compiled_wasm` **per agent** (today it
  just fills them all with the *same* bundle). Path A = resolve per agent in that
  existing loop. The per-agent compile cost is absorbed by the
  sha256-memoization already in the recompile path (agents whose column resolves
  identically dedupe).
- **Admission and reach ride inside each agent's per-agent bundle** as the #122
  lowered synthetic tools (`agent.run`, `agent.handoff:<target>`), decided at
  runtime on the existing path. So one per-agent bundle carries both halves: the
  role-keyed tool policy (resolved from the matrix column) *and* that agent's
  `agent.*` admission/reach rules.

**Path B (rejected).** One shared bundle keyed by `(role, agent)`, selected at
enforcement. This forces: re-keying `PolicySet` to `(role, agent)` (a breaking
change that escapes into `rego.py`, the enforcer, and every legacy loader),
`input.agent` guards in Rego, extending the pydantic↔WASM parity gate, **and**
plumbing a *dynamic* executing-agent identity through `HexgateContext` and every
framework adapter — which no adapter does today (they resolve a separate artifact
per agent; they do not re-key one). Path B reopens the two-engine surgery Path A
avoids entirely.

> Split of concerns, made explicit: **"what tools does agent A use?"** is static
> per agent → resolved away at compile (Path A). **"May A hand off to B?"** depends
> on the runtime target → stays a keyed rule (`agent.handoff:B`) in A's bundle
> (#122/#124). You cannot resolve reach away; you can and should resolve tool
> policy away.

### Path A vs Path B — the honest tradeoff

Both are internally consistent. The choice is *where you spend complexity*, not
whether the feature works. Recorded here so the reasoning outlives the decision.

**What B genuinely does better.** The intuition "we're already multi-key on role,
agent is just one more input" is correct, and B has real merits:

- **One signed artifact per project** — one signature, one version, one thing to
  distribute and audit. A produces *N* per-agent bundles.
- **Uniform keying** — `decide(role, agent, tool, args)` is one more `input` field
  on a bundle that already selects by `input.role`.
- **Less compile work** — one compile per project vs one per distinct agent column.

So B does not "hurt" at the distribution level; there it is arguably *simpler*.

**Why A wins anyway.** The cost of B is precise and architectural, not
performance:

1. **B pushes the agent dimension into both engines.** The modular design exists
   to keep composition at the **model layer** so the pydantic and WASM engines
   only ever see *one resolved policy* ("resolve, then compile"). B adds
   `input.agent` guards + a two-level fallback to the Rego template, re-keys
   `PolicySet`, and — the sharp part — **extends the pydantic↔WASM parity gate**,
   the one seam where a silent, asymmetric divergence is the worst-case bug. A
   leaves the engines and the parity gate untouched.
2. **Least-exposure of signed artifacts.** Under A, each agent's signed bundle
   carries **only its own authority** — `billing_bot`'s bundle has no trace of
   `triage_bot`'s grants. Under B, every agent ships the **entire project matrix**.
   For a security product that is a real property, not a nicety.
3. **A is not actually more infrastructure.** The platform already stores a bundle
   **per agent** (`compiled_wasm` per `Agent` row); today #121 compiles once and
   copies identical bytes to every row. A turns those identical copies into real
   per-agent compiles — no new storage or schema — and the sha256 memoization
   already in the recompile path bounds the extra compiles (identical columns
   dedupe). The infrastructure is already shaped for A.

**A correction, in fairness to B.** An earlier framing claimed B needs "dynamic
per-call executing-agent plumbing that no adapter does." That is too strong. Each
wrapped agent already has its **own** enforcer holding its **own** static
`agent_name`, and that enforcer *is* that agent — so passing `agent=self.agent_name`
into `evaluate()` is a one-liner and the static name suffices. B's real cost is
**not** context plumbing; it is the **Rego two-level fallback + parity-gate
extension + `PolicySet` re-key**. Feasible — but landing squarely on the seam the
architecture most wants to protect.

**Reach does not tip the choice.** Under A, an agent's `agent.handoff:<target>`
rules resolve into *its own* bundle with the executing agent implicit (it is whose
bundle it is), so no `input.agent` is forced by reach either. Both paths keep
reach as closed-world keyed rules; neither is more "reach-native."

**Choose B only if** "one signed artifact + one version per project" is a hard
requirement for the audit/distribution story — that is the single thing B does
strictly better, and worth the parity cost *only* if that constraint is real.
Absent that, **A** keeps composition at the model layer, protects the parity gate,
and gives per-agent least-exposure bundles on infrastructure that already exists.

## Selection & the sentinel reconciliation

At compile time, agent A's bundle is `fold` of `(role, A)` cells merged over
`(role, "*")`, for every role. At **run** time nothing new happens for tool
policy — A enforces its own role-keyed bundle. The fallback that matters is at
*resolve*: a `(role, agent)` cell, else the `(role, "*")` cell, else the role is
absent from A's bundle → fail-closed deny.

Three default sentinels currently collide and **must be reconciled**:

- `"*"` — the matrix default-agent key (this doc).
- `"default"` — the executing-agent name default in `enforcer.py` / the adapters
  today.
- `"default"` — `DEFAULT_ROLE_NAME`.

Decision: **the default executing-agent name becomes `"main"`** (reconcile
`factory.py` / `enforcer.py` and the adapter name-fallbacks), distinct from both
`"*"` (the matrix wildcard *key*) and the `default` *role*. Otherwise the
`(role, "*")` fallback silently never matches a real executing agent named
`"default"`, and every unroled agent fails closed (or matches the wrong cell).

## Storage — keep `(project_id, role)`, evolve the value (no migration)

The DB change is **independent of Path A vs B** — both must persist the matrix.
The question is only *how*, and it decides whether there is a migration.

**Chosen — evolve the JSON value (no migration).** Keep the `role_binding` table
exactly as is: key `(project_id, role)`, and the already-`Column(JSON)`
`capabilities` field. Let the *value* carry the structure — role is the umbrella,
everything nests under it:

- legacy row: `["read_only"]` (a flat list)
- new row: `{"*": {capabilities: […]}, "billing_bot": {capabilities: […], agents: {…}}, …}`

Read logic normalizes a legacy flat `list` to `{"*": {capabilities: <list>}}` (the
generic baseline). Then:

- **`metadata.create_all` is a no-op** (the table schema is unchanged) → **no
  migration on any DB, fresh or populated** — which matters because the platform
  has no migration tool and an additive-only posture.
- **Existing rows keep working for free** (flat list = generic baseline).
- New sections (`agents`, later `mcp`, …) are value-shape changes only — the table
  never changes again.
- The one thing we give up — querying *by agent* in SQL — we never do:
  `get_roles` already loads a project's whole binding and resolves in the SDK, and
  `roles_importing` already walks it in Python.

**Rejected — row-per-cell.** Add an `agent` column and change the unique key to
`(project_id, role, agent)`. Clean on a fresh DB, but on a populated one it is a
real migration (`create_all` won't add a column or alter a UNIQUE constraint on an
existing table): manual `ALTER` + constraint drop/recreate + backfill `agent="*"`,
with no in-repo tooling to run it. Buys SQL-queryability by agent that we don't
use.

No new tables either: per-agent **bundles already live** in `compiled_wasm` on the
`Agent` row (today filled identically; Path A makes them differ).

## Impact — quantified (Path A)

From a file-level review of the SDK, platform, editor, and PR stack.

| Surface | Change | Size |
| --- | --- | --- |
| SDK `module_loader.load_roles` | parse the matrix; accept flat form as sugar for `{"*": …}` | M |
| SDK `linker` | normalize the matrix; per-agent resolve (filter column ∪ `"*"`, reuse the fold) | M |
| SDK `analyzer` | lints gain an `agent` tag; surface multiplies per `(role, agent)` cell | M (deferrable) |
| SDK `policy_set` / `rego` / `enforcer` / parity | **unchanged** (Path A) | — |
| Platform `RoleBinding` | evolve the JSON value shape; key unchanged; read legacy flat list as `"*"` | S, **no migration** |
| Platform schemas | `RoleBindings{Read,Write}` nested; accept flat on write | S |
| Platform service | `get_roles` / `set_roles` / `roles_importing` / `_norm` / `resolve*` matrix-aware | M |
| Platform recompile | fan out per agent (loop exists; resolve per column; memoized) | M |
| Editor `api.ts` types | `RoleBindings`, `ResolvedPolicy`, `PolicyTestRequest + agent` | S |
| Editor `EditorPane` parse/dump | matrix + flat form (`roles.yaml` is free-text, so authoring stays small) | M |
| Editor Inspector + Test panel | add the agent axis (second selector) | M |
| Tests | ~21 platform + ~8 SDK + 2 dashboard files reshaped | M |

**Verdicts:** `roles.yaml` schema = **additive/non-breaking**. HTTP `/policy-roles`
shape = **breaking, but no current dashboard consumer** (keep flat-form accepted on
write). DB = **no migration** (JSON value evolves; key unchanged). `PolicySet` /
runtime / parity = **untouched** (this is the whole point of Path A). Net: a
**medium–large** feature with **no L item, no engine surgery, and no DB migration**.

### Top risks

1. **The sentinel collision** — pin the executing-agent default to `"main"` and
   reconcile the `enforcer.py` / adapter fallbacks, or the `(role, "*")` fallback
   silently never matches and unroled agents fail closed / match the wrong cell.
2. **`_norm` / `roles_importing` must become matrix-aware**, or the
   recompile-skip and capability-delete guards regress into stale enforcement.
3. **Legacy-value normalization must be exactly right.** A stored flat list must
   read as `{"*": {capabilities: […]}}` everywhere it's consumed; a miss here is a
   silent semantic change to existing projects (the price of the no-migration
   storage is that the compatibility lives in code, not the schema).
4. **Parity is only at risk under Path B.** Under Path A the two engines never see
   the agent dimension, so there is nothing to keep in lockstep.
5. **Not a migration, but a behavior shift on the platform:** #121 today serves
   *one* bundle to every agent; Path A makes per-agent bundles differ. Agents whose
   effective policy actually changes will re-compile on the next policy write — an
   intended enforcement change, worth calling out in the rollout.

## Where it lands (PRs)

Two PRs carry the whole feature: **#121 + #132**. The SDK foundation is **wired
directly into #121** (not a separate base PR): #121's branch already carries the
merged SDK foundation (#115/#117) and already edits `linker.py` (its
`agent_leaf`/`agent_boundaries` seam), so the matrix `load_roles` + per-agent
resolve belong with the per-agent *compile* that consumes them. Kept as their own
clean commits within #121 so review stays tractable.

Everything builds on the **already-merged #122 grammar** (`admission`/`agents`
blocks + lower-to-synthetic-tools), which lives on `main` — so no closed PR is
edited and no new base PR is needed.

- **#121** — SDK (matrix `load_roles`, per-agent resolve, analyzer agent tags) +
  platform compile (`recompile_project` fans out **per agent**; retire the
  `agent_leaf`/`agent_boundaries` seam). Rebased onto current `main` (it predates
  #122), on top of the review fixes already on its branch.
- **#132** (stacked on #121) — `role_binding` **value-shape** change (no
  migration) + `/policy-roles` API matrix-aware + the editor agent axis.
- **#124 → #142 → #138** — **not touched** for the matrix; they only need to agree
  on the agent-**name** identity (`"main"`). Retiring #121's ad-hoc seam is what
  makes #121 and #124 stop diverging — both converge on #122. (#142 is already
  conflicting and needs a rebase regardless — its own pre-existing issue.)

## Open decisions

1. **Path A vs Path B.** This doc chooses **A**. B is only warranted if we
   specifically want one runtime bundle serving many agents (and accept the
   engine/parity/adapter cost).
2. **`capabilities:` selection vs inline `tools:`** under a node — this doc keeps
   capabilities-only, consistent with "capabilities are the only authored unit."
3. **Default executing-agent name = `"main"`** (reconcile the existing `"default"`).
4. **Scope of unification with reach/admission** — share one agent identity across
   the matrix and the `agents:`/`agent.*` keys (recommended), which couples the
   sequencing of the two stacks at the "agent name" level only.

## What does not change

- Boundaries as global, role- and agent-independent ceilings.
- Capabilities as the only authored, reusable unit; roles/agents as thin bindings.
- The compile path: effective policy → Rego → WASM → signed bundle.
- The pydantic and WASM engines, and their parity gate (Path A).
- The #122/#124 admission/reach key model and its "lower to synthetic tools"
  mechanism.
