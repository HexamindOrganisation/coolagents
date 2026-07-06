# Policy Binding — pull, enforcement, and per-run refresh for every agent surface

**Status:** phase 1 implemented (with the revisions in the addendum below)
**Scope:** `HexgateAgent` (`create_agent` / loaders) + the four adapters
(`openai`, `google`, `pydantic_ai`, `langchain` BYO-graph)
**Date:** 2026-06-04

> **Addendum — post-review simplifications (2026-06-04).** Phase 1 landed a
> deliberately smaller `PolicyBinding` than §3/§4 describe. Where this
> addendum and the body disagree, the addendum wins:
>
> 1. **No auto-register in the binding.** `AutoRegisterSpec`,
>    `manifest_payload`, and the 404→register→retry flow are gone (SRP:
>    registration is not policy resolution — and `hexgate.cli.register`
>    already builds *better* manifests from the real agent object). A 404
>    propagates as `HexgateError` with `.status == 404`; callers that want
>    register-on-miss catch it, call `register_agent(agent)`, and resolve
>    again. Adapter phases add this 4-line pattern at the wrap sites.
> 2. **No `fallback` param.** The plain constructor *is* the explicit
>    static path: `PolicyBinding(PolicyEnforcer(engine, agent_name=...))`.
> 3. **No `prefetched` param.** The loader composes directly: build the
>    pre-seeded `PlatformPolicySource`, decode the bundle (as it already
>    does), and call the constructor. Same single round trip, no parameter.
> 4. **No `client` / `agent_name` fields.** The binding holds exactly
>    `enforcer` + `source`; `agent_name` is read from the enforcer for
>    logs, and the `HexgateClient` stays a caller concern
>    (`agent.hexgate_client`, as today).
> 5. **No `_warn_uncovered_tools`.** YAGNI — revisit in the adapter phases
>    if real usage shows the need.
> 6. **The `HEXGATE_LOCAL_POLICY` helpers live in `security/source.py`**
>    (env var → `PolicySource` is source-construction), not in
>    `binding.py`. The loader re-imports them from there.
> 7. **The refresh lock lives in `PlatformPolicySource`**, which owns the
>    mutable cache it protects — the binding has no lock.
>
> Net: `binding.py` is ~200 lines (resolve → local override → platform →
> raise; fail-soft `refresh`/`refresh_async`), and the client kept only
> `HexgateError.status` from its planned changes.

---

## 1. Problem statement

Today only the loader path (`load_hexgate_agent` / `load_agent` with
`HEXGATE_API_KEY`, `hexgate/agents/loader.py:528`) delivers the full governance
loop: pull the signed policy bundle from the platform, verify it, enforce it
on every tool call, and re-pull (ETag/304) at the top of every run.

Every other construction path falls short:

| Surface | Pull | Enforce | Per-run refresh |
|---|---|---|---|
| `load_hexgate_agent` / `load_agent` + `HEXGATE_API_KEY` | ✅ verified bundle | ✅ `GuardedTool` | ✅ ETag/304 |
| `create_agent(...)` (programmatic) | ❌ | ❌ | no-op |
| `create_agent(...)` + `enforce_policy(p)` | ❌ (static `p`) | ✅ | no-op (no source) |
| `wrap_openai_agent` / `HexgateRunner` (openai) | ❌ placeholder **allow-all** | ✅ (allow-all) | ❌ |
| `wrap_google_agent` / `HexgateRunner` (google) | ❌ placeholder **allow-all** | ✅ (allow-all) | ❌ |
| `wrap_langchain_agent` (BYO `CompiledStateGraph`) | ❌ placeholder **allow-all** | ✅ (allow-all) | ❌ |
| `wrap_pydantic_agent` | ❌ placeholder **allow-all** | ✅ (allow-all) | ❌ |

The four adapters each carry an identical placeholder with the same TODO:

```python
def build_policy_set(api_key, agent_name, tool_names) -> PolicySet:
    """Placeholder allow-all one-role bundle. TODO: cloud-fetch via HexgateClient."""
```

(`adapters/openai/wrapper.py:19`, `adapters/google/wrapper.py:17`,
`adapters/pydantic_ai/wrapper.py:22`, `adapters/langchain/wrapper.py:22`)

`api_key` is collected — and then ignored. This spec replaces all four
placeholders and the `create_agent` gap with **one** framework-agnostic
primitive.

### 1.1 The structural fact this design exploits

Every enforcement mechanism in the codebase — `GuardedTool`
(`adapters/langchain/tools.py:61`), `install_enforcer_on_tool`
(`adapters/langchain/tools.py:178`), the OpenAI `FunctionTool.on_invoke_tool`
copy (`adapters/openai/tools.py:30`), the ADK tool wrappers, the pydantic_ai
toolset clone — closes over the **`PolicyEnforcer`**, never over the policy
itself. The enforcer is a one-field indirection
(`hexgate/security/enforcer.py:18`):

```python
enforcer.policy = new_bundle   # hot-swaps enforcement for every wrapped tool
```

So "refresh" is framework-agnostic by construction. The only missing pieces
are (a) a shared resolve-and-pull step and (b) a refresh call at each
surface's run boundary. That is the entire refactor.

---

## 2. Goals / non-goals

### Goals

1. **One implementation** of policy resolution (precedence, verification,
   fallback) and refresh (ETag/304, fail-soft) shared by all six surfaces.
2. `create_agent` can bind to the platform at creation; refresh already
   fires per `stream_agent` / `invoke_agent` — no streaming changes.
3. All four adapters pull a **real** policy at wrap time and refresh at every
   run entry point; the allow-all placeholder is deleted.
4. Verification semantics are byte-identical to today's loader: a tampered
   or unverifiable bundle is **never** silently downgraded.
5. `load_hexgate_agent` dedupes onto the same primitive (net code deletion).

### Non-goals

- No new platform endpoints. `GET /v1/agents/{name}` (ETag/304,
  `platform/api/main.py:857`) and `POST /v1/agents` (auto-register with
  default role-aware policy + signed bundle, `platform/api/main.py:829`)
  already exist and suffice.
- No per-tool-call refresh. Refresh granularity stays **per run/turn**
  (matching `stream_agent` today). Mid-turn policy edits land next turn.
- No change to the enforcement decision pipeline
  (`PolicyEnforcer.decide` → engine `evaluate` → `Decision`), nor to the
  WASM evaluation path (`hexgate/security/wasm_engine.py`).
- No change to approval-handler semantics per adapter (LangChain resolves
  inline; OpenAI/Google/pydantic_ai render markered errors — unchanged).

---

## 3. Core design: `PolicyBinding`

New module: **`hexgate/security/binding.py`** — framework-agnostic, imports
nothing from `hexgate.adapters.*` or `hexgate.agents.factory` (avoids the
factory↔loader↔adapters import cycles).

```python
@dataclass
class PolicyBinding:
    """Resolved policy for one agent: an enforcer plus an optional refresh source.

    The enforcer is the stable object every wrapped tool closes over;
    refresh() mutates `enforcer.policy` in place, so a binding created once
    keeps all previously wrapped tools current forever.
    """

    enforcer: PolicyEnforcer
    source: PolicySource | None          # None → static policy, refresh is a no-op
    client: HexgateClient | None         # kept for lazy User-scope attenuation
    agent_name: str
    _refresh_lock: threading.Lock        # serializes concurrent refreshes
```

### 3.1 `PolicyBinding.resolve(...)` — the pull

```python
@classmethod
def resolve(
    cls,
    agent_name: str,
    *,
    api_key: str | None = None,          # explicit → HEXGATE_API_KEY env
    client: HexgateClient | None = None, # reuse an existing client (loader path)
    prefetched: tuple[dict, str | None] | None = None,  # (payload, etag) reuse
    fallback: PolicyEngine | None = None,
    auto_register: AutoRegisterSpec | None = None,
    approval_context: str | None = None,  # display only
) -> "PolicyBinding":
```

Resolution precedence — lifted verbatim from `load_hexgate_agent`
(`loader.py:597-636`); the loader's helpers `_local_policy_override`,
`_verify_local_source_signature_policy`, `_resolve_pubkey_for_verification`,
`_local_sign_callable` **move** into this module (loader re-imports them, so
its behavior and its tests stay identical):

1. **`HEXGATE_LOCAL_POLICY` override** (dev loop) — wins outright.
   `BundleDirPolicySource` (mtime-refreshed pre-built bundle) or
   `YamlPolicySource` (auto-recompile on save), exactly as today
   (`hexgate/security/source.py:165,256`). The platform is not contacted.
2. **Platform** — when an `api_key`/`HEXGATE_API_KEY`/`client` is available:
   1. Build or reuse the `HexgateClient` (Biscuit signature verified lazily
      on first use, `cloud/client.py:177`).
   2. `payload, etag = client.get_agent(agent_name)` — or use `prefetched`
      when the caller already fetched (loader path; avoids a double fetch).
   3. `decode_and_verify_platform_bundle(payload, client.public_key_bytes())`
      (`source.py:117`): Ed25519 signature over the exact manifest bytes
      **and** `sha256(wasm) == manifest.wasm_hash`. **Any failure raises** —
      identical to today.
   4. Bundle present → it is the policy. Bundle absent (platform couldn't
      compile, e.g. no `opa`) → fall back to
      `load_policy_set_from_dict(payload["policy_yaml"])` (pydantic engine),
      unless `HEXGATE_BUNDLE_REQUIRE_SIGNATURE` is set → raise
      (today's rule, `loader.py:615-621`).
   5. Attach `PlatformPolicySource(client, agent_name, initial_bundle=...,
      initial_etag=...)` pre-seeded so the first refresh is a 304
      (`source.py:78-93`).
   6. **404 — agent unknown to the platform:**
      - if `auto_register` is provided → `POST /v1/agents` with a minimal
        manifest (name + tool names), which the platform answers with a
        default role-aware policy and a signed bundle
        (`platform/api/main.py:829`, `services.py:1290`); then re-fetch and
        proceed. Registration failure → raise.
      - else → raise `PolicyBindingError` with a message pointing at
        `hexgate agents register` / `auto_register=`.
3. **`fallback` engine** — used only when neither a local override nor any
   API key is in play. `None` (the default) → raise. This is the explicit
   opt-out that replaces the adapters' silent allow-all; callers who truly
   want ungoverned behavior must write it down:
   `fallback=PolicySet.allow_all(tool_names)`.

Construction is **eager**: the fetch and verification happen inside
`resolve()`. Rationale: failures are loud at construction, and the enforcer
always holds a real, verified policy before any run. (The lazy alternative —
an unseeded source plus a "pending" policy — interacts badly with refresh's
deliberate fail-soft: a network blip on first run would leave the agent
either unguarded or hard-bricked. Rejected.)

#### `AutoRegisterSpec`

```python
@dataclass(frozen=True)
class AutoRegisterSpec:
    tool_names: list[str]
    model: str | None = None
    description: str | None = None
```

Carried by the caller because only the wrap site knows the real tool list.
Re-registers never overwrite an existing agent's `policy_yaml`
(platform guarantee, `main.py:836-841`), so auto-register is idempotent and
dashboard edits survive.

### 3.2 `refresh()` / `refresh_async()` — the per-run pull

```python
def refresh(self) -> None:
    """Pull the current policy and swap it in. Cheap when nothing changed.

    No-op when source is None. Failures are logged and swallowed —
    a transient network blip never crashes a turn; the previous verified
    policy stays in force (fail-open to STALENESS, never to NO-POLICY).
    """
    if self.source is None:
        return
    with self._refresh_lock:               # collapse concurrent refreshes
        try:
            new_policy = self.source.fetch()
        except Exception as exc:
            logger.warning("policy refresh failed: %s — keeping previous policy", exc)
            return
        if new_policy is None or new_policy is self.enforcer.policy:
            return                          # 304 path: same object identity
        self.enforcer.policy = new_policy   # atomic rebind — all tools see it

async def refresh_async(self) -> None:
    await asyncio.to_thread(self.refresh)
```

This is the body of `HexgateAgent.refresh_policy` + `_refresh_policy_safely`
(`factory.py:434-460,550-566`) with two deltas:

- **fail-soft moves into the binding** (one place instead of per-caller), and
- a **`threading.Lock`** serializes concurrent refreshes. Adapters' proxies
  are documented multi-user objects; without the lock, two concurrent runs
  both miss the ETag cache and double-fetch. `enforcer.policy =` itself is an
  atomic rebind and `WasmPolicy` already serializes evaluation
  (`wasm_engine.py:130-133`), so the lock is purely an efficiency/etag-
  coherence measure, not a correctness one.

The cheap path is unchanged from today: `PlatformPolicySource.fetch()` sends
`If-None-Match: "<wasm_hash>"`; the platform compares against
`sha256(compiled_wasm)` and answers `304` with no body
(`platform/api/main.py:881-893`); the source returns the *same cached
`PolicyBundle` object*; identity check short-circuits the swap. Cost per
unchanged run: one small HTTP round trip — no signature re-verify, no
wasmtime work.

On a `200`, the source re-runs the **full** decode + signature + integrity
verification before caching (`source.py:103-114`). A bundle that fails
verification at refresh time raises inside `source.fetch()` → caught by
`refresh()` → logged → **previous verified policy stays in force**. A
tampered refresh can therefore deny service to *new* policy but can never
*install* itself.

### 3.3 Refresh granularity and timing contract

- Refresh fires **once at the top of every run** (turn), before any model or
  tool execution for that run. All surfaces below uphold this.
- Tool calls within a single run see one consistent policy: the swap only
  happens at the run boundary; mid-run a concurrent runner's swap can land
  (shared enforcer), which is acceptable — both policies involved are
  platform-verified, and per-tool-call atomicity is guaranteed by
  `decide()` reading `self.policy` once.
- Sync entry points call `refresh()` directly (blocking HTTP, ~ms, on the
  caller's thread — same as any sync tool I/O). Async entry points call
  `await refresh_async()`.

---

## 4. Surface integration

### 4.1 `HexgateAgent` — `create_agent` (hexgate/agents/factory.py)

New keyword params on `create_agent`:

```python
def create_agent(
    model, tools, system_prompt=DEFAULT_SYSTEM_PROMPT,
    *,
    name: str | None = None,             # exists today
    bind_policy: bool | None = None,     # NEW — None = auto
    approval_handler: ApprovalHandler | None = None,   # NEW (threaded to enforce)
    ...
) -> tuple[AgentGraph, CallbackHandler]:
```

Semantics of `bind_policy`:

| value | behavior |
|---|---|
| `None` (default, **auto**) | bind iff (`HEXGATE_API_KEY` set **or** `HEXGATE_LOCAL_POLICY` set) **and** `name` is provided; otherwise return the bare agent exactly as today |
| `True` | bind or **raise** (`name` required; no key and no local override → raise) |
| `False` | today's behavior, unconditionally (escape hatch for unit tests of bare graphs) |

Binding step (runs after the `HexgateAgent` is constructed):

```python
binding = PolicyBinding.resolve(name, auto_register=AutoRegisterSpec(tool_names))
enforced = agent.enforce_policy(binding.enforcer.policy, approval_handler=approval_handler)
enforced._binding = binding
enforced._policy_source = binding.source     # back-compat alias, see 4.2
enforced.hexgate_client = binding.client
```

**No streaming changes.** `_refresh_policy_safely` already fires at the top
of `stream_agent` / `stream_agent_raw` / `invoke_agent`
(`factory.py:579,600`), and `with_tools` already propagates the seam across
rebuilds (`factory.py:365-379`). `HexgateAgent.refresh_policy` becomes a
delegation to `self._binding.refresh()` when a binding is present, keeping
the legacy `_enforcer`/`_policy_source` attribute path working for code that
attached them by hand.

Auto-register default: **on** for the `create_agent` binding path (the agent
was authored in code; registering it is what makes the dashboard useful) —
mirrors the `hexgate serve` UX introduced in `bd925a9`/`71586c2`.

### 4.2 Loader dedupe (hexgate/agents/loader.py)

`load_hexgate_agent` (`loader.py:528`) keeps its public contract but its
policy-precedence block (`loader.py:597-636`) becomes:

```python
binding = PolicyBinding.resolve(
    resolved_name,
    client=client,
    prefetched=(payload, initial_etag),   # no second fetch
)
enforced = enforce_policy(agent, binding.enforcer.policy, approval_handler=...)
enforced._binding = binding
enforced.hexgate_client = binding.client
```

`prefetched` matters: the loader needs the payload for `agent_yaml` /
`system_md` *before* the agent exists; passing it through keeps the load a
single round trip. ~40 duplicated lines deleted; the two paths can no longer
drift. `load_local_agent` keeps its current shape (static policy from disk +
optional local-override source) but routes the override resolution through the
moved helpers.

**Back-compat invariants:** `_enforcer` and `_policy_source` remain readable
attributes (tests and `with_tools` propagation rely on them). They become
views over the binding (`_enforcer ≡ binding.enforcer`,
`_policy_source ≡ binding.source`).

### 4.3 LangChain BYO-graph (adapters/langchain/wrapper.py, agent.py)

`wrap_langchain_agent` (`wrapper.py:34`):

```python
binding = PolicyBinding.resolve(
    agent_name,
    api_key=resolved_key,
    auto_register=AutoRegisterSpec(tool_names),
)
install_enforcer_on_tools(tools, enforcer=binding.enforcer)   # unchanged mechanics
return HexgateLangchainAgent(agent=agent, binding=binding, tool_names=tool_names)
```

`build_policy_set` is **deleted**. `HexgateLangchainAgent`
(`adapters/langchain/agent.py:15`) stores the binding and refreshes at every
run boundary:

| method | refresh call |
|---|---|
| `ainvoke`, `astream`, `astream_events` | `await self._binding.refresh_async()` (first line, before entering the User scope) |
| `invoke`, `stream` | `self._binding.refresh()` (first line) |

The graph and its in-place-mutated tools are never touched again — only
`enforcer.policy` swaps.

### 4.4 OpenAI Agents (adapters/openai/wrapper.py, runner.py)

The OpenAI `HexgateRunner` receives the agent **per call**
(`runner.py:59-125`) and currently re-wraps it (and would re-resolve a fresh
binding) on every run — which would defeat the ETag cache. Spec:

- `HexgateRunner` gains a binding cache: `self._bindings: dict[str, PolicyBinding]`.
- New private helper:

```python
def _binding_for(self, agent: Agent) -> PolicyBinding:
    name = getattr(agent, "name", "default")
    binding = self._bindings.get(name)
    if binding is None:
        binding = PolicyBinding.resolve(
            name, api_key=self.api_key,
            auto_register=AutoRegisterSpec([t.name for t in agent.tools]),
        )
        self._bindings[name] = binding
    return binding
```

- `wrap_openai_agent` changes signature to accept the enforcer (or binding)
  instead of building its own placeholder:
  `wrap_openai_agent(agent, enforcer=binding.enforcer)` → tool copies via
  `wrap_tools` (`adapters/openai/tools.py:53`), mechanics unchanged. Re-
  wrapping per call stays (it's cheap `copy.copy` of `FunctionTool`s and the
  agent arrives per call anyway); the **enforcer** is the cached, shared
  object, so refresh reaches every copy.
- Run methods:
  - `run` (async): `binding = self._binding_for(agent)` →
    `await binding.refresh_async()` → wrap → run inside the User scope.
  - `run_sync`: same with `binding.refresh()`.
  - `run_streamed`: **refresh synchronously in the setup body, before
    `Runner.run_streamed` is called.** Tools execute later, during
    `stream_events` iteration, but they hold the enforcer reference fixed at
    wrap time — and the policy they consult is whatever the enforcer holds
    when the tool actually fires. Refreshing at setup satisfies the
    "refresh before the run's first tool call" contract. (A second refresh
    inside `_stream_events_with_scope` is *not* added: one refresh per run.)

First call for an agent name = full resolve (200 + verify [+ register]);
subsequent calls = 304s against the cached source.

### 4.5 Google ADK (adapters/google/wrapper.py, runner.py)

The Google `HexgateRunner` wraps **once at construction**
(`runner.py:42` — "Policy is baked at construction") and reuses the built
ADK `Runner`. Spec:

- `__init__`: `self._binding = PolicyBinding.resolve(agent_name,
  api_key=self.api_key, auto_register=AutoRegisterSpec(tool_names))`;
  `wrap_google_agent(agent, enforcer=self._binding.enforcer)`; ADK `Runner`
  built once, as today. Construction becomes the loud-failure point (network,
  signature, 404-without-register all raise here).
- `run` (sync generator): `self._binding.refresh()` first line, before
  `user.sync_scope()`.
- `run_async` (async generator): `await self._binding.refresh_async()` first
  line.

The pre-built `Runner` and the `model_copy`'d agent never change; the
enforcer swap is invisible to ADK.

### 4.6 pydantic_ai (adapters/pydantic_ai/wrapper.py, agent.py)

Same pattern as LangChain:

- `wrap_pydantic_agent` resolves the binding (auto-register from the
  extracted tool names), wraps the cloned toolset with
  `binding.enforcer`, deletes its `build_policy_set`, and passes the binding
  into `HexgatePydanticAgent`.
- `HexgatePydanticAgent` run methods: `await self._binding.refresh_async()`
  (async) / `self._binding.refresh()` (sync) as their first line.

---

## 5. Failure semantics — one matrix, all surfaces

The governing rule, inherited from the loader and made universal:
**construction is fail-loud, refresh is fail-soft (to staleness only).**

| Event | When | Behavior |
|---|---|---|
| `HEXGATE_API_KEY` malformed / Biscuit signature invalid | resolve | raise (`HexgateError`) |
| Platform unreachable | resolve | raise — caller decides; never run on a policy we never had |
| Platform unreachable | refresh | warn + keep previous verified policy (unbounded staleness — see §8.3) |
| Bundle signature/integrity fails | resolve | raise; never downgrade to pydantic engine |
| Bundle signature/integrity fails | refresh | raise inside `source.fetch()` → caught → warn + keep previous policy (tamper cannot install itself) |
| Platform serves no bundle (no `opa` on control plane) | resolve | pydantic engine on `policy_yaml`; raise if `HEXGATE_BUNDLE_REQUIRE_SIGNATURE` |
| Agent 404 on platform | resolve | auto-register (when spec provided) → re-fetch; else raise `PolicyBindingError` |
| Agent 404 | refresh | treated as fetch failure → warn + keep previous (agent deleted mid-session keeps last policy; see §8.3) |
| No key, no local override, no `fallback` | resolve | raise — **replaces the adapters' silent allow-all** |
| `HEXGATE_LOCAL_POLICY` set but broken (bad yaml, missing opa, bad sig) | resolve & refresh | raise loudly (today's rule — silently degrading a security override defeats it, `loader.py:206-209`) |
| Tool name in wrapped agent absent from fetched policy | resolve | `logger.warning` listing uncovered tools (they will be denied-by-absence at call time) |

---

## 6. Security invariants (must hold after the refactor)

1. **Single trust root.** The platform's Ed25519 root key signs both
   Biscuits (`HEXGATE_API_KEY`) and bundle manifests; the SDK verifies both
   against the same key (explicit → `HEXGATE_PUBLIC_KEY` → JWKS TOFU).
2. **No silent downgrade.** A served-but-unverifiable bundle is fatal at
   resolve and inert at refresh. The pydantic fallback is only reachable
   when the platform *affirmatively served no bundle*, and
   `HEXGATE_BUNDLE_REQUIRE_SIGNATURE` closes even that.
3. **No silent allow-all.** Removing `build_policy_set` removes the last
   construction path that runs ungoverned with a `HEXGATE_API_KEY` present.
   Ungoverned operation requires an explicit `fallback=` or
   `bind_policy=False` in the caller's code.
4. **Verification happens before caching.** `PlatformPolicySource` only
   caches bundles that passed signature + integrity; the 304 path can only
   return previously verified objects.
5. **Role resolution stays call-time.** `PolicyEnforcer.decide` re-reads the
   `User` contextvar per tool call (`enforcer.py:42-44`); binding/refresh is
   user-agnostic. One binding safely serves many concurrent users.
6. **Refresh can deny freshness, never grant access.** The worst a
   compromised refresh channel can do is keep an old (verified) policy in
   force.

---

## 7. Platform contract (existing, consumed as-is)

| Endpoint | Use | Notes |
|---|---|---|
| `GET /v1/agents/{name}` (bearer) | resolve + refresh | project from token; `ETag: "<sha256(wasm)>"`; `If-None-Match` → `304` (`platform/api/main.py:857-893`) |
| `POST /v1/agents` (bearer) | auto-register on 404 | first register generates default role-aware policy + signed bundle; re-register never touches `policy_yaml` (`main.py:829`, `services.py:1290`) |
| `GET /v1/.well-known/keys` | trust bootstrap | JWKS TOFU when no key pinned (`cloud/client.py:234`) |
| `PUT /v1/projects/{id}/agents/{name}` (dashboard) | not called by SDK | save-time recompile + re-sign via `build_signed_bundle` — the producer of what we pull (`services.py:911`) |

Payload contract (`_agent_read`, `main.py:577`): `agent_yaml`, `policy_yaml`,
`system_md`, `bundle_wasm_b64`, `bundle_manifest` (exact signed bytes as
text), `bundle_signature_b64`.

---

## 8. Behavior changes, migration, and known gaps

### 8.1 Breaking-ish changes (changelog required)

1. **Adapters: allow-all → real policy.** Wrapped OpenAI/Google/pydantic_ai/
   LangChain agents go from "everything allowed" to "whatever the platform
   says", with deny-by-absence for unlisted tools. Mitigated by
   auto-register's generated default policy covering the agent's actual tool
   names; surfaced by the §5 uncovered-tools warning.
2. **Adapters: missing/unreachable platform now raises at wrap/construct**
   instead of silently running open. Escape hatch: `fallback=`.
3. **`create_agent` with `HEXGATE_API_KEY` set + a `name`** now binds by default
   (auto mode). Programmatic callers who want a bare graph in a keyed
   environment pass `bind_policy=False`.

### 8.2 Non-changes

- `stream_agent` / `invoke_agent` / `hexgate serve` behavior is identical.
- Loaders' public signatures are identical.
- Enforcement outcomes (`ALLOW` / `NEEDS_APPROVAL` / `DENY` rendering per
  adapter) are identical.

### 8.3 Known gaps carried forward (explicitly out of scope, tracked)

1. **Unbounded staleness on refresh failure.** No max-staleness TTL; a
   platform outage keeps the last verified policy in force indefinitely
   (one warning per run). A future `HEXGATE_POLICY_MAX_STALENESS` knob can
   harden revocation scenarios.
2. **`_WasmPolicyCache` is unwired.** `WasmPolicy.from_bytes_cached`
   (`wasm_engine.py:169`) has no production call sites;
   `PolicyBundle.policy()` calls `from_bytes` directly (`bundle.py:275`). A
   `200` whose wasm bytes are unchanged (e.g. a non-policy field edit) pays a
   fresh ~50–100 ms wasmtime instantiation. Fix (small, recommended rider):
   `policy()` → `WasmPolicy.from_bytes_cached(self.wasm_bytes,
   self.wasm_hash)` when `wasm_hash` is present.
3. **Non-`BaseTool` specs pass `enforce_policy` unguarded**
   (`factory.py:415-426`) — pre-existing; unchanged by this spec but worth a
   warning log in a follow-up.

---

## 9. Test plan

### 9.1 Core (`tests/security/test_policy_binding.py`)

- precedence: local override beats platform beats fallback; no key + no
  fallback raises.
- resolve: 200 → verified bundle, source pre-seeded (next fetch sends
  `If-None-Match`); bundle-less payload → pydantic engine;
  `REQUIRE_SIGNATURE` blocks the fallback; bad signature raises; 404 +
  auto-register → registers then binds; 404 without → raises.
- refresh: 304 → no swap (object identity), one HTTP call; 200 → swap, old
  decisions change on next `decide`; fetch exception → warn + keep policy;
  tampered 200 → warn + keep policy; concurrent refreshes serialize (lock).
- `prefetched` short-circuits the resolve fetch (call count == 0).

### 9.2 Factory/loader

- `create_agent(name=..., bind_policy=True)` with mocked client: tools are
  `GuardedTool`s, `_policy_source`/`_binding` present, `stream_agent` issues
  the conditional GET.
- auto mode: no key → bare agent unchanged, `refresh_policy()` no-ops.
- `bind_policy=True` without `name` → `ValueError`.
- `load_hexgate_agent` regression suite passes unmodified (dedupe is
  behavior-preserving); single round-trip asserted via mock call count.
- `with_tools` rebuild keeps `_binding` reachable.

### 9.3 Per adapter (×4, same skeleton)

- wrap pulls platform policy: a platform deny rule blocks the tool (assert
  the framework-appropriate error rendering).
- second run sends `If-None-Match`; 304 keeps enforcer.policy identity.
- platform policy updated between runs → next run enforces the new policy.
- platform down at refresh → run proceeds on previous policy + warning.
- wrap with unreachable platform raises; `fallback=` allows it.
- OpenAI-specific: binding cached across `run` calls (resolve once);
  `run_streamed` refreshes before setup; per-call rewrap shares the cached
  enforcer.
- Google-specific: construct-time failure raises; refresh fires per
  `run`/`run_async` without rebuilding the ADK `Runner`.
- concurrency smoke: two concurrent runs on one proxy/runner, single fetch.

### 9.4 End-to-end (against the platform test app)

Extend `platform/api/tests/test_agents.py` style: register → wrap (each
adapter) → run (denied tool) → edit policy via `PUT` → run again →
allowed/denied flips; assert exactly one `200` and N `304`s on the agent
endpoint.

---

## 10. Implementation phases

Each phase lands green and independently shippable.

| Phase | Content | Files |
|---|---|---|
| **1** | `PolicyBinding` + `AutoRegisterSpec` + move loader env-override helpers; core tests | `hexgate/security/binding.py` (new), `hexgate/agents/loader.py` (re-import), `tests/security/test_policy_binding.py` |
| **2** | Loader dedupe onto `PolicyBinding` (with `prefetched`); `HexgateAgent.refresh_policy` delegates to binding; back-compat aliases | `hexgate/agents/loader.py`, `hexgate/agents/factory.py` |
| **3** | `create_agent(bind_policy=...)` + auto mode | `hexgate/agents/factory.py`, tests |
| **4** | LangChain BYO adapter (smallest delta; validates the adapter pattern) | `adapters/langchain/wrapper.py`, `adapters/langchain/agent.py` |
| **5** | Google adapter (construct-once shape) | `adapters/google/wrapper.py`, `adapters/google/runner.py` |
| **6** | OpenAI adapter (binding cache, `run_streamed` ordering) | `adapters/openai/wrapper.py`, `adapters/openai/runner.py` |
| **7** | pydantic_ai adapter | `adapters/pydantic_ai/wrapper.py`, `adapters/pydantic_ai/agent.py` |
| **8** | Rider: wire `from_bytes_cached` into `PolicyBundle.policy()`; delete the four `build_policy_set` placeholders' remaining references; changelog | `hexgate/security/bundle.py`, docs |

---

## 11. Resolved decisions (rationale recorded)

| Decision | Choice | Why |
|---|---|---|
| Eager vs lazy first fetch | **Eager** in `resolve()` | loud failures at construction; refresh's fail-soft would otherwise leave the first run unguarded or bricked |
| 404 at resolve | **auto-register by default at adapter/`create_agent` surfaces**, raise otherwise | platform mints a safe default policy + signed bundle (`71586c2`); matches `hexgate serve` UX; idempotent re-registers protect dashboard edits |
| Adapters' default without platform | **raise** (no more silent allow-all) | a present `HEXGATE_API_KEY` signals governance intent; ungoverned must be explicit (`fallback=`) |
| Refresh failure | **warn + keep previous verified policy** | availability over freshness; tamper still cannot install itself |
| Refresh granularity | **per run/turn** | matches `stream_agent` today; per-tool-call adds a network call to the hot path for negligible win |
| Sync entry points | direct blocking `refresh()` | ~ms HTTP on a thread already doing sync I/O; `to_thread` only for async paths |
| Concurrency | `threading.Lock` around refresh | proxies are multi-user; collapse duplicate fetches; swap itself already atomic |
| Where the code lives | `hexgate/security/binding.py` | importable by factory, loader, and all adapters without cycles; security logic stays in `security/` |
