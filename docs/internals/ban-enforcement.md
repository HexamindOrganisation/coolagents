# Bans & Ban Enforcement — Design and Logic

> **Status:** Reflects the shipped implementation. Deferred hardening is called out as
> *known issues worth addressing in later PRs* where relevant (see §9).
>
> **Primitive name:** `Ban` (model), `features/bans/` (API slice), `/v1/bans` (SDK feed),
> `AgentBannedError` (SDK error), `ban_enforcement` (ClickHouse telemetry table). The dashboard
> surfaces this as the **Bans** page.

---

## 1. What a ban is

A **ban** is an operator-controlled, **override-everything denylist entry** that refuses
execution **before the LLM runs**. It is deliberately *not* part of the policy engine — it is
a separate primitive evaluated *around* policy, at a new invoke-time gate.

There are exactly **two ban types**:

| Type | Blocks | Scope | Matched against |
|------|--------|-------|-----------------|
| **`agent`** | one agent, for **all** users | project | the agent's `agent_name` |
| **`user`**  | one `user_id`, across **all** agents | project | `user.user_id` from the runtime `HexgateContext` scope |

Key properties:

- **Project-scoped.** A ban lives under one project and never crosses projects. (User bans are
  project-wide, matching the SDK's project-scoped biscuit auth; org-wide user bans are deferred.)
- **Overrides policy.** The gate refuses before policy is ever consulted, so a ban inherently
  wins over any `allow` / `needs_approval` decision.
- **Refuses before the model runs.** No tokens are spent, no tool fires — the run raises (or, on
  a stream, refuses before the first chunk).
- **No expiry (v1).** A ban is *active* while `revoked_at` is null. Lifting a ban is a **soft
  delete** that preserves the who/when trail. Time-based expiry is a known gap (see §9).
- **One active ban per target.** Enforced in the service layer (SQLite has no reliable partial
  unique index), not by a DB constraint.
- **Fail-soft.** A control-plane blip never crashes a run; the SDK keeps the last-good ban set.

> **Not a ban:** tool-level blocking ("ban just tool X of agent Y"). That is covered by ordinary
> policy (`deny` the tool). v1 has only the two "don't run at all" ban types.

---

## 2. Architecture at a glance

```
                    DASHBOARD (cookie auth, project-admin)
                    ─────────────────────────────────────
  operator ── Create/Revoke ──▶  POST/GET/DELETE
                                 /v1/projects/{pid}/bans
                                        │
                                        ▼
        ┌──────────────────────────────────────────────────┐
        │  CONTROL-PLANE API  (platform/api)                 │
        │  features/bans/{router,service}.py                 │
        │                                                    │
        │   Ban rows  ──────────────▶  RELATIONAL DB         │
        │   (SQLModel / SQLite)         table: ban            │
        └──────────────────────────────────────────────────┘
                                        │
                     GET /v1/bans (bearer/biscuit, ETag)
                                        │  active bans only
                                        ▼
        ┌──────────────────────────────────────────────────┐
        │  SDK  (hexgate/security/bans.py)                   │
        │                                                    │
        │  PlatformBanSource  ──fetch()──▶ BanSet (cached)   │
        │        │  shared per (api-key, base-url)           │
        │        ▼                                           │
        │  BanGate.check() / .check_async()                  │
        │        │  runs in every adapter's run path         │
        │        │  BEFORE the LLM                           │
        │        ├── hit? ── emit BanEnforcementEvent ──┐    │
        │        │          raise AgentBannedError      │    │
        │        └── miss? ── continue to policy/LLM     │   │
        └──────────────────────────────────────────────┼────┘
                                                        │
                   POST /v1/audit/ban-enforcements (bearer, fire-and-forget)
                                                        ▼
        ┌──────────────────────────────────────────────────┐
        │  ClickHouse  hexgate_audit.ban_enforcement         │
        │  (blocked attempts; 90-day TTL)                    │
        └──────────────────────────────────────────────────┘
                                        ▲
        GET /v1/projects/{pid}/audit/ban-enforcements (cookie, project-admin)
                                        │
              Dashboard "Blocked attempts" panel + drawer
```

Two distinct stores:

- **The ban rules** live in the **relational config DB** (SQLModel / SQLite) — mutable, soft-deletable.
- **The blocked attempts** (one row per refused run) live in **ClickHouse** — append-only telemetry.

---

## 3. Data model & storage

### 3.1 The `Ban` table (relational config DB)

`platform/api/hexgate_api/models.py:312`

```python
class Ban(SQLModel, table=True):
    """A hard block overriding policy for one agent or user_id, project-scoped.

    Active while ``revoked_at`` is null; revoke is a soft delete keeping the
    who/when trail (the row is the audit record). One active ban per target,
    enforced in the service like Invitation (no SQLite partial index).
    """
    id: str = Field(primary_key=True)                 # new_id(Ban) -> "ban_…"
    project_id: str = Field(foreign_key="project.id", index=True)
    ban_type: str = Field(index=True)                 # "agent" | "user"
    # Exactly one set, matching ban_type; a user ban leaves this null.
    target_agent_name: Optional[str] = Field(default=None, index=True)
    target_user_id:    Optional[str] = Field(default=None, index=True)
    reason: Optional[str] = None
    created_by_user_id: str = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(default_factory=utcnow, sa_type=DateTime(timezone=True))
    revoked_at: Optional[datetime] = Field(default=None, sa_type=DateTime(timezone=True))
    revoked_by_user_id: Optional[str] = Field(default=None, foreign_key="user.id")
```

- **Active ⇔ `revoked_at IS NULL`.** There is no status enum.
- Indexed on everything the queries filter by: `project_id`, `ban_type`, `target_agent_name`,
  `target_user_id`, `created_by_user_id`.
- The row *is* its own control-plane audit record: it keeps `created_by`/`created_at` and, once
  lifted, `revoked_by`/`revoked_at`.

### 3.2 Ban ID format

`platform/api/hexgate_api/core/ids.py`

```python
_ID_PREFIXES = { Agent: "agt", AgentVersion: "agv", Tool: "tol", DevToken: "tok", Ban: "ban" }

def new_id(kind: type) -> str:
    return f"{_ID_PREFIXES[kind]}_{secrets.token_hex(6)}"
```

A ban id is `ban_` + 12 hex chars (6 bytes of `secrets` entropy), e.g. `ban_a1b2c3d4e5f6`.

### 3.3 The `ban_enforcement` table (ClickHouse — blocked attempts)

`platform/clickhouse/init/schema.sql:46`

```sql
CREATE TABLE IF NOT EXISTS hexgate_audit.ban_enforcement
(
    -- Envelope (shared with policy_decision — same names, types, order)
    event_id            UUID,
    occurred_at         DateTime64(3, 'UTC'),
    received_at         DateTime64(3, 'UTC') DEFAULT now64(3),
    project_id          LowCardinality(String),
    agent_name          LowCardinality(String),
    agent_version_id    LowCardinality(String) DEFAULT '',
    session_id          String DEFAULT '',
    user_id             LowCardinality(String) DEFAULT '',

    -- Ban-specific
    ban_type            Enum8('agent' = 1, 'user' = 2),
    ban_id              LowCardinality(String),
    reason              String
)
ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(received_at)
ORDER BY (project_id, occurred_at, event_id)
TTL toDateTime(received_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

- **Sibling of `policy_decision`**, sharing the audit envelope. Kept as a *separate* table on
  purpose (see §9) so the tool-decision Audit views stay pure and coherent.
- `ReplacingMergeTree(received_at)` dedups by the sort key `(project_id, occurred_at, event_id)` —
  an SDK retry carrying the same `event_id` collapses on a background merge (reads are eventually
  consistent; no `FINAL`).
- Monthly partitions on `received_at`; **90-day TTL**.
- Carries **no** `tool_name`/`role`/`arguments`/`outcome` — a ban is refused *before* any tool
  call, so those dimensions don't exist for a blocked attempt.

---

## 4. End-to-end lifecycle

### 4.1 Creating a ban (dashboard → API)

**UI:** `platform/dashboard/src/components/bans/CreateBanDialog.tsx`, opened from the Bans page
(`routes/Bans.tsx`) or the empty-state button in `ActiveBansPanel`.

The operator fills:

- **Type** — Agent / User toggle (default `agent`).
- **Target** — if agent: a `Select` populated from `api.listAgents(projectId)` (fetched lazily
  only when the dialog is open); if user: a free-text `user_id` input.
- **Reason** (optional) — free text; shown later in the blocked-attempts feed.

The `useCreateBan` hook (`lib/bans.ts`) POSTs to `/v1/projects/{projectId}/bans` with
`credentials: "include"` and a body that carries **only the one matching target field**:

```ts
const body = { ban_type: input.ban_type };
if (input.ban_type === "agent") body.target_agent_name = input.target_agent_name;
else                            body.target_user_id    = input.target_user_id;
if (input.reason) body.reason = input.reason;
```

On success it invalidates the `["bans", projectId]` query cache, toasts "Ban created", and closes.

**Permission gating.** `useCanManageBans()` returns true only for org role `owner`/`admin`. The
Bans page hard-blocks non-admins with an `AdminRequiredNotice` rather than rendering tables that
would 403.

**Cross-page tie-ins.** `Bans.tsx` reads `?ban_user=` / `?ban_agent=` query params to pre-fill and
auto-open the dialog (clearing the params on close), so the Audit page's "Ban user" affordance and
the Agents page's "Ban agent" affordance can deep-link here.

**Server side** (`features/bans/router.py:53`, `service.py:47`):

1. `BanCreate` validation (`schemas.py:168`) enforces "exactly one target matching `ban_type`" via
   a `model_validator`; a mismatched shape is a **422**.
2. `create_ban()` first runs `_active_ban_for_target()` — if an active ban already targets this
   agent/user, it raises `BanConflictError` → **409**.
3. Otherwise it inserts a fresh `Ban` (`id = new_id(Ban)`, `created_by_user_id` = the authenticated
   caller), commits, and returns a `BanRead` (with `created_by_email` = the caller's email, no lookup).

### 4.2 Serving the feed to the SDK

`GET /v1/bans` (`router.py:116`) is the **SDK-facing feed** — bearer/biscuit auth via
`require_project`, project resolved from the token (no per-agent param):

```python
rows = await active_bans_for_project(session, project_id=project_id)  # active only, ORDER BY id
entries = [_feed_entry(b) for b in rows]                              # BanFeedEntry
body = json.dumps([e.model_dump() for e in entries], sort_keys=True).encode()
etag = f'"{hashlib.sha256(body).hexdigest()}"'
if if_none_match and if_none_match.strip() == etag:
    return Response(status_code=304, headers={"ETag": etag})
response.headers["ETag"] = etag
return entries
```

- Only **active** bans are served (`active_bans_for_project`, `service.py:136`, ordered by `id`
  for a deterministic ETag).
- The wire shape (`BanFeedEntry`, `schemas.py:210`) is deliberately minimal — `ban_id`, `ban_type`,
  `target_agent_name`, `target_user_id`, `reason`. No `created_by`/timestamps leak to the SDK.
- The **ETag** is the SHA-256 of the sorted-JSON body, enabling cheap `304 Not Modified` responses.

> The feed is intentionally decoupled from the per-agent policy fetch (`GET /v1/agents/{name}`) so
> toggling a ban doesn't bust every agent's policy ETag, and so it can carry **cross-agent user
> bans** that can't live in any single agent's policy.

### 4.3 Pulling bans on the SDK side

All in `hexgate/security/bans.py`. The feed is project-scoped, so the source and sink are **shared
per api-key** via module registries (unlike the per-agent policy source).

**HTTP.** `HexgateClient.get_bans(if_none_match=...)` (`cloud/client.py:194`) hits
`GET {base_url}/v1/bans` with `Authorization: Bearer {key}` and returns `(payload, etag)`;
`payload is None` on a 304. Conditional GETs use the tighter `refresh_timeout`.

**Cache + parse.** `PlatformBanSource.fetch()` serializes read-etag → HTTP → write-cache under a
lock, then indexes the body:

```python
def ban_set_from_payload(entries):
    # non-list body / non-dict entry -> BanContentError (contract drift, logged loudly)
    for raw in entries:
        entry = BanEntry(ban_id=..., ban_type=..., target_agent_name=..., target_user_id=..., reason=...)
        if   entry.ban_type == "agent" and entry.target_agent_name: by_agent[...] = entry
        elif entry.ban_type == "user"  and entry.target_user_id:    by_user[...]  = entry
        else:  # unknown type or blank target -> DROP and WARN (unenforceable)
            logger.warning("dropping unenforceable ban %s ...", entry.ban_id)
    return BanSet(by_agent, by_user)
```

The result is an immutable `BanSet` with two O(1) lookups: `agent_ban(name)` and `user_ban(uid)`.

**Fail-soft.** `fetch()` **never raises**. On a malformed 200 (`BanContentError`) it logs ERROR and
returns last-good; on any transient error it logs WARNING and returns last-good. A cold-start
failure with nothing cached degrades to `EMPTY_BAN_SET` (fail-*open*, never a prior restrictive
state).

**Refresh cadence.** There is **no background poll**. `BanGate` calls `source.fetch()` on **every
run** (once per invocation); the ETag/304 keeps each call cheap (a 304 returns the cached object by
identity).

**Sharing.** `get_ban_source(api_key, client)` keys the source cache on
`(api_key, client.config.base_url)` — same key + platform share one cache; the same key against
staging vs prod get distinct sources.

### 4.4 Enforcing at runtime

The gate is `BanGate` (`bans.py:227`). It is per-agent but points at the shared source, and decides:

```python
def _decide(self, bans, context):
    # Agent ban checked FIRST so a coincident agent+user ban emits a deterministic ban_type/ban_id.
    hit = bans.agent_ban(self._agent_name)
    if hit is None and context is not None:
        hit = bans.user_ban(context.user_id)
    if hit is None:
        return
    self._emit(hit, context)                    # fire-and-forget telemetry (§4.5)
    target = hit.target_agent_name if hit.ban_type == "agent" else hit.target_user_id
    raise AgentBannedError(
        ban_type=hit.ban_type, target=target or "",
        code=f"{hit.ban_type}_banned", reason=hit.reason,
    )
```

Two entry points:

- `check(context)` — sync: fetch (fail-soft) → decide.
- `check_async(context)` — fetches off-loop via `asyncio.to_thread`, then decides + emits + raises
  **on the loop** (the fire-and-forget `AuditSender` only adopts a running loop on its on-loop path,
  so emitting from the worker thread would drop the event).

**Precedence.** Agent ban wins over a coincident user ban. When `context is None`, only the agent
dimension is evaluated. Tool-level bans don't exist on the SDK side.

**The exception.** `AgentBannedError` (`hexgate/security/errors.py:14`) is a `RuntimeError` enriched
so integrators can localize UX or show a default verbatim:

```python
class AgentBannedError(RuntimeError):
    ban_type: str        # "agent" | "user"
    target: str          # agent_name or user_id
    code: str            # "agent_banned" | "user_banned" — stable, machine-checkable
    reason: str | None   # operator-supplied, may be None
    user_message: str    # sensible default, safe to show verbatim:
        # agent:  "This agent is currently disabled by an administrator."
        # user:   "Your access to this agent has been suspended by an administrator."
```

The ban surfaces as a **typed error, never a disguised assistant message** — it can't be mistaken
for model output, isn't written to history, and hands the integrator's backend an explicit catch
point. On **streaming** entrypoints the check runs *before the first chunk*, so a banned run yields
nothing (no partial output, no fake terminal message).

**Where the gate is composed in — all four adapters + the native factory:**

| Integration | Gate resolution | Fired in (after policy refresh, before the LLM) |
|-------------|-----------------|--------------------------------------------------|
| **Native factory** (`agents/factory.py`) | threaded through `with_tools` rebuilds; user is **ambient** via `get_current_context()` | `ainvoke`, `astream_events` (via `_check_ban()`) |
| **OpenAI** (`adapters/openai/runner.py`) | lazy per-agent cache `_ban_gate_for` | `run` (async), `run_sync`, `run_streamed` (before the background task spawns) |
| **Google ADK** (`adapters/google/runner.py`) | single gate at construction | `run` (sync generator), `run_async` |
| **LangChain** (`adapters/langchain/agent.py`) | injected via wrapper | `invoke`, `ainvoke`, `stream`, `astream`, `astream_events` |
| **Pydantic-AI** (`adapters/pydantic_ai/agent.py`) | injected via wrapper | `run`, `run_sync`, `run_stream`, `iter` |

The wiring entry point is `resolve_ban_gate(agent_name, api_key=..., client=...)` (`bans.py:307`),
which returns **`None`** — and callers then skip the check entirely — for every "no platform" case:
`HEXGATE_LOCAL_MODE`, `HEXGATE_LOCAL_POLICY` (offline local-policy dev), or no resolvable API key.
`PolicyEnforcer.decide()` and the per-tool-call hot path are **never modified** by any of this.

> **Note:** non-wrapped adapter methods (e.g. LangChain `batch`/`abatch`/`astream_log`, pydantic-AI
> `to_a2a`/`to_ag_ui`, or accessing the native factory's `._graph` directly) bypass the gate — this
> is documented at each call site.

### 4.5 Reporting a blocked attempt

Before raising, `BanGate._emit()` fires a **`BanEnforcementEvent`** at the shared `AuditSender`
(fire-and-forget). Its payload:

```python
{
  "event_id": str(uuid4), "occurred_at": iso8601,
  "agent_name": ..., "user_id": ... or "", "session_id": ... or "",
  "ban_type": ..., "ban_id": ..., "reason": ... or "",
}
```

- **Endpoint:** `POST {base_url}/v1/audit/ban-enforcements` (bearer). Server-resolved fields
  (`project_id`, `agent_version_id`, `received_at`) are deliberately omitted from the SDK payload.
- **Sink:** `configure_ban_sink()` gets-or-creates an `AuditSender` keyed on the path constant
  `/v1/audit/ban-enforcements`; it's distinct from the decisions/usage senders even for the same
  key, and is `None` in local mode / without a key. Drained by the existing `audit.shutdown`.
- **Best-effort:** if the sink is `None` (or, on a sync entrypoint with no running loop, was built
  off-loop) the event is dropped — **the refusal itself is unaffected**.

**Ingest** (`features/audit/router.py:103`): `ingest_ban_enforcement` validates the event window,
resolves `agent_version_id` from the latest agent version, and inserts into `ban_enforcement` via
`asyncio.to_thread(insert_ban_enforcement, ...)`. It's idempotent on `event_id`, returns **202**,
maps transient ClickHouse transport errors to 503 and hard rejections to 422. `received_at` is
stamped server-side by the DDL default.

### 4.6 Viewing blocked attempts (dashboard)

`GET /v1/projects/{project_id}/audit/ban-enforcements` (`features/audit/router.py:275`,
cookie + project-admin) reads `list_ban_enforcements` (`features/audit/service.py:528`):

```sql
SELECT event_id, occurred_at, received_at, agent_name, session_id, user_id,
       ban_type, ban_id, reason,
       count() OVER () AS total_matches
FROM ban_enforcement
WHERE <project + window scope>
ORDER BY occurred_at DESC, event_id DESC   -- event_id breaks ms-precision ties into a total order
LIMIT {lim:UInt32} OFFSET {off:UInt32}
```

- Scoped by **project + time window only** (no tool/role/user filters — those dimensions don't
  exist for a ban). Window is either an explicit `start_date`/`end_date` range or a sliding
  `now() - INTERVAL {hrs} HOUR`.
- `count() OVER ()` returns the full pre-LIMIT match total in the same scan (the paginated
  `BanEnforcementPage` exposes `rows` + `total` + `limit` + `offset`).
- `policy_decision` is untouched by this read.

**UI:** `BlockedAttemptsPanel` renders **Time / Type / Target / Reason** with a window toggle
(24h / 7d / 30d / 90d) and a "Load more" button that grows `limit` by a page size. Clicking a row
opens `BlockedAttemptDrawer`, a slide-over showing the full enforcement detail (target, "refused
before the model ran" banner, ban type/target/agent/user/session/`ban id`/reason, and timing:
occurred / received / event id).

### 4.7 Revoking (lifting) a ban

**UI:** the Revoke action in `ActiveBansPanel` opens a `ConfirmDialog` ("Revoke ban?", noting the
target can run again "on the next run"); on confirm `useRevokeBan` DELETEs
`/v1/projects/{projectId}/bans/{banId}` and invalidates `["bans", projectId]`.

**Server** (`revoke_ban`, `service.py:110`): a **soft delete** — the same row is mutated in place,
setting `revoked_at = utcnow()` and `revoked_by_user_id`. It is:

- **Project-scoped** — an unknown/cross-project id raises `BanNotFoundError` → **404**.
- **Idempotent** — already-revoked is a no-op.
- **Never a hard delete and never a new row** — the row remains as the audit record.

After revoke the ban disappears from the active feed (so the target's **next run** is allowed) and
from the default list view (visible only with `include_revoked=true`). Existing `ban_enforcement`
rows are **not** affected — those historical blocked attempts persist until the 90-day TTL.

> **Propagation latency.** Because the SDK re-checks the feed at the start of each run, a create or
> revoke takes effect on the target's **next run**; an in-progress run is not interrupted. There is
> no push invalidation in v1 (a known gap; see §9). The dashboard sets this expectation in its copy.

---

## 5. REST API reference

All ban routes live in `features/bans/router.py`; the enforcement telemetry routes live in the
`audit` slice. Routes are declared without the `/v1` prefix in the router — it's added at mount time.

| Method | Path | Auth | Success | Body / Params | Returns |
|--------|------|------|---------|---------------|---------|
| `POST` | `/v1/projects/{project_id}/bans` | cookie, project-admin | 201 | `BanCreate` | `BanRead` |
| `GET` | `/v1/projects/{project_id}/bans` | cookie, project-admin | 200 | `?include_revoked=bool` (default false) | `list[BanRead]` |
| `DELETE` | `/v1/projects/{project_id}/bans/{ban_id}` | cookie, project-admin | 204 | path `ban_id` | — |
| `GET` | `/v1/bans` | bearer/biscuit, project | 200 / 304 | header `If-None-Match` | `list[BanFeedEntry]` |
| `POST` | `/v1/audit/ban-enforcements` | bearer, project | 202 | `BanEnforcementEvent` | `BanEnforcementAccepted` |
| `GET` | `/v1/projects/{project_id}/audit/ban-enforcements` | cookie, project-admin | 200 | window + `limit`/`offset` | `BanEnforcementPage` |

**Error codes:** `POST /bans` → 409 on duplicate active target, 422 on target/type mismatch.
`DELETE /bans/{id}` → 404 if not in this project. `POST /audit/ban-enforcements` → 400 out-of-window,
503 transient storage, 422 rejected by storage.

### Wire schemas (`platform/api/hexgate_api/schemas.py`)

- **`BanCreate`** (`:168`) — `ban_type` (`^(agent|user)$`), `target_agent_name?`, `target_user_id?`,
  `reason?`; a `model_validator` enforces exactly one target matching the type.
- **`BanRead`** (`:192`) — full dashboard row: adds `created_by_user_id`, display-only
  `created_by_email` (null if the account was deleted), `created_at`, `revoked_at`, and computed
  `active` (`revoked_at is None`). Note `revoked_by_user_id` is stored but **not** exposed here.
- **`BanFeedEntry`** (`:210`) — minimal SDK feed shape (§4.2).
- **`BanEnforcementEvent`** (`:470`, extends `AuditEnvelope`) — `ban_type` + `ban_id` (1–64) +
  `reason`; the ingest body.
- **`BanEnforcementAccepted`** (`:478`) — `{ event_id }`.
- **`BanEnforcementRow`** (`:560`) / **`BanEnforcementPage`** (`:575`) — read models for the panel.

---

## 6. SDK internals reference (`hexgate/security/bans.py`)

| Symbol | Role |
|--------|------|
| `BanEntry` | one active ban, mirroring `BanFeedEntry` (frozen dataclass). |
| `BanSet` | immutable snapshot indexed by target; `agent_ban(name)` / `user_ban(uid)` O(1) lookups. `EMPTY_BAN_SET` is the no-op sentinel. |
| `ban_set_from_payload(entries)` | parse+index the feed body; drops unenforceable entries (loud WARN), raises `BanContentError` on a non-array/non-object body. |
| `BanContentError` | raised on a 200-but-malformed feed body (contract drift, not transient). |
| `PlatformBanSource` | ETag-cached, lock-serialized, fail-soft fetch. Owns last-good. |
| `get_ban_source(key, client)` | get-or-create the shared source, keyed `(api_key, base_url)`. |
| `BanEnforcementEvent` | the fire-and-forget telemetry payload (`as_payload()`). |
| `configure_ban_sink(...)` | get-or-create the shared `AuditSender` for `/v1/audit/ban-enforcements`. |
| `BanGate` | per-agent gate: refresh (fail-soft) → decide → emit + raise. `check` / `check_async`. |
| `resolve_ban_gate(name, ...)` | build the gate, or `None` for all "no platform" cases. |

---

## 7. Failure semantics & edge cases

- **Control-plane unreachable / feed error** → SDK keeps the last-good `BanSet` (fail-soft). Runs
  continue with the last-known bans.
- **Cold start during an outage** → `EMPTY_BAN_SET` (fail-open). A ban that was never successfully
  fetched is not enforced.
- **Malformed feed (200 but wrong shape)** → `BanContentError`, logged at ERROR, last-good kept.
- **Unknown `ban_type` or blank target in the feed** → dropped at parse time with a WARNING (so an
  operator knows an older SDK isn't enforcing a ban it doesn't understand).
- **Local / no-key modes** → no gate at all (`resolve_ban_gate` returns `None`); bans are a no-op.
  Documented and accepted.
- **Concurrent creates racing** → the "one active ban per target" check is service-level, not a DB
  constraint, so two simultaneous creates can produce duplicate active bans. This is fail-safe
  (over-blocks, never under-blocks); a partial unique index would back it at the DB level (see §9).
- **`user_id` trust** → the `user_id` is read from the integrator-supplied runtime `HexgateContext` scope. It
  is bypassable by the integrator's own process, not by their end-users — which matches the threat
  model (a trusted integrator stopping a misbehaving agent or abusive end-user). Binding `user_id`
  into the attenuated biscuit is a known gap (see §9).

---

## 8. Design decisions (why it's built this way)

1. **A ban is a separate primitive, not a policy.** Policy is per-agent, static, compiled to signed
   WASM, evaluated locally. A ban is cross-agent (for user bans), highly dynamic, security-critical,
   and wants fast propagation — forcing it into `policy_yaml` would mean recompiling+resigning WASM
   on every toggle and couldn't carry cross-agent user bans.
2. **Single invoke-time gate.** Because both v1 ban types mean "don't run at all," there is exactly
   one enforcement seam — before the LLM — instead of a per-tool-call check. `PolicyEnforcer.decide()`
   is untouched; the gate refuses before policy is consulted, so a ban inherently wins.
3. **Dedicated feed `/v1/bans`.** Decoupled from `GET /v1/agents/{name}` so a ban toggle doesn't
   bust every agent's policy ETag, and so the feed can carry cross-agent user bans.
4. **Dedicated `ban_enforcement` ClickHouse table** (not a fourth `banned` outcome on
   `policy_decision`). A fourth outcome would have broken the dashboard's Audit views (which
   hardcode three outcomes in ~11 places), and a ban has no `tool_name`/`role`/`args` and fires per
   attempt (high volume). A separate table keeps tool-decision reads pure by construction.
5. **Typed error, not a fake assistant message.** The refusal happens before any model turn, so it
   can't be narrated by the model; a disguised assistant message would lie about provenance (written
   to history, fed back next turn, counted in token metrics). `AgentBannedError` carries structured
   fields so integrators localize/render good UX.
6. **Fail-soft for v1.** Consistent with the policy path. Fail-closed is a possible later-PR opt-in.
7. **Soft delete.** The `Ban` row is its own audit record — revoke keeps who/when rather than
   deleting the row.

---

## 9. Known limitations (worth addressing in later PRs)

These are known, accepted gaps in the current implementation — not blockers, but worth picking up
in follow-up PRs:

- **Propagation latency** — poll+ETag at run start, no push; a long-running conversation won't see a
  new ban until its next run. Push invalidation over the existing WS/relay infra would close this.
- **No per-ban TTL/expiry** — bans are indefinite until revoked.
- **Fail-open cold start** and **fail-soft** — a fail-closed opt-in is not yet available.
- **Unsigned feed** — v1 relies on TLS + biscuit; signing the ban set (same keystore as policy
  bundles) would add defense-in-depth.
- **`user_id` spoofing** — the `user_id` is trusted from the runtime scope; binding it into the
  attenuated biscuit would make user bans spoof-resistant.
- **No DB uniqueness constraint** — the one-active-ban-per-target rule is service-enforced only; a
  partial unique index would back it at the DB level.
- **No tool-level bans** — covered by policy `deny`; could be reintroduced if a real need appears.
- **Enforcement rows are SDK-attested, not platform-verified at ingest** — `POST /v1/audit/ban-enforcements` trusts the project bearer (same model as the decisions ingest), so a leaked bearer could spray fake rows into *its own* project's feed; verifying/signing audit telemetry is a cross-cutting follow-up.

---

## 10. File reference index

**Control plane (API):**
- `platform/api/hexgate_api/models.py:312` — `Ban` table
- `platform/api/hexgate_api/core/ids.py` — `new_id` / `ban_` prefix
- `platform/api/hexgate_api/features/bans/service.py` — create / list / revoke / active feed
- `platform/api/hexgate_api/features/bans/router.py` — CRUD + `/v1/bans` feed
- `platform/api/hexgate_api/schemas.py:164,470,560` — ban & enforcement wire shapes
- `platform/api/hexgate_api/features/audit/router.py:103,275` — enforcement ingest + read
- `platform/api/hexgate_api/features/audit/service.py:163,528` — `insert_ban_enforcement` / `list_ban_enforcements`
- `platform/clickhouse/init/schema.sql:46` — `ban_enforcement` DDL

**Dashboard:**
- `platform/dashboard/src/routes/Bans.tsx` — page + deep-link prefill
- `platform/dashboard/src/lib/bans.ts` — hooks (`useBans`, `useCreateBan`, `useRevokeBan`, `useCanManageBans`)
- `platform/dashboard/src/components/bans/` — `CreateBanDialog`, `ActiveBansPanel`, `BlockedAttemptsPanel`, `BlockedAttemptDrawer`, `BanTypeBadge`, `format.ts`, `constants.ts`
- `platform/dashboard/src/lib/api.ts` — typed ban + enforcement client methods

**SDK:**
- `hexgate/security/bans.py` — `BanEntry`, `BanSet`, `PlatformBanSource`, `BanGate`, `resolve_ban_gate`
- `hexgate/security/errors.py:14` — `AgentBannedError`
- `hexgate/cloud/client.py:194` — `get_bans` (feed fetch)
- `hexgate/agents/loader.py:488`, `hexgate/agents/factory.py` — native-factory wiring
- `hexgate/adapters/{openai,google,langchain,pydantic_ai}/…` — per-adapter enforcement call sites

**Design plans (rationale):**
- `plans/kill-switch.md` (master design), `kill-switch-phase1.md` (API), `kill-switch-phase2.md`
  (SDK enforcement), `kill-switch-phase3.md` (dashboard)

**Tests:**
- `platform/api/tests/features/bans/test_bans.py`, `tests/features/audit/test_audit.py`
- `tests/security/test_bans.py`, `tests/agents/test_platform_bundle.py`
- `platform/dashboard/src/lib/bans.test.tsx`, `src/routes/Bans.test.tsx`
