# Audit Pipeline Specification

> Status: living — kept in sync with the audit code. Last reviewed 2026-07.

Scope: the end-to-end path that records every policy decision a Hexgate-wrapped
agent makes, from the SDK enforcement point to durable storage in ClickHouse and
the dashboard read view.

This document is descriptive of the current implementation (PR
`gp/feat/sdk_emit_audit_event` + the platform audit endpoint). Where behaviour
is intentionally lossy or POC-grade, it says so explicitly.

---

## 1. Overview

Every time an agent proposes a tool call, the SDK's `PolicyEnforcer` produces a
`Decision` (allow / deny / needs_approval). The audit pipeline ships a copy of
that decision — **out of band, fire-and-forget** — to the platform, which
validates it, resolves server-owned identity fields, and appends one immutable
row to a ClickHouse table. Audit emission is a **side effect of enforcement**:
it never changes, blocks, or fails the decision the agent acts on.

```
┌─────────────────────────── SDK (hexgate) ───────────────────────────┐
│  tool call                                                           │
│     │                                                                │
│     ▼                                                                │
│  PolicyEnforcer.decide()  ──►  Decision (event_id, occurred_at)      │
│     │                            │                                   │
│     │ returns to agent  ◄────────┘ (synchronous, authoritative)      │
│     │                                                                │
│     └─► AuditSender.emit(AuditEvent)   (one OTel span, best-effort)  │
│              │  BatchSpanProcessor: bounded queue, drop-on-saturation│
└──────────────┼───────────────────────────────────────────────────────┘
               │  OTLP/HTTP POST /v1/traces   (Bearer <hexgate_key>)
               │  → Collector → Redpanda → span-enricher job (see the
               │    "OpenTelemetry migration design" doc)
               ▼
┌─────────────────────── Platform API (FastAPI) ──────────────────────┐
│  require_project      bearer → project_id                            │
│  require_clickhouse   client or 503                                  │
│  validate             clock-skew / retention window                  │
│  resolve              agent_version_id from latest AgentVersion      │
│  insert_decision      byte-cap args/hint, write one row              │
└──────────────┼───────────────────────────────────────────────────────┘
               │  INSERT (async_insert, wait_for_async_insert=1)
               ▼
┌─────────────────────────── ClickHouse ──────────────────────────────┐
│  hexgate_audit.policy_decision   MergeTree, monthly partitions,      │
│  TTL 90 days, received_at server-stamped                             │
└──────────────┬───────────────────────────────────────────────────────┘
               │  GET /v1/projects/{id}/audit/{summary,timeseries,decisions}
               ▼
        Project-scoped aggregation endpoints (read API)
```

### Design principles

1. **Enforcement is authoritative; audit is observational.** The `Decision`
   returned to the agent is the source of truth. Audit failures (network down,
   platform 503, saturation) degrade silently and never propagate to the caller.
   The same `Decision` is also surfaced locally by `hexgate chat`'s decision
   panel — same data, different sink, useful when iterating offline.
2. **The server owns identity.** `project_id`, `agent_version_id`, and
   `received_at` are resolved/stamped server-side and are **never trusted from
   the request body**, even though the SDK sends some of them as empty strings.
3. **One envelope, many event types.** The first eight columns/fields are a
   shared "envelope" intended to be reused by future event tables
   (`tool_invocation`, …). `policy_decision` is the first concrete event.
4. **Lossy under pressure, never blocking.** Both the SDK (drop on saturation)
   and the storage layer (byte caps, truncated `arguments`) prefer dropping or
   truncating data over slowing the agent.

---

## 2. The audit record

### 2.1 Stamped at the emission site

`hexgate/audit.py` — `AuditEvent` stamps the two audit identifiers at
construction. They live on the event, not on `Decision`: they exist only for
audit emission, and the no-audit path never constructs an event (so a
`decide()` call without a sender mints neither).

| Field | Type | Source |
|-------|------|--------|
| `event_id` | `UUID` | `uuid4()` per event — the idempotency key end-to-end |
| `occurred_at` | `datetime` (UTC) | `datetime.now(timezone.utc)` at construction |

The enforcer builds the `AuditEvent` immediately after the `Decision`, so
`occurred_at` is decision time for practical purposes. The decision fields
(`agent_name`, `tool_name`, `outcome`, `user_roles`, `deciding_role`, `reason`, `error_type`,
`violations`, `hint`, `arguments`) are populated by `Decision.from_verdict()`
from the policy engine's `Verdict` plus host context.

### 2.2 Outcome and error_type

```
DecisionOutcome   wire value        error_type (derived)
ALLOW             "allow"           "" (no error tag)
DENY              "deny"            "policy_denied"
NEEDS_APPROVAL    "needs_approval"  "approval_required"
```

### 2.3 Wire format — one OTel span per event, `AuditEvent.span_attributes()`

`hexgate/audit.py` — `AuditEvent` wraps a `Decision` plus the caller identity
read from the active `HexgateContext` scope (`user_id`, `session_id`). The
sender turns it into one OpenTelemetry span under instrumentation scope
**`hexgate.audit`**; `span_attributes()` produces the span's flat attribute
map. Every key is a constant in `hexgate/tracing/semconv.py` — the single
wire contract shared with the platform's span-enricher job, which decodes by
the same names:

```
scope: hexgate.audit                       (AuditEvent.SCOPE)
start_time == end_time = occurred_at       (point-in-time event; no attribute)

sec_ai.event_id       "0b9c…"              str(UUID) — the idempotency key
sec_ai.agent_name     "example_agent"
sec_ai.tool_name      "read_file"
sec_ai.outcome        "deny"
sec_ai.user_roles     ["analyst", "billing"]   native string array; [] when none
sec_ai.deciding_role  ""                   role that granted/gated it; "" on a deny
sec_ai.error_type     "policy_denied"      "" for allow
sec_ai.reason         "denied for path"
sec_ai.violations     ["v1", "v2"]         native string array, capped (§7)
sec_ai.hint           '{"glob": "/x/**"}'  JSON *string*; absent when unset
sec_ai.arguments      '{"path": "/etc/passwd"}'  JSON string; redacted + capped; absent when unset
sec_ai.attributes     '{"department": "finance"}' JSON string; caller ABAC bag; absent when empty
sec_ai.user_id        "alice"              "" when no request context
sec_ai.session_id     "sess_1"             "" when unset
```

Two shape rules worth knowing: the dict fields travel as **JSON strings**
(their platform byte caps are defined in serialized-JSON bytes, so the capped
quantity stays the measured one), and unset optional fields are **left out**
rather than sent as null (OTel attributes can't carry `None`; the enricher
defaults them). `occurred_at` is the span's `start_time_unix_nano`, not an
attribute. Server-resolved fields (`project_id`, `agent_version_id`,
`received_at`) are **deliberately absent**: `project_id` in particular is
derived from the bearer by the Collector's auth extension and travels as the
Kafka record key — a self-declared project on the span is never trusted.

---

## 3. SDK emission layer

### 3.1 Where emission happens

`PolicyEnforcer.decide()` (`hexgate/security/enforcer.py`):

1. Resolve the caller's role *set* from the active `HexgateContext` contextvar
   (deduped, capped at 32; `[None]` when unroled).
2. Evaluate each role and fold the verdicts permissively (`ALLOW` >
   `NEEDS_APPROVAL` > `DENY`), short-circuiting on the first allow; lift the
   winner into a `Decision` carrying `user_roles` + `deciding_role`.
3. If an `AuditSender` was injected into this enforcer, `emit()` an `AuditEvent`.
4. Return the `Decision` to the adapter (synchronous, unaffected by step 3).

The sender is **injected per enforcer**, not looked up globally — see §3.4.

### 3.2 `AuditSender` — one OTel span per event

`hexgate/tracing/_senders.py` — shared by `hexgate.audit` (policy decisions),
`hexgate.tracing.usage` (LLM token usage) and `hexgate.security.bans` (ban
enforcements); none of those modules owns it. One sender per `api_key` holds
one `TracerProvider` → `BatchSpanProcessor` → `OTLPSpanExporter` chain and
three tracers, one per instrumentation scope (`hexgate.audit` /
`hexgate.usage` / `hexgate.bans`) — the scope name is how the platform tells
the event types apart. `emit(event)` starts a span on the event's tracer with
`start_time = occurred_at`, sets `event.span_attributes()`, and ends it at the
same instant. Key behaviours:

- **Never blocks, never raises for transport.** `emit()` only enqueues the
  finished span onto the processor's in-memory queue; a worker thread batches
  and POSTs on a timer (5s) or size trigger (512). Export failures surface as
  the exporter's own log lines, never to the agent.
- **Drop on saturation.** The queue is bounded (2048 spans); when full the
  processor drops the newest and logs a warning.
- **Thread-agnostic.** There is no event-loop affinity: `emit()` behaves the
  same on an asyncio loop thread, in a `run_in_executor` worker, and in a
  purely synchronous caller with no loop anywhere (pydantic_ai's `run_sync()`).
  The old asyncio-task / sync-thread fallback machinery, and the adapters'
  per-call `drain_pending_tasks()` hooks, are gone with it.
- **Always sampled, always a root span.** The provider uses `ALWAYS_ON` and
  each span starts from an empty `Context`, so a customer's own OTel tracing
  can neither parent our spans nor apply its sampling rate to them.
- **Retries** are the OTLP exporter's built-in backoff on 429/5xx, bounded by
  a 5s export timeout (`DEFAULT_EXPORT_TIMEOUT`, replacing OTel's 30s default
  so a slow platform can't hold process exit).
- **Auth:** `Authorization: Bearer <api_key>` header on every export.

### 3.3 Endpoint resolution

The exporter targets `HEXGATE_OTLP_ENDPOINT` when set, else
`<HEXGATE_API_URL>/v1/traces` (`hexgate.config.env.resolve_otlp_endpoint`).
The dedicated variable exists because the Collector's OTLP receiver can be
deployed on its own host/port (4318 by default) rather than behind the FastAPI
control plane; the fallback keeps the single-host case zero-config.

### 3.4 Configuration & lifecycle

`hexgate.audit.configure(api_key=None, base_url=None) -> AuditSender | None`
is a thin, decisions-specific wrapper around the shared
`hexgate.tracing._senders.get_or_create_sender()`:

- Resolves `api_key` from the argument or `HEXGATE_API_KEY`; returns `None` (audit
  inert) when no key is resolvable.
- Resolves `base_url` from the argument or `HEXGATE_API_URL`, defaulting to
  Hexgate Cloud (`https://app.hexgate.ai`); set `http://localhost:8000` when
  self-hosting. The export endpoint follows §3.3.
- **Keyed by `api_key`.** Senders live in a shared registry
  `dict[str, AuditSender]` in `hexgate/tracing/_senders.py`. One sender per
  key carries every event type — decisions, LLM usage and ban enforcements —
  since the span's instrumentation scope, not a separate endpoint, tells them
  apart. Calling `configure()` again with the **same** key returns the
  existing sender (idempotent); a **different** key gets its own sender with
  its own bearer token, which is what lets one process audit several
  tenants/keys.

Each adapter wrapper (`wrap_langchain_agent`, `wrap_openai_agent`,
`wrap_google_agent`, `wrap_pydantic_agent`) and `factory.enforce_policy` call
`configure()` with their resolved key and inject the returned sender into the
`PolicyEnforcer` they build. `bootstrap()` also calls `configure()` (env key) so
local runs work without an explicit key.

#### Local mode (`HEXGATE_LOCAL_MODE`)

The gate lives in `hexgate/tracing/_senders.py` and applies to every event
type sharing the registry, not just decisions. Setting `HEXGATE_LOCAL_MODE=1`
makes `configure()` (and `configure_usage_sender()`) return `None` even when
`HEXGATE_API_KEY` is present in env. `bootstrap(local_only=True)` sets the var
*before* the first `configure()` call, and `hexgate chat` passes
`local_only=True` — so the inner-loop REPL never posts audit events even if
a key has been lingering in `.env` from an earlier platform session.

The gate is re-checked on every `configure()` call (not cached), so an adapter
wrapper that re-`configure`s post-bootstrap still respects it. The truthy
value parser accepts `1` / `true` / `yes` / `on` (case-insensitive).

There are now two clean operating modes, not three:

| Mode | `HEXGATE_API_KEY` | `HEXGATE_LOCAL_MODE` | Policy from | Audit |
|------|---------------|----------------------|-------------|-------|
| **Local** | (irrelevant) | `1`, or unset with no key | YAML / disk / builtin | suppressed |
| **Platform-managed** | set | unset | platform fetch | emitted |

A single INFO line (`sender suppressed: HEXGATE_LOCAL_MODE=1 (...)`) is
logged the first time a sender is requested with both a key and local mode
active — exactly the case where the suppression would be surprising — and
once per process thereafter stays quiet. The "no key anywhere" case never
logs.

A separate WARNING fires from `bootstrap()` itself when both `HEXGATE_API_KEY`
and `HEXGATE_LOCAL_POLICY` are set — that combination is almost always a
forgotten env entry from an earlier session, and surfacing it at startup
saves a later debugging detour.

> For the user-facing description of when each mode applies in practice
> — chat vs. serve, inner loop vs. team loop — see the
> ["Which path do I pick?"](/two-paths) page.

#### Shutdown contract — host applications must flush

`async shutdown()` flushes every sender's queued spans and stops its worker
**across the whole shared registry** — decisions, LLM usage and ban
enforcements alike. It is safe to call multiple times and is the required
teardown hook: **the host application calls `await hexgate.audit.shutdown()`
before exit.** Either `hexgate.audit.shutdown()` or
`hexgate.tracing.usage.shutdown()` does it, since both delegate to
`hexgate.tracing._senders.shutdown()`.

Why it's required: normal traffic flushes itself on the processor's 5s timer,
but the final in-flight batch only leaves the process on an explicit flush.
The processor's worker is a **daemon thread** — it does not keep the
interpreter alive to finish a pending export the way the old non-daemon
fallback threads did. There is one safety net: `TracerProvider` registers an
`atexit` hook (`shutdown_on_exit=True`) that performs the same flush, bounded
by the export timeout, so a script that forgets still usually gets its tail
out — but an interpreter that exits via `os._exit`, a killed worker, or a
flush that outlives the timeout loses whatever was queued. Call `shutdown()`.

| Function | Purpose |
|----------|---------|
| `hexgate.tracing._senders.get_or_create_sender(key, url)` | Get-or-create the sender for `key`. Idempotent per key. |
| `hexgate.tracing._senders.get_sender(key)` | Registry lookup by `key` (diagnostics). Prefer the injected sender. |
| `hexgate.tracing._senders.shutdown()` | Flush + stop every sender. |
| `hexgate.audit.configure(key, url)` / `hexgate.tracing.usage.configure_usage_sender(key, url)` / `hexgate.security.bans.configure_ban_sink(key, url)` | Per-module wrappers over `get_or_create_sender(key, url)`; all three return the same sender for the same key. |
| `hexgate.audit.get_sender(key)` / `hexgate.tracing.usage.get_usage_sender(key)` | Wrappers over `get_sender(key)`. |
| `hexgate.audit.shutdown()` / `hexgate.tracing.usage.shutdown()` | Both call the shared `shutdown()`; either flushes all event types. |

---

## 4. Platform ingest endpoint

`POST /v1/audit/decisions` (`platform/api/main.py` → `ingest_decision`).

### 4.1 Request

- **Auth:** `Authorization: Bearer <hexgate_key>`. `require_project` verifies
  the key and resolves it to a `project_id`. Missing/invalid → **401**.
- **Body:** `DecisionEvent` (`platform/api/schemas.py`), a pydantic model that
  extends `AuditEnvelope`. Field-level validation (max lengths, enum membership)
  happens here; a malformed body → **422** (FastAPI validation).
- **ClickHouse dependency:** `require_clickhouse` resolves the client and maps a
  connect failure to **503** with `Retry-After: 5`.

### 4.2 Server-side processing

1. **Clock-skew / retention guard.** Reject `occurred_at` more than 5 minutes in
   the future (`CLOCK_SKEW_FUTURE`) or older than the 90-day `RETENTION_WINDOW`
   → **400**.
2. **Resolve `agent_version_id`** = latest `AgentVersion.id` for
   `(project_id, agent_name)`, or `""` if the agent isn't registered. Unknown
   agents still log; the version is just empty.
3. **Insert** via `audit.insert_decision`. `project_id` (bearer-resolved) and
   `agent_version_id` (platform lookup) are passed explicitly and override
   anything in the body.

### 4.3 Responses

| Status | Meaning |
|--------|---------|
| **202 Accepted** | Row written. Body: `{"event_id": "<uuid>"}`. (Sync write, see §5.2 — 202 reflects "queued/durable" semantics but the insert has actually completed.) |
| **400** | `occurred_at` outside the accepted time window. |
| **401** | Missing/malformed/invalid/revoked bearer key. |
| **413** | `arguments` > 8 KiB, or `hint` / `attributes` > 4 KiB each, after JSON serialization. |
| **422** | Body failed schema validation, **or** ClickHouse rejected the row (non-transient — retry won't help). |
| **503** | ClickHouse unreachable or transient insert failure (`OperationalError`). Retryable; carries `Retry-After`. |

### 4.4 Trust boundary

`AuditEnvelope` is intentionally **narrower** than the storage row. The body
carries only `event_id`, `occurred_at`, `agent_name`, `session_id`, `user_id`
(envelope) plus the decision fields. `project_id`, `agent_version_id`, and
`received_at` are server-owned and cannot be spoofed by the SDK.

---

## 5. Storage — ClickHouse

`platform/clickhouse/init/schema.sql`. Database `hexgate_audit`, table
`policy_decision`.

> ⚠️ The `init/` directory runs **once on an empty volume**. Editing the schema
> after first boot is ignored — use a real migration runner for changes.

### 5.1 Schema

```sql
CREATE TABLE hexgate_audit.policy_decision
(
  -- Envelope (shared with future event tables)
  event_id            UUID,
  occurred_at         DateTime64(3, 'UTC'),
  received_at         DateTime64(3, 'UTC') DEFAULT now64(3),   -- server-stamped
  project_id          LowCardinality(String),
  agent_name          LowCardinality(String),
  agent_version_id    LowCardinality(String) DEFAULT '',
  session_id          String                 DEFAULT '',
  user_id             LowCardinality(String) DEFAULT '',

  -- Decision-specific
  tool_name           LowCardinality(String),
  outcome             Enum8('allow'=1, 'deny'=2, 'needs_approval'=3),
  error_type          LowCardinality(String) DEFAULT '',
  reason              String,
  violations          Array(String),
  hint                String CODEC(ZSTD(3)),
  arguments           String CODEC(ZSTD(3)),  -- SDK-truncated JSON; may be lossy
  attributes          String CODEC(ZSTD(3)),  -- caller ABAC bag (ctx.*); redacted + truncated
  -- Roles are stored only as a set — there is no legacy scalar `role` column.
  -- An SDK predating multi-role sends one; the API folds it into user_roles
  -- at ingest, so every stored row is the same shape whatever wrote it.
  user_roles          Array(LowCardinality(String)),
  deciding_role       LowCardinality(String) DEFAULT ''       -- '' when every role denied
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (project_id, agent_name, outcome, occurred_at)
TTL toDateTime(occurred_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
```

- **`occurred_at`** is event time (SDK), **`received_at`** is ingest time
  (server default). Reads order by `received_at`; retention/partitioning key off
  `occurred_at`.
- **Sort key** `(project_id, agent_name, outcome, occurred_at)` optimizes the
  expected query shape: "decisions for a project/agent, filtered by outcome,
  newest within a window."
- **`hint` / `arguments`** are stored as ZSTD-compressed JSON strings, not native
  JSON, and are documented as potentially lossy (`arguments` is SDK-truncated;
  see §6).
- **TTL 90 days** — rows self-expire, consistent with the ingest retention guard.

### 5.2 Insert semantics

`platform/api/audit.py` — `insert_decision`:

- **Byte caps before write:** `arguments` JSON ≤ 8 KiB, `hint` JSON ≤ 4 KiB,
  `attributes` JSON ≤ 4 KiB — each checked independently, else
  `AuditPayloadTooLarge` → 413. `None` serializes to `""`.
- **Insert settings:** `async_insert=1`, `wait_for_async_insert=1`,
  `async_insert_deduplicate=1`. Small inserts are batched server-side, but the
  call **blocks until the batch flushes**, so a write failure surfaces
  synchronously rather than being acked-then-dropped — an audit log must not
  silently lose acknowledged rows.
- **Dedup:** `async_insert_deduplicate` plus the unique `event_id` provides
  idempotency across SDK retries (the single 503 retry, or any at-least-once
  delivery): re-POSTing the same `event_id` does not create a duplicate row.

---

## 6. Privacy & data-handling notes

- **`arguments` carries tool inputs** (paths, payloads, possibly PII). It is
  transmitted to the platform and stored (compressed) for up to 90 days. The
  default `base_url` is **plaintext `http://localhost:8000`**; production
  deployments must set `HEXGATE_API_URL` to a TLS endpoint.
- **Default key-name redaction, always on.** `AuditEvent.as_payload()` replaces
  values whose key matches `password|passwd|secret|token|api[-_]?key|
  credential|authorization` (case-insensitive, recursive into nested
  dicts/lists) with `"[REDACTED]"` before transmission. **This is a seatbelt,
  not a guarantee**: values sensitive by *content* rather than key name — SQL
  strings, email bodies, free text — are captured verbatim. Operators whose
  tools carry such data need their own redaction before relying on this in
  production.
- **`attributes` redaction is anchored to the whole key**
  (`_SENSITIVE_ATTR_KEY_RE`), where `arguments` uses the substring rule above.
  The bag holds policy facts rather than caller payloads: blanking
  `authorization_tier` or `access_token_scope` would leave the `ctx.*`-driven
  deny they caused unexplainable, defeating the reason the bag is persisted at
  all. A key named exactly `token` still reads as a secret and is blanked.
- **SDK truncation at the platform cap.** `as_payload()` measures `arguments`
  as the platform does (JSON, `default=str`); over 8 KiB it replaces the dict
  with `{"_truncated": true, "original_bytes": N, "preview": <JSON prefix>}`
  sized to fit the cap. Lossy, but the event is stored — the platform
  **rejects** (413) oversize payloads, so an untrimmed over-cap decision would
  not be stored at all. `attributes` (4 KiB) and `hint` (4 KiB) go through the
  same `_truncate_json(payload, cap=...)` helper. Only the audit copy is
  trimmed: the `Decision` the host holds — and `as_error_payload()`, which the
  model sees — keeps the full `hint`.
- **`attributes` carries the caller ABAC bag** (the `ctx.*` namespace the
  decision was evaluated against): stored for 90 days and rendered verbatim in
  the dashboard's audit detail drawer for anyone with project read access. It
  goes through the same key-name redactor as `arguments`, with the same
  seatbelt-not-a-guarantee caveat, so content-sensitive values (emails,
  customer identifiers) pass through. `docs/concepts/user-scope.mdx` warns
  callers to filter on the coarsest value the policy needs. Never rendered into
  `as_error_payload` — the model must not see it.

---

## 7. Read path — aggregation endpoints

The raw `GET /v1/audit/decisions?limit=N` debug dump has been **removed**.
Reads are now project-scoped aggregation endpoints that group server-side in
ClickHouse (query-time `GROUP BY`; no rollups/materialized views). The table's
sort key `(project_id, agent_name, outcome, occurred_at)` and `LowCardinality`
columns make these scans cheap. All time-axis logic keys off `occurred_at`
(event time), never `received_at`. See `platform/api/audit.py` (`summarize`,
`timeseries`, `list_decisions`).

| Endpoint | Returns |
|----------|---------|
| `GET /v1/projects/{id}/audit/summary?window=` | Totals + denial counts, plus breakdowns by agent / tool / user (one `GROUPING SETS` query) and by role (a second scan over the same `WHERE`). |
| `GET /v1/projects/{id}/audit/timeseries?window=` | Per-bucket outcome counts (`toStartOfInterval`); bucket size tracks the window. |
| `GET /v1/projects/{id}/audit/decisions?window=&agent=&role=&outcome=&limit=&offset=` | Filterable detail rows, newest first, with `total` for pagination; `hint`/`arguments` decoded back to objects. |

- **`window`** is `24h` / `7d` / `30d` / `90d`, validated by a `Literal` (bad
  value → 422) and bounded by the 90-day storage TTL. `role=` (empty value)
  selects the empty-role bucket; an absent `role` means "no filter". No
  sentinel string is reserved on the wire — the dashboard's "(none)" is a
  display label only.
- **`role` filters on membership** (`has(user_roles, …)`), so one call by
  `["billing","support"]` is returned under either name, subsuming the old
  `role = X` equality. `by_role` therefore counts *memberships* and
  `sum(by_role[*].all) >= totals.all` — hence its own scan, since an
  `arrayJoin` in the `GROUPING SETS` query would inflate every breakdown.
- **Concurrency.** A client firing several of these reads at once (e.g. a
  dashboard loading summary + timeseries + decisions together) would otherwise
  hit "concurrent queries within the same session". The shared, process-global
  ClickHouse client is created with `autogenerate_session_id=False`
  (`platform/api/clickhouse.py`) so the thread-safe HTTP pool serves concurrent
  queries in parallel; this also hardens the ingest path under load.

> Still POC-grade on **auth**: the endpoints are project-scoped (gap #1 partly
> closed) but not yet gated behind the `read_audit` scope — they carry a
> `TODO(auth)` marker, matching the unauth posture of the other dashboard reads
> (`/agents`, `/tokens`). Scope enforcement must land before exposure beyond
> local development.

---

## 8. Failure-mode summary

| Failure | SDK behaviour | Agent impact |
|---------|---------------|--------------|
| No api_key configured | `configure()` returns `None`; no sender injected | none (audit inert) |
| No running event loop | `emit()` no-ops, one-time warning | none |
| Sender saturated | event dropped, periodic warning | none |
| Platform returns 503 | one retry, then network-error log | none |
| Platform returns 413/422/400 | logged as ingest error (`>= 400`) | none |
| Network unreachable | `RequestError` logged, dropped | none |
| Event loop rotates | client + semaphore rebuilt transparently | none |

| Failure | Platform behaviour |
|---------|--------------------|
| ClickHouse unreachable | 503 + `Retry-After` (startup logs a warning, does not crash) |
| Transient insert error | 503 + `Retry-After` |
| Storage rejects row | 422 (retry won't help) |
| Oversize args/hint/attributes | 413 |
| Bad/missing bearer | 401 |
| occurred_at out of window | 400 |

---

## 9. Open items / known gaps

1. **Read path auth & scoping** — `GET /v1/audit/decisions` is unauthenticated
   and cross-project (POC). Needs `read_audit` scope + `project_id` filter.
2. **`arguments`/`attributes` redaction is key-name-only** — the default
   redactor strips sensitive-keyed values, but content-sensitive values (SQL,
   email bodies, identifiers in the ABAC bag) pass through; no per-tool
   allow/deny lists, no `ctx.*` allowlist, no `redact` callable yet.
3. **Default transport is plaintext HTTP** — safe only for localhost; require
   TLS via `HEXGATE_API_URL` elsewhere.
4. **Sync agents emit nothing** — `emit()` requires a running loop; sync entry
   points silently produce no audit.
5. **Schema evolution** — `init/schema.sql` runs once; there is no migration
   runner wired up yet. Interim convention: a DDL change also lands a
   hand-applied statement in `platform/clickhouse/migrations/`, run in filename
   order via `make clickhouse-cli` **before** deploying the API that references
   the new column. Exception: when no `ALTER` can restate pre-existing rows
   truthfully — the multi-role columns — no migration ships and the volume is
   recreated instead (`make clickhouse-reset`). A boot-time gap raises
   `SchemaOutOfDate`, which points the operator at both paths.
6. **At-least-once, not exactly-once end to end** — the SDK can drop on
   saturation/network failure (audit is best-effort); `event_id` dedup prevents
   duplicates but not gaps.
7. **Write path is unscoped within a project** — `POST /v1/audit/decisions`
   authorizes via `require_project` (signature + project resolution only); any
   valid SDK bearer for the project can write audit, fetch policy, and register
   agents interchangeably. The biscuit attenuation primitive already exists
   (`platform/api/biscuits.py`); an `emit_audit` scope fact + endpoint check is
   the natural fix. Note existing minted tokens won't carry the fact — needs a
   deprecation window or re-mint.
8. **No rate limit or volume alerting on ingest** — an exfiltrated key can
   flood the log to bury real activity. Needs a per-project token bucket
   (`429 + Retry-After`; the SDK already logs-and-drops on ≥400) plus an
   ingest-volume-per-project alert.
