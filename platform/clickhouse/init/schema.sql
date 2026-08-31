-- Audit log for PolicyEnforcer decisions.
-- The first eight columns are the envelope shared with future event
-- tables (tool_invocation, ...) — same names, types, and order.
-- This init dir runs once on an empty volume; edits afterward are
-- ignored. Don't add more files here — use a real migration runner
-- instead. Until there is one: every edit below also needs a
-- hand-applied counterpart in ../migrations/ for existing volumes —
-- unless no ALTER can restate pre-existing rows truthfully (the role
-- set), in which case the volume is recreated and no migration ships.

CREATE DATABASE IF NOT EXISTS hexgate_audit;

CREATE TABLE IF NOT EXISTS hexgate_audit.policy_decision
(
    -- Envelope (shared across all future event tables)
    event_id            UUID,
    occurred_at         DateTime64(3, 'UTC'),
    received_at         DateTime64(3, 'UTC') DEFAULT now64(3),
    project_id          LowCardinality(String),
    agent_name          LowCardinality(String),
    agent_version_id    LowCardinality(String) DEFAULT '',
    session_id          String DEFAULT '',
    user_id             LowCardinality(String) DEFAULT '',

    -- Decision-specific
    tool_name           LowCardinality(String),
    outcome             Enum8('allow' = 1, 'deny' = 2, 'needs_approval' = 3),
    error_type          LowCardinality(String) DEFAULT '',
    reason              String,
    violations          Array(String),
    hint                String CODEC(ZSTD(3)),
    arguments           String COMMENT 'SDK-truncated JSON snapshot; may be lossy' CODEC(ZSTD(3)),
    attributes          String COMMENT 'Caller ABAC bag (ctx.*); advisory + client-assertable; SDK-redacted and truncated' CODEC(ZSTD(3)),
    -- The caller's roles are a set, stored only as a set — there is no legacy
    -- scalar `role` column. An SDK predating multi-role sends one; it is folded
    -- into user_roles at ingest (audit/service.py), so every row here is the
    -- same shape whatever wrote it. No DEFAULT: these columns have existed
    -- since the first CREATE, so nothing needs a read-time rescue.
    user_roles          Array(LowCardinality(String)) COMMENT 'Distinct roles evaluated for this call, caller order; advisory + client-assertable',
    deciding_role       LowCardinality(String) DEFAULT '' COMMENT 'Role whose policy granted/gated the call; empty when every role denied',

    -- Run attribution (advisory + client-assertable, same tier as user_id /
    -- user_roles). Zero UUID / zero counters means "not attributed to a run
    -- scope by the SDK that sent this row" — a truthful default until the
    -- SDK starts stamping the run_ns namespace read once per decision
    -- (hexgate/security/enforcer.py). See plans/run-state/run-state-schema.md §7.
    run_id              UUID     DEFAULT toUUID('00000000-0000-0000-0000-000000000000') COMMENT 'RunFacts.id; zero when the decision was made outside a run scope or by an SDK that does not yet send it',
    run_tool_calls      UInt32   DEFAULT 0 COMMENT 'run.tool_calls at decision time',
    run_llm_calls       UInt32   DEFAULT 0 COMMENT 'run.llm_calls at decision time',
    run_denials         UInt32   DEFAULT 0 COMMENT 'run.denials at decision time',
    run_total_tokens    UInt32   DEFAULT 0 COMMENT 'run.total_tokens at decision time',
    run_elapsed_ms      UInt32   DEFAULT 0 COMMENT 'run.elapsed_seconds * 1000 at decision time'
)
-- ReplacingMergeTree: SDK retries (same event_id) collapse on background
-- merges — eventual dedup; exact counts use FINAL or count(DISTINCT event_id).
ENGINE = ReplacingMergeTree(received_at)
-- Partition + TTL anchor on server-stamped received_at, not the
-- client-supplied occurred_at (clock skew would break retention).
PARTITION BY toYYYYMM(received_at)
ORDER BY (project_id, agent_name, outcome, occurred_at, event_id)
TTL toDateTime(received_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;


-- Kill-switch ban enforcements — one row per execution refused at the invoke gate.
-- Sibling of policy_decision sharing the envelope; separate table because a ban
-- has no tool/outcome and its per-attempt volume would swamp the decision feed.
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


CREATE TABLE IF NOT EXISTS hexgate_audit.llm_invocation
(
    -- Envelope (shared across all future event tables)
    event_id            UUID,
    occurred_at         DateTime64(3, 'UTC'),
    received_at         DateTime64(3, 'UTC') DEFAULT now64(3),
    project_id          LowCardinality(String),
    agent_name          LowCardinality(String),
    agent_version_id    LowCardinality(String) DEFAULT '',
    session_id          String DEFAULT '',
    user_id             LowCardinality(String) DEFAULT '',

    -- LLM-invocation-specific
    model               LowCardinality(String),
    input_tokens        UInt32,
    output_tokens       UInt32,
    latency_ms          UInt32 DEFAULT 0,
    status              LowCardinality(String) DEFAULT 'success',
    error_code          LowCardinality(String) DEFAULT '',

    run_id              UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') COMMENT 'RunFacts.id of the run this LLM call belongs to; zero when outside a run scope or from an SDK that does not yet send it'
)
ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(received_at)
ORDER BY (project_id, user_id, agent_name, model, occurred_at, event_id)
TTL toDateTime(received_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
