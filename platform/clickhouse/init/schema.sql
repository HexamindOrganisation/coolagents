-- Audit log for PolicyEnforcer decisions.
-- The first eight columns are the envelope shared with future event
-- tables (tool_invocation, ...) — same names, types, and order.
-- This init dir runs once on an empty volume; edits afterward are
-- ignored. Don't add more files here — use a real migration runner
-- instead.

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
    role                LowCardinality(String) DEFAULT '',
    outcome             Enum8('allow' = 1, 'deny' = 2, 'needs_approval' = 3),
    error_type          LowCardinality(String) DEFAULT '',
    reason              String,
    violations          Array(String),
    hint                String CODEC(ZSTD(3)),
    arguments           String COMMENT 'SDK-truncated JSON snapshot; may be lossy' CODEC(ZSTD(3))
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
    error_code          LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(received_at)
PARTITION BY toYYYYMM(received_at)
ORDER BY (project_id, user_id, agent_name, model, occurred_at, event_id)
TTL toDateTime(received_at) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
