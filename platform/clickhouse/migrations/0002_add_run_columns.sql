-- Applied BY HAND, not by a runner. init/ only executes on an empty volume, so
-- every environment that already has policy_decision / llm_invocation needs
-- this run against it via `make clickhouse-cli` (paste the statements below).
--
-- ORDERING: apply this BEFORE deploying the API that references these
-- columns. Skipping it takes down ingest for both event types, the same way
-- 0001 describes:
--   * policy_decision — insert_decision names the six run_* columns in
--     column_names, ClickHouse rejects the row (ProgrammingError), the API
--     returns 503 (see features/audit/router.py's ProgrammingError branch),
--     and the SDK sender retries until the schema catches up.
--   * llm_invocation — same shape, and until this migration's companion fix
--     to features/llm_invocations/router.py, a ProgrammingError there fell
--     through to a non-retryable 422 instead; this migration and that fix
--     ship together.
-- Both ALTERs are additive and back-compatible — a running old API never
-- references the new columns — so they can be applied arbitrarily early.
--
-- Metadata-only on MergeTree: no part rewrite, no downtime, idempotent.
-- Pre-existing rows read back as the zero UUID / zero counters, which is
-- truthful: no SDK before this migration ever attributed a decision to a
-- run, so "not attributed" is the correct historical value, not a
-- placeholder.
--
-- ADD COLUMN without AFTER appends physically, matching schema.sql's order —
-- see that file's comment on why order matching matters.

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS run_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000')
    COMMENT 'RunFacts.id; zero when the decision was made outside a run scope or by an SDK that does not yet send it',
    ADD COLUMN IF NOT EXISTS run_tool_calls UInt32 DEFAULT 0
    COMMENT 'run.tool_calls at decision time',
    ADD COLUMN IF NOT EXISTS run_llm_calls UInt32 DEFAULT 0
    COMMENT 'run.llm_calls at decision time',
    ADD COLUMN IF NOT EXISTS run_denials UInt32 DEFAULT 0
    COMMENT 'run.denials at decision time',
    ADD COLUMN IF NOT EXISTS run_total_tokens UInt32 DEFAULT 0
    COMMENT 'run.total_tokens at decision time',
    ADD COLUMN IF NOT EXISTS run_elapsed_ms UInt32 DEFAULT 0
    COMMENT 'run.elapsed_seconds * 1000 at decision time';

ALTER TABLE hexgate_audit.llm_invocation
    ADD COLUMN IF NOT EXISTS run_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000')
    COMMENT 'RunFacts.id of the run this LLM call belongs to; zero when outside a run scope or from an SDK that does not yet send it';
