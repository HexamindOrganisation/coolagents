-- Applied BY HAND, not by a runner. init/ only executes on an empty volume, so
-- every environment that already has a policy_decision table needs this run
-- against it via `make clickhouse-cli` (paste the statement below).
--
-- ORDERING: apply this BEFORE deploying the API that references the column.
-- Skipping it takes down both halves of the audit feature, loudly:
--   * ingest — insert_decision names `attributes` in column_names, ClickHouse
--     rejects the row, the API logs "audit insert rejected by ClickHouse" and
--     returns 422 (non-retryable), and the SDK sender drops the event.
--   * reads  — `attributes` is part of _LIST_COLUMNS, so the SELECT fails and
--     GET /v1/audit/decisions 503s: the whole dashboard Audit page, not just
--     the new drawer section.
-- The ALTER is additive and back-compatible — the running old API never
-- references the new column — so it can be applied arbitrarily early.
--
-- Metadata-only on MergeTree: no part rewrite, no downtime, idempotent.
-- Pre-existing rows read back as '', which _decode_json_column maps to None
-- ("no attributes recorded") rather than a misleading {}.
--
-- ADD COLUMN without AFTER appends physically, matching the trailing position
-- in init/schema.sql — so a hand-altered volume and a freshly-initialized one
-- end up with identical column order, which is what _DECISION_COLUMNS
-- ("order matches schema.sql") relies on.

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS attributes String
    COMMENT 'Caller ABAC bag (ctx.*); advisory + client-assertable; SDK-redacted and truncated'
    CODEC(ZSTD(3));
