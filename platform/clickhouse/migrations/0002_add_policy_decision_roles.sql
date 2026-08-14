-- Applied BY HAND, not by a runner. init/ only executes on an empty volume, so
-- every environment that already has a policy_decision table needs this run
-- against it via `make clickhouse-cli` (paste the statements below, in order).
--
-- Adds the multi-role decision columns: `user_roles` (every role the SDK
-- evaluated for one tool call) and `deciding_role` (the one that granted or
-- gated it). `role` stays exactly what it was — the caller's FIRST role — so
-- nothing already stored becomes false.
--
-- ORDERING: apply this BEFORE deploying the API that references the columns.
-- Skipping it takes down both halves of the audit feature, loudly:
--   * ingest — insert_decision names `user_roles`/`deciding_role` in
--     column_names, ClickHouse rejects the row, the API logs "audit insert
--     rejected by ClickHouse" and returns 422 (non-retryable), and the SDK
--     sender drops the event.
--   * reads  — both names are in _LIST_COLUMNS, and `user_roles` drives the
--     by_role breakdown and every role filter, so the SELECTs fail and
--     GET /v1/audit/decisions 503s: the whole dashboard Audit page.
-- The ALTERs are additive and back-compatible — the running old API never
-- references the new columns — so they can be applied arbitrarily early.
--
-- ADD COLUMN without AFTER appends physically, matching the trailing position
-- in init/schema.sql — so a hand-altered volume and a freshly-initialized one
-- end up with identical column order, which is what _DECISION_COLUMNS
-- ("order matches schema.sql") relies on.
--
-- WHY THE DEFAULT EXPRESSION: parts written before the ALTER hold no
-- user_roles data. `DEFAULT if(role = '', [], [role])` gives every historic
-- single-role row the role set it logically always had, so membership reads
-- (`has(user_roles, 'billing')`) answer correctly for pre-upgrade events. New
-- inserts always name the column explicitly, so the default never applies to
-- them — which is why a genuinely empty role set stores [] and lands in the ''
-- bucket rather than [''].
--
-- WHY STATEMENT 3 IS NOT OPTIONAL — verified on clickhouse-server 24.10.4.191:
--   `optimize_functions_to_subcolumns` (default 1 since 24.x) rewrites
--   `empty(user_roles)` and `length(user_roles)` into a read of the
--   `user_roles.size0` subcolumn. That subcolumn does not exist in a part
--   written before the ALTER, and the rewritten read yields size 0 WITHOUT
--   evaluating the DEFAULT expression above. Net effect: every legacy
--   single-role row is misreported as having an EMPTY role set by any filter
--   using empty()/length(), even though SELECTing the column shows ['billing'].
--   Concretely, the dashboard's "(none)" role drill-down would return every
--   pre-upgrade row. `has(...)` and `arrayJoin(...)` are NOT rewritten and were
--   correct throughout, which is what makes the bug easy to miss in review.
--   MATERIALIZE COLUMN writes the default into the existing parts, so no read
--   path depends on read-time DEFAULT evaluation any more and the optimizer
--   rewrite becomes harmless.
--
-- COST of statement 3: a mutation, not a full part rewrite — it writes one
-- column's files per part and hardlinks the rest (measured: +4% bytes_on_disk
-- on the probe parts). It is the one non-metadata-only step here, so on a large
-- table run it in a maintenance window and watch system.mutations. Statements 1
-- and 2 remain instant and metadata-only.
--
-- `deciding_role` needs no MATERIALIZE: its DEFAULT ('') is identical to the
-- type's own zero value, so a missing-column read and the DEFAULT expression
-- cannot disagree. Only a DEFAULT that differs from the type default — like
-- user_roles' — can produce the divergence described above.
--
-- All four statements are idempotent and safe to re-run.

-- `role` keeps its meaning and its data; only its documentation changes. Kept
-- in step with init/schema.sql so a migrated volume and a fresh one produce a
-- byte-identical DESCRIBE — verified by diffing system.columns across both.
ALTER TABLE hexgate_audit.policy_decision
    COMMENT COLUMN IF EXISTS role 'Legacy: the caller''s first role. Membership queries read user_roles';

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS user_roles Array(LowCardinality(String))
    DEFAULT if(role = '', [], [role])
    COMMENT 'Distinct roles evaluated for this call, caller order; advisory + client-assertable';

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS deciding_role LowCardinality(String) DEFAULT ''
    COMMENT 'Role whose policy granted/gated the call; empty when every role denied';

-- Bake the DEFAULT into existing parts. mutations_sync=2 makes this block until
-- every replica finishes, so a hand-run migration can't "succeed" while the
-- data is still inconsistent. Drop to mutations_sync=0 and poll
-- system.mutations instead if the table is large enough that blocking is
-- impractical — but do not skip the statement.
ALTER TABLE hexgate_audit.policy_decision
    MATERIALIZE COLUMN user_roles
    SETTINGS mutations_sync = 2;
