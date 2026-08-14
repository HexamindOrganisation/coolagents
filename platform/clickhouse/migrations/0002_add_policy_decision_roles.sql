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
-- Skipping it breaks ingest (the driver refuses to send a row naming an absent
-- column) and the whole dashboard Audit page (both names are in _LIST_COLUMNS).
-- The API guards the ordering rather than trusting it: startup DESCRIBEs the
-- audit tables and refuses to boot on a gap (audit/service.py verify_schema),
-- so a wrong-order rollout fails instead of silently discarding events. The
-- ALTERs are additive, so they can be applied arbitrarily early.
--
-- ADD COLUMN without AFTER appends physically, matching init/schema.sql, so a
-- hand-altered volume and a fresh one keep identical column order — what
-- _DECISION_COLUMNS ("order matches schema.sql") relies on.
--
-- WHY THE DEFAULT EXPRESSION: parts written before the ALTER hold no user_roles
-- data. `if(role = '', [], [role])` gives historic single-role rows the set they
-- logically always had, so membership reads answer correctly for them. New
-- inserts always name the column, so a genuinely empty set stores [], not [''].
--
-- WHY STATEMENT 3 IS NOT OPTIONAL — verified on clickhouse-server 24.10.4.191:
--   `optimize_functions_to_subcolumns` (default 1 since 24.x) rewrites
--   `empty(user_roles)`/`length(user_roles)` into a read of `user_roles.size0`,
--   which does not exist in pre-ALTER parts and yields 0 WITHOUT evaluating the
--   DEFAULT above. Every legacy single-role row then reads as an empty set —
--   the dashboard's "(none)" drill-down would return all of them — even though
--   SELECTing the column shows ['billing']. `has(...)`/`arrayJoin(...)` are not
--   rewritten, which is what makes this easy to miss. MATERIALIZE COLUMN writes
--   the default into existing parts, so no read depends on it any more.
--
-- COST of statement 3: a mutation, not a full part rewrite — one column's files
-- per part, the rest hardlinked (measured: +4% bytes_on_disk). It is the only
-- non-metadata-only step, so on a large table run it in a maintenance window
-- and watch system.mutations.
--
-- `deciding_role` needs no MATERIALIZE: its DEFAULT ('') equals the type's zero
-- value, so a missing-column read and the DEFAULT cannot disagree.
--
-- All four statements are idempotent and safe to re-run.

-- Documentation only — `role` keeps its meaning and data. Kept in step with
-- init/schema.sql so both volumes produce a byte-identical DESCRIBE.
ALTER TABLE hexgate_audit.policy_decision
    COMMENT COLUMN IF EXISTS role 'Legacy: the caller''s first role. Membership queries read user_roles';

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS user_roles Array(LowCardinality(String))
    DEFAULT if(role = '', [], [role])
    COMMENT 'Distinct roles evaluated for this call, caller order; advisory + client-assertable';

ALTER TABLE hexgate_audit.policy_decision
    ADD COLUMN IF NOT EXISTS deciding_role LowCardinality(String) DEFAULT ''
    COMMENT 'Role whose policy granted/gated the call; empty when every role denied';

-- Bake the DEFAULT into existing parts. mutations_sync=2 blocks until every
-- replica finishes, so this can't "succeed" while the data is inconsistent. If
-- the table is too large to block on, drop to 0 and poll system.mutations —
-- but do not skip the statement.
ALTER TABLE hexgate_audit.policy_decision
    MATERIALIZE COLUMN user_roles
    SETTINGS mutations_sync = 2;
