from collections.abc import Sequence

from clickhouse_connect.driver.client import Client

from datetime import datetime

from hexgate_api.core.clickhouse import BatchItem, insert_batch, verify_written_columns
from hexgate_api.query_scope import scope_filters
from hexgate_api.schemas import LlmInvocationEvent

# Order matches schema.sql; received_at absent (server-stamped via column default).
_LLM_INVOCATION_COLUMNS = [
    "event_id",
    "occurred_at",
    "project_id",
    "agent_name",
    "agent_version_id",
    "session_id",
    "user_id",
    "model",
    "input_tokens",
    "output_tokens",
    "latency_ms",
    "status",
    "error_code",
]

LLM_INVOCATION_TABLE = "llm_invocation"


def verify_schema(client: Client) -> None:
    """Raise AuditSchemaOutOfDate if llm_invocation misses a written column.

    This feature's slice of the startup guard — same machinery and semantics
    as the audit tables' check (see core.clickhouse.verify_written_columns)."""
    verify_written_columns(client, ((LLM_INVOCATION_TABLE, _LLM_INVOCATION_COLUMNS),))


# async_insert batches small inserts; wait_for_async_insert=1 blocks until flush
# so write failures surface synchronously — an llm invocation log must not ack-then-drop.
# Retry dedup is NOT handled here: insert-level dedup settings no-op on
# non-replicated tables. The ReplacingMergeTree(received_at) engine collapses
# duplicate event_ids on background merges instead (see schema.sql).
_LLM_INVOCATION_INSERT_SETTINGS = {
    "async_insert": 1,
    "wait_for_async_insert": 1,
}


def _llm_invocation_row(
    event: LlmInvocationEvent, *, project_id: str, agent_version_id: str
) -> list:
    """Build one llm_invocation row in ``_LLM_INVOCATION_COLUMNS`` order,
    shared by the single-row and batch insert paths."""
    return [
        event.event_id,
        event.occurred_at,
        project_id,  # bearer-resolved
        event.agent_name,
        agent_version_id,  # platform-resolved
        event.session_id,
        event.user_id,
        event.model,
        event.input_tokens,
        event.output_tokens,
        event.latency_ms,
        event.status,
        event.error_code,
    ]


def insert_llm_invocation(
    clickhouse_client: Client,
    *,
    event: LlmInvocationEvent,
    project_id: str,
    agent_version_id: str,
) -> None:
    """Write one row to llm_invocation.

    Raises ClickHouseError on insert failure; propagates so the caller maps
    it to a transport error.
    """
    row = _llm_invocation_row(
        event, project_id=project_id, agent_version_id=agent_version_id
    )
    clickhouse_client.insert(
        LLM_INVOCATION_TABLE,
        [row],
        column_names=_LLM_INVOCATION_COLUMNS,
        settings=_LLM_INVOCATION_INSERT_SETTINGS,
    )


def insert_llm_invocations_batch(
    clickhouse_client: Client,
    items: Sequence[BatchItem[LlmInvocationEvent]],
) -> None:
    """Write many llm_invocation rows in one batch insert.

    Each ``BatchItem`` carries its own ``project_id`` and ``agent_version_id``
    (keyword-only, see ``BatchItem``) — resolved per item, because a consumer
    batch aggregates across Kafka records and so can span projects and agents.
    Retry-safe rather than atomic: a failed call can have landed part of the
    batch (ClickHouse commits per block), so the caller retries the whole
    batch — safe because
    ReplacingMergeTree(received_at) eventually collapses re-inserted
    event_ids on a background merge (both copies are visible to non-FINAL
    reads until then). Same guarantee edges as ``insert_decisions_batch`` in
    features/audit/service.py: dedup stays within the monthly received_at
    partition, and an intra-batch duplicate collapses at insert time only if
    both copies fall in the same insert block — otherwise it waits for a
    background merge. No async_insert, unlike the single-row path — see
    ``BATCH_INSERT_SETTINGS`` in core/clickhouse.py for why.
    """
    insert_batch(
        clickhouse_client,
        "llm_invocation",
        _LLM_INVOCATION_COLUMNS,
        _llm_invocation_row,
        items,
    )


def _scope(
    project_id: str,
    since_hours: int,
    *,
    agent: str | None = None,
    user: str | None = None,
    model: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[str], dict[str, object]]:
    """WHERE + params for llm_invocation reads: the shared project/window/agent
    scope, plus this table's own user/model filters (no role/tool — those
    columns don't exist here)."""
    where, params = scope_filters(
        project_id, since_hours, agent=agent, start_date=start_date, end_date=end_date
    )
    if user is not None:
        where.append("user_id = {user:String}")
        params["user"] = user
    if model:
        where.append("model = {model:String}")
        params["model"] = model
    return where, params


# Grand total + per-(model|agent|user) in one scan. Rows are classified by
# their GROUPING() flags (1 = column rolled up); only the () set rolls up
# every dimension, so that's the grand-total row.
_GROUPING_SETS = "GROUPING SETS ((), (model), (agent_name), (user_id))"
_SELECT_COLS = [
    "model",
    "agent_name",
    "user_id",
    "GROUPING(model) AS g_model",
    "GROUPING(agent_name) AS g_agent",
    "GROUPING(user_id) AS g_user",
    "count() AS calls",
    "sum(input_tokens) AS input_tokens",
    "sum(output_tokens) AS output_tokens",
]


def summarize_llm_invocations(
    client: Client,
    *,
    project_id: str,
    since_hours: int,
    agent: str | None = None,
    user: str | None = None,
    model: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict:
    """Totals + breakdowns for the scoped slice. Returns ``{totals, by_model,
    by_agent, by_user}``; each breakdown is ``{key, calls, input_tokens,
    output_tokens, total_tokens}`` sorted by ``total_tokens`` desc."""
    where, params = _scope(
        project_id,
        since_hours,
        agent=agent,
        user=user,
        model=model,
        start_date=start_date,
        end_date=end_date,
    )
    where_sql = " AND ".join(where)
    summary_sql = (
        f"SELECT {', '.join(_SELECT_COLS)} "
        f"FROM llm_invocation WHERE {where_sql} GROUP BY {_GROUPING_SETS}"
    )
    result = client.query(summary_sql, parameters=params)

    totals = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    by_model: dict[str, dict[str, int]] = {}
    by_agent: dict[str, dict[str, int]] = {}
    by_user: dict[str, dict[str, int]] = {}

    def _bucket(
        store: dict[str, dict[str, int]],
        key: str,
        calls: int,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        bucket = store.setdefault(
            key,
            {"calls": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )
        bucket["calls"] += calls
        bucket["input_tokens"] += input_tokens
        bucket["output_tokens"] += output_tokens
        bucket["total_tokens"] += input_tokens + output_tokens

    for (
        row_model,
        row_agent,
        row_user,
        g_model,
        g_agent,
        g_user,
        calls,
        input_tokens,
        output_tokens,
    ) in result.result_rows:
        calls = int(calls)
        input_tokens = int(input_tokens)
        output_tokens = int(output_tokens)
        if g_model and g_agent and g_user:  # () grand total
            totals = {
                "calls": calls,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }
        elif not g_model:  # (model)
            _bucket(by_model, row_model, calls, input_tokens, output_tokens)
        elif not g_agent:  # (agent_name)
            _bucket(by_agent, row_agent, calls, input_tokens, output_tokens)
        else:  # (user_id)
            _bucket(by_user, row_user, calls, input_tokens, output_tokens)

    def _ranked(store: dict[str, dict[str, int]]) -> list[dict]:
        return sorted(
            ({"key": k, **v} for k, v in store.items()),
            key=lambda r: r["total_tokens"],
            reverse=True,
        )

    return {
        "totals": totals,
        "by_model": _ranked(by_model),
        "by_agent": _ranked(by_agent),
        "by_user": _ranked(by_user),
    }
