from clickhouse_connect.driver.client import Client

from datetime import datetime

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


# async_insert batches small inserts; wait_for_async_insert=1 blocks until flush
# so write failures surface synchronously — an llm invocation log must not ack-then-drop.
# Retry dedup is NOT handled here: insert-level dedup settings no-op on
# non-replicated tables. The ReplacingMergeTree(received_at) engine collapses
# duplicate event_ids on background merges instead (see schema.sql).
_LLM_INVOCATION_INSERT_SETTINGS = {
    "async_insert": 1,
    "wait_for_async_insert": 1,
}


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
    row = [
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

    clickhouse_client.insert(
        "llm_invocation",
        [row],
        column_names=_LLM_INVOCATION_COLUMNS,
        settings=_LLM_INVOCATION_INSERT_SETTINGS,
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
