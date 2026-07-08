from clickhouse_connect.driver.client import Client

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
