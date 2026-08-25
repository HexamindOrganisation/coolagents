"""ClickHouse client + reachability probe.

Single shared Client — clickhouse-connect manages its own HTTP pool internally.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from functools import lru_cache
from typing import Protocol, TypeVar

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from hexgate_api.settings import get_settings

_log = logging.getLogger(__name__)


@lru_cache
def get_clickhouse() -> Client:
    """Return the process-wide ClickHouse client, configured from settings."""
    settings = get_settings()
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        database=settings.clickhouse_database,
        secure=settings.clickhouse_secure,
        compress=True,
        connect_timeout=5,
        send_receive_timeout=30,
        # No session_id: this client is shared across the request threadpool,
        # and a session would reject concurrent queries. We use no session state.
        autogenerate_session_id=False,
    )


def ping() -> bool:
    """Return True if ClickHouse is reachable. Suppresses all errors."""
    try:
        return bool(get_clickhouse().ping())
    except Exception as exc:
        _log.warning("ClickHouse ping failed: %s", exc)
        return False


def table_columns(client: Client, table: str) -> set[str]:
    """Column names ClickHouse reports for ``table``.

    ``table`` is interpolated, so it must stay a code-owned constant.
    """
    result = client.query(f"DESCRIBE TABLE {table}")
    name_index = result.column_names.index("name")
    return {row[name_index] for row in result.result_rows}


_E = TypeVar("_E", contravariant=True)


class RowBuilder(Protocol[_E]):
    """Shape one event into a row, in the caller's column order.

    Keyword-only ids on purpose — the batch item is a bare tuple, and this
    is where the two adjacent ``str`` fields get names again.
    """

    def __call__(
        self, event: _E, *, project_id: str, agent_version_id: str
    ) -> list: ...


# The one batch-insert contract, shared by every ``insert_*_batch``:
# - Empty batch never touches ClickHouse.
# - No async_insert, unlike the single-row paths: it exists to coalesce many
#   small inserts, and this insert is already a batch — buffering it again
#   would only add a server-side copy and a busy-timeout wait. A plain
#   synchronous insert surfaces failures the same way (the call raises).
#   Pinned to 0 rather than left to the server default so a cluster-wide
#   async_insert=1 can't silently turn this into ack-before-durable.
BATCH_INSERT_SETTINGS = {"async_insert": 0}


def insert_batch(
    client: Client,
    table: str,
    columns: Sequence[str],
    row_builder: RowBuilder[_E],
    items: list[tuple[_E, str, str]],
) -> None:
    """Insert ``items`` — ``(event, project_id, agent_version_id)`` each — as
    one multi-row insert into ``table``, rows built by ``row_builder`` in
    ``columns`` order. Retry semantics are the table engine's, not this
    function's; see the per-table ``insert_*_batch`` docstrings.
    """
    if not items:
        return
    rows = [
        row_builder(event, project_id=project_id, agent_version_id=agent_version_id)
        for event, project_id, agent_version_id in items
    ]
    client.insert(table, rows, column_names=columns, settings=BATCH_INSERT_SETTINGS)
