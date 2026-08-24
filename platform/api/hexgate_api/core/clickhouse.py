"""ClickHouse client + reachability probe.

Single shared Client — clickhouse-connect manages its own HTTP pool internally.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import KW_ONLY, dataclass
from functools import lru_cache
from typing import Generic, Protocol, TypeVar

import clickhouse_connect
from clickhouse_connect.driver.client import Client
from clickhouse_connect.driver.exceptions import DatabaseError, OperationalError

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


E = TypeVar("E")
_E_contra = TypeVar("_E_contra", contravariant=True)


@dataclass(frozen=True, slots=True)
class BatchItem(Generic[E]):
    """One event plus the ids it resolves to, for the ``insert_*_batch`` paths.

    Both ids are keyword-only on purpose: they are two adjacent strings, and
    a positional ``(event, agent_version_id, project_id)`` slip would land
    every row with the ids transposed and nothing to catch it. This mirrors
    the ``*, project_id, agent_version_id`` signature of the single-row
    inserts, so the batch path is no easier to get wrong than they are.
    """

    event: E
    _: KW_ONLY
    project_id: str
    agent_version_id: str


class RowBuilder(Protocol[_E_contra]):
    """Shape one event into a row, in the caller's column order."""

    def __call__(
        self, event: _E_contra, *, project_id: str, agent_version_id: str
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
    row_builder: RowBuilder[E],
    items: Sequence[BatchItem[E]],
) -> None:
    """Insert ``items`` as one multi-row insert into ``table``, rows built by
    ``row_builder`` in ``columns`` order. Retry semantics are the table
    engine's, not this function's; see the per-table ``insert_*_batch``
    docstrings.
    """
    if not items:
        return
    rows = [
        row_builder(
            item.event,
            project_id=item.project_id,
            agent_version_id=item.agent_version_id,
        )
        for item in items
    ]
    client.insert(table, rows, column_names=columns, settings=BATCH_INSERT_SETTINGS)


# --- Written-schema guard ------------------------------------------------------
#
# Generic machinery for the per-feature startup checks: each feature's
# service.py wraps verify_written_columns with its own (table, columns), so no
# feature has to know about another feature's tables.


class SchemaOutOfDate(Exception):
    """An event table is missing a column the ingest writes."""

    def __init__(self, missing: dict[str, list[str]]) -> None:
        detail = "; ".join(
            f"{table}: {', '.join(columns)}"
            for table, columns in sorted(missing.items())
        )
        super().__init__(
            f"ClickHouse schema is behind this build ({detail}). "
            "Recreate the volume so init/schema.sql runs (`make clickhouse-reset` "
            "locally) before starting the API. Event tables ship no migrations: "
            "no ALTER can restate pre-existing rows truthfully."
        )
        self.missing = missing


_UNKNOWN_TABLE_CODE = 60
# clickhouse-connect exposes the server-side code only in the message text;
# DatabaseError carries no structured attribute for it.
_SERVER_ERROR_CODE_RE = re.compile(r"code:\s*(\d+)")


def _server_error_code(exc: DatabaseError) -> int | None:
    match = _SERVER_ERROR_CODE_RE.search(str(exc))
    return int(match.group(1)) if match else None


def verify_written_columns(
    client: Client, tables: Sequence[tuple[str, list[str]]]
) -> None:
    """Raise :class:`SchemaOutOfDate` if a written column is missing.

    Extra server-side columns are fine — only gaps in what we write break
    inserts. Startup-only: changing this needs a deployment or manual DDL.

    An absent table breaks inserts exactly like an absent column, so it earns
    the same actionable error rather than a raw driver traceback out of the
    lifespan. Every other failure degrades to a warning: being unable to read
    the schema is not evidence that it is stale, and the error this would
    otherwise raise tells the operator to destroy the volume. Degrading is
    safe — a genuinely broken table makes inserts 503, which the SDK retries.
    """
    missing: dict[str, list[str]] = {}
    for table, columns in tables:
        try:
            present = table_columns(client, table)
        except OperationalError as exc:
            _log.warning(
                "ClickHouse unreachable during %s schema check: %s", table, exc
            )
            return
        except DatabaseError as exc:
            if _server_error_code(exc) != _UNKNOWN_TABLE_CODE:
                # ACCESS_DENIED on a scoped grant, quota, metadata blip…
                _log.warning("cannot verify the %s schema: %s", table, exc)
                return
            present = set()
        gaps = sorted(set(columns) - present)
        if gaps:
            missing[table] = gaps
    if missing:
        raise SchemaOutOfDate(missing)
