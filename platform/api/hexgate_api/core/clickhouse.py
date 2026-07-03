"""ClickHouse client + reachability probe.

Single shared Client — clickhouse-connect manages its own HTTP pool internally.
"""

from __future__ import annotations

import logging
from functools import lru_cache

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
