"""ClickHouse dependency: resolve the client, mapping connect failures to 503."""

import logging

from clickhouse_connect.driver.exceptions import ClickHouseError
from fastapi import HTTPException

from hexgate_api.core.clickhouse import get_clickhouse

_log = logging.getLogger(__name__)


def _audit_unavailable() -> HTTPException:
    return HTTPException(
        status_code=503,
        detail="audit log temporarily unavailable",
        headers={"Retry-After": "5"},
    )


def require_clickhouse():
    """Resolve the ClickHouse client as a dependency, mapping connect failures
    to 503 — get_clickhouse() connects eagerly, so without this the raise
    escapes dependency resolution as an uncaught 500."""
    try:
        return get_clickhouse()
    except ClickHouseError as exc:
        _log.warning("ClickHouse unreachable resolving audit client: %s", exc)
        raise _audit_unavailable()
