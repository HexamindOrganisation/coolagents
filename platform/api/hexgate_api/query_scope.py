"""Shared window/scope utilities for ClickHouse event-envelope reads.

Every event table (``policy_decision``, ``llm_invocation``, ...) shares the
same envelope columns — ``project_id``, ``occurred_at``, ``agent_name``,
``user_id`` — and the same accepted ingest window / dashboard time-range
handling (schema.sql's own header comment already anticipates future event
tables sharing this envelope). This module holds that shared logic once;
each feature's ``service.py`` imports from here instead of reaching into a
sibling feature's module.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

_log = logging.getLogger(__name__)


class EventOutOfWindow(Exception):
    """occurred_at falls outside the accepted ingest window."""


# Accepted occurred_at window: small future skew for client clocks, and no
# older than retention — rows past TTL would be merged away on arrival.
CLOCK_SKEW_FUTURE = timedelta(minutes=5)
RETENTION_WINDOW = timedelta(days=90)

# Dashboard windows → hours; 90d is the 90-day TTL ceiling.
WINDOW_HOURS: dict[str, int] = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}


def validate_event_window(occurred_at: datetime) -> None:
    """Raise :class:`EventOutOfWindow` when occurred_at is outside
    [now - retention, now + skew]. Mapped to 400 in each feature's router."""
    now = datetime.now(timezone.utc)
    if occurred_at > now + CLOCK_SKEW_FUTURE:
        raise EventOutOfWindow("occurred_at is in the future")
    if occurred_at < now - RETENTION_WINDOW:
        raise EventOutOfWindow("occurred_at is older than retention window")


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def prepare_date_range(
    start_date: datetime | None, end_date: datetime | None
) -> tuple[datetime | None, datetime | None]:
    start_date = _ensure_utc(start_date)
    end_date = _ensure_utc(end_date)

    if end_date:
        end_date = min(end_date, datetime.now(timezone.utc) + CLOCK_SKEW_FUTURE)

    if start_date and end_date:
        start_date = max(start_date, end_date - RETENTION_WINDOW)

    return start_date, end_date


def _date_range_valid(start: datetime | None, end: datetime | None) -> bool:
    """True if both dates are present and start <= end."""
    if not (start and end):
        return False
    if start > end:
        _log.warning(f"Date range invalid, start > end: {start} > {end}")
        return False
    return True


def scope_filters(
    project_id: str,
    since_hours: int,
    *,
    agent: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[str], dict[str, object]]:
    """WHERE + params shared by every envelope-scoped read: project, time
    window (an explicit date range when valid, else a rolling since_hours),
    and agent. Table-specific filters (role/tool, user, model, ...) are
    appended by each feature's own ``_scope()`` wrapper, in whatever order
    that feature's dashboard needs.

    Both branches bind a fixed instant, so the returned pair is a snapshot —
    callers issuing several queries from one scope depend on that."""
    where = ["project_id = {pid:String}"]
    params: dict[str, object] = {"pid": project_id}
    if _date_range_valid(start_date, end_date):
        where.append(
            "occurred_at >= {start_date:DateTime} AND occurred_at <= {end_date:DateTime}"
        )
        params["start_date"] = start_date
        params["end_date"] = end_date
    else:
        # NOT ``now() - INTERVAL {hrs} HOUR``: ClickHouse evaluates now() per
        # query, so two scans from one scope would share the SQL text but not
        # the window, and a row inserted between them would land in only one.
        where.append("occurred_at >= {since:DateTime}")
        params["since"] = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    if agent:
        where.append("agent_name = {agent:String}")
        params["agent"] = agent
    return where, params
