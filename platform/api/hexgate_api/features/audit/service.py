"""ClickHouse layer for audit events — both halves of the pipeline.

Write path: validation caps + ``insert_decision`` (the SDK ingest).
Read path: ``summarize`` / ``timeseries`` / ``list_decisions`` (the
dashboard aggregations). They stay in one module because they share the
table contract (``_DECISION_COLUMNS``, windows, scope filters) — unlike
``services.py``, nothing here touches the relational store.

HTTP-agnostic — exceptions map to status codes in main.py.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from collections import deque

from clickhouse_connect.driver.client import Client

from hexgate_api.schemas import (
    AnomalySeverity,
    AuditAnomaly,
    AuditOutcome,
    DecisionEvent,
)

_log = logging.getLogger(__name__)


class AuditPayloadTooLarge(Exception):
    """Serialized payload column exceeds its per-field byte cap."""

    def __init__(self, field: str, limit: int) -> None:
        super().__init__(f"{field} exceeds {limit} bytes")
        self.field = field
        self.limit = limit


class AuditEventOutOfWindow(Exception):
    """occurred_at falls outside the accepted ingest window."""


MAX_ARGS_BYTES = 8 * 1024
MAX_HINT_BYTES = 4 * 1024

# Accepted occurred_at window: small future skew for client clocks, and no
# older than retention — rows past TTL would be merged away on arrival.
CLOCK_SKEW_FUTURE = timedelta(minutes=5)
RETENTION_WINDOW = timedelta(days=90)

_ANOMALY_MIN_REQUESTS = 5
_TIMEDELTA_ANOMALY_HOURS = 1
_WINDOW_TD = timedelta(hours=_TIMEDELTA_ANOMALY_HOURS)
_DENY_RATE_MEDIUM = 0.3
_DENY_RATE_HIGH = 0.5


def validate_event_window(occurred_at: datetime) -> None:
    """Raise :class:`AuditEventOutOfWindow` when occurred_at is outside
    [now - retention, now + skew]. Mapped to 400 in main.py."""
    now = datetime.now(timezone.utc)
    if occurred_at > now + CLOCK_SKEW_FUTURE:
        raise AuditEventOutOfWindow("occurred_at is in the future")
    if occurred_at < now - RETENTION_WINDOW:
        raise AuditEventOutOfWindow("occurred_at is older than retention window")


# Order matches schema.sql; received_at absent (server-stamped via column default).
_DECISION_COLUMNS = [
    "event_id",
    "occurred_at",
    "project_id",
    "agent_name",
    "agent_version_id",
    "session_id",
    "user_id",
    "tool_name",
    "role",
    "outcome",
    "error_type",
    "reason",
    "violations",
    "hint",
    "arguments",
]

# async_insert batches small inserts; wait_for_async_insert=1 blocks until flush
# so write failures surface synchronously — an audit log must not ack-then-drop.
# Retry dedup is NOT handled here: insert-level dedup settings no-op on
# non-replicated tables. The ReplacingMergeTree(received_at) engine collapses
# duplicate event_ids on background merges instead (see schema.sql).
_DECISION_INSERT_SETTINGS = {
    "async_insert": 1,
    "wait_for_async_insert": 1,
}


def insert_decision(
    clickhouse_client: Client,
    *,
    event: DecisionEvent,
    project_id: str,
    agent_version_id: str,
) -> None:
    """Write one decision row to policy_decision.

    Raises AuditPayloadTooLarge on payload overflow and ClickHouseError on
    insert failure; both propagate so the caller maps them to transport errors.
    """
    args_json = (
        json.dumps(event.arguments, default=str) if event.arguments is not None else ""
    )
    hint_json = json.dumps(event.hint, default=str) if event.hint is not None else ""
    if len(args_json.encode("utf-8")) > MAX_ARGS_BYTES:
        raise AuditPayloadTooLarge("arguments", MAX_ARGS_BYTES)
    if len(hint_json.encode("utf-8")) > MAX_HINT_BYTES:
        raise AuditPayloadTooLarge("hint", MAX_HINT_BYTES)

    row = [
        event.event_id,
        event.occurred_at,
        project_id,  # bearer-resolved
        event.agent_name,
        agent_version_id,  # platform-resolved
        event.session_id,
        event.user_id,
        event.tool_name,
        event.role,
        event.outcome,
        event.error_type,
        event.reason,
        list(event.violations),
        hint_json,
        args_json,
    ]
    clickhouse_client.insert(
        "policy_decision",
        [row],
        column_names=_DECISION_COLUMNS,
        settings=_DECISION_INSERT_SETTINGS,
    )


# --- Read path: dashboard aggregation (query-time GROUP BY, no rollups) -------

# Dashboard windows → hours; 90d is the 90-day TTL ceiling.
WINDOW_HOURS: dict[str, int] = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}


def bucket_minutes_for_timedelta(delta: timedelta) -> int:
    """Bucket size (minutes) for a free-form date range.

    ≤30min→1min, ≤1h→5min, ≤6h→15min, ≤12h→30min, ≤24h→60min, ≤7d→360min, else→1440min.
    """
    if delta <= timedelta(minutes=30):
        return 1
    elif delta <= timedelta(hours=1):
        return 5
    elif delta <= timedelta(hours=6):
        return 15
    elif delta <= timedelta(hours=12):
        return 30
    elif delta <= timedelta(hours=24):
        return 60
    elif delta <= timedelta(days=7):
        return 360
    else:
        return 1440


def _zero_counts() -> dict[str, int]:
    return {"all": 0, **{e.value: 0 for e in AuditOutcome}}


def _date_range_valid(start: datetime | None, end: datetime | None) -> bool:
    """True if both dates are present and start <= end."""
    if not (start and end):
        return False
    if start > end:
        _log.warning(f"Date range invalid, start > end: {start} > {end}")
        return False
    return True


def _scope(
    project_id: str,
    since_hours: int,
    *,
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> tuple[list[str], dict[str, object]]:
    """Shared WHERE + params for the scope filters (project/window/agent/role/
    tool) that all reads narrow by. Pass role="" for the no-role bucket."""
    where = [
        "project_id = {pid:String}",
    ]
    params: dict[str, object] = {"pid": project_id}
    if _date_range_valid(start_date, end_date):
        where.append(
            "occurred_at >= {start_date:DateTime} AND occurred_at <= {end_date:DateTime}"
        )
        params["start_date"] = start_date
        params["end_date"] = end_date
    else:
        params["hrs"] = since_hours
        where.append("occurred_at >= now() - INTERVAL {hrs:UInt32} HOUR")
    if agent:
        where.append("agent_name = {agent:String}")
        params["agent"] = agent
    if role is not None:
        where.append("role = {role:String}")
        params["role"] = role
    if tool:
        where.append("tool_name = {tool:String}")
        params["tool"] = tool
    if user is not None:
        where.append("user_id = {user:String}")
        params["user"] = user
    return where, params


# Grand total + per-outcome + per-(agent|role|tool, outcome) in one scan.
# Rows are classified by their GROUPING() flags (1 = column rolled up); only the
# () set rolls up outcome, so g_outcome=1 marks the grand-total row.
_GROUPING_SETS = (
    "GROUPING SETS ((), (outcome), (agent_name, outcome), "
    "(role, outcome), (tool_name, outcome), (user_id, outcome))"
)
_SELECT_COLS = [
    "agent_name",
    "role",
    "tool_name",
    "user_id",
    "outcome",
    "GROUPING(agent_name) AS g_agent",
    "GROUPING(role) AS g_role",
    "GROUPING(tool_name) AS g_tool",
    "GROUPING(user_id) AS g_user",
    "GROUPING(outcome) AS g_outcome",
    "count() AS n",
]


def summarize(
    client: Client,
    *,
    project_id: str,
    since_hours: int,
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict:
    """Totals + breakdowns for the scoped slice. Returns ``{totals, by_agent,
    by_role, by_tool}``; each breakdown is ``{key, all, allow, deny,
    needs_approval}`` sorted by ``all`` desc. An empty role keeps its raw
    ``""`` key — labelling it ("(none)") is the dashboard's concern, so no
    string is reserved on the wire."""
    where, params = _scope(
        project_id,
        since_hours,
        agent=agent,
        role=role,
        tool=tool,
        user=user,
        start_date=start_date,
        end_date=end_date,
    )
    where_sql = " AND ".join(where)
    summary_sql = (
        f"SELECT {', '.join(_SELECT_COLS)} "
        f"FROM policy_decision WHERE {where_sql} GROUP BY {_GROUPING_SETS}"
    )
    result = client.query(summary_sql, parameters=params)

    totals = _zero_counts()
    by_agent: dict[str, dict[str, int]] = {}
    by_role: dict[str, dict[str, int]] = {}
    by_tool: dict[str, dict[str, int]] = {}
    by_user: dict[str, dict[str, int]] = {}

    def _add(store: dict[str, dict[str, int]], key: str, outcome: str, n: int) -> None:
        bucket = store.setdefault(key, _zero_counts())
        bucket["all"] += n
        if outcome in bucket:
            bucket[outcome] += n

    for (
        agent,
        role,
        tool,
        user,
        outcome,
        g_agent,
        g_role,
        g_tool,
        g_user,
        g_outcome,
        n,
    ) in result.result_rows:
        n = int(n)
        if g_outcome:  # only the () grand-total set rolls up outcome
            totals["all"] = n
        elif g_agent and g_role and g_tool and g_user:  # (outcome) set
            if outcome in totals:
                totals[outcome] = n
        elif not g_agent:  # (agent_name, outcome)
            _add(by_agent, agent, outcome, n)
        elif not g_role:  # (role, outcome)
            _add(by_role, role, outcome, n)
        elif not g_tool:  # (tool_name, outcome)
            _add(by_tool, tool, outcome, n)
        else:  # (user_id, outcome)
            _add(by_user, user, outcome, n)

    def _ranked(store: dict[str, dict[str, int]]) -> list[dict]:
        return sorted(
            ({"key": k, **v} for k, v in store.items()),
            key=lambda r: r["all"],
            reverse=True,
        )

    return {
        "totals": totals,
        "by_agent": _ranked(by_agent),
        "by_role": _ranked(by_role),
        "by_tool": _ranked(by_tool),
        "by_user": _ranked(by_user),
    }


def timeseries(
    client: Client,
    *,
    project_id: str,
    since_hours: int,
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[dict]:
    """Per-bucket outcome counts, ordered by bucket. Sparse: empty buckets are
    omitted. Returns ``[{bucket, allow, deny, needs_approval}]``."""
    where, params = _scope(
        project_id,
        since_hours,
        agent=agent,
        role=role,
        tool=tool,
        user=user,
        start_date=start_date,
        end_date=end_date,
    )
    if "start_date" in params:
        bucket_minutes = bucket_minutes_for_timedelta(end_date - start_date)
    else:
        bucket_minutes = bucket_minutes_for_timedelta(timedelta(hours=since_hours))
    params["bucket"] = bucket_minutes
    where_sql = " AND ".join(where)
    ts_sql = (
        "SELECT toStartOfInterval(occurred_at, INTERVAL {bucket:UInt32} MINUTE) AS t, "
        f"outcome, count() AS n FROM policy_decision WHERE {where_sql} "
        "GROUP BY t, outcome ORDER BY t"
    )
    result = client.query(ts_sql, parameters=params)
    points: dict[object, dict] = {}
    for t, outcome, n in result.result_rows:
        point = points.setdefault(
            t, {"bucket": t, **{e.value: 0 for e in AuditOutcome}}
        )
        if outcome in point:
            point[outcome] = int(n)
    return [points[t] for t in sorted(points)]


def _decode_json_column(raw: str) -> object:
    """Decode a stored JSON string ("" → None); leave malformed values as-is."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return raw


_LIST_COLUMNS = (
    "event_id, occurred_at, received_at, agent_name, agent_version_id, "
    "session_id, user_id, tool_name, role, outcome, error_type, "
    "reason, violations, hint, arguments"
)


def list_decisions(
    client: Client,
    *,
    project_id: str,
    since_hours: int,
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    outcome: str | None = None,
    session_id: str | None = None,
    limit: int = 25,
    offset: int = 0,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> dict:
    """Detail rows for the events table, newest first. Scope filters plus
    table-only ``outcome``/``session_id``. Returns ``{rows, total, limit,
    offset}`` with ``total`` the unpaginated match count."""
    where, params = _scope(
        project_id,
        since_hours,
        agent=agent,
        role=role,
        tool=tool,
        user=user,
        start_date=start_date,
        end_date=end_date,
    )
    if outcome:
        where.append("outcome = {outcome:String}")
        params["outcome"] = outcome
    if session_id:
        where.append("session_id = {session_id:String}")
        params["session_id"] = session_id
    where_sql = " AND ".join(where)

    # One scan yields the page and its ``total`` together: a separate ``count()``
    # would re-evaluate ``now()`` and could disagree with the page as rows arrive.
    # ``count() OVER ()`` is computed before LIMIT, so it carries the full match
    # count on every returned row.
    page_params = {**params, "lim": limit, "off": offset}
    result = client.query(
        f"SELECT {_LIST_COLUMNS}, count() OVER () AS total_matches "
        f"FROM policy_decision WHERE {where_sql} "
        "ORDER BY occurred_at DESC LIMIT {lim:UInt32} OFFSET {off:UInt32}",
        parameters=page_params,
    )
    rows = []
    total = 0
    for raw in result.result_rows:
        row = dict(zip(result.column_names, raw))
        total = int(row.pop("total_matches"))
        row["violations"] = list(row.get("violations") or [])
        row["hint"] = _decode_json_column(row.get("hint") or "")
        row["arguments"] = _decode_json_column(row.get("arguments") or "")
        rows.append(row)

    # An empty page past the end (offset > 0) carries no window value, so the
    # match count is unavailable; fall back to a plain count for that rare case.
    if not rows and offset:
        total = int(
            client.query(
                f"SELECT count() FROM policy_decision WHERE {where_sql}",
                parameters=params,
            ).result_rows[0][0]
        )

    return {"rows": rows, "total": total, "limit": limit, "offset": offset}


def _sliding_window_anomalies(
    rows: list[tuple],
) -> list[AuditAnomaly]:
    """Emits one anomaly per above-threshold burst (not per qualifying window) so the full
    peak window is captured rather than the first qualifying moment."""
    list_anomalies: list[AuditAnomaly] = []
    curr_user, curr_deny, window, best_burst = "", 0, deque(), None

    def _flush(burst: dict | None) -> None:
        if burst:
            list_anomalies.append(AuditAnomaly(**burst))

    for user, timestamp, decision in rows:
        if user != curr_user:
            _flush(best_burst)
            curr_user = user
            curr_deny = 0
            window.clear()
            best_burst = None

        while window and timestamp - window[0][0] > _WINDOW_TD:
            _, old_decision = window.popleft()
            curr_deny -= int(old_decision == AuditOutcome.DENY)

        window.append((timestamp, decision))
        curr_deny += int(decision == AuditOutcome.DENY)
        window_length = len(window)
        deny_rate = curr_deny / window_length

        if window_length >= _ANOMALY_MIN_REQUESTS and deny_rate >= _DENY_RATE_HIGH:
            severity = AnomalySeverity.HIGH
        elif window_length >= _ANOMALY_MIN_REQUESTS and deny_rate >= _DENY_RATE_MEDIUM:
            severity = AnomalySeverity.MEDIUM
        else:
            severity = None

        if severity:
            candidate = dict(
                user_id=curr_user,
                severity=severity,
                deny=curr_deny,
                all=window_length,
                deny_rate=deny_rate,
                first_seen=window[0][0],
                last_seen=window[-1][0],
            )
            if best_burst is None or (deny_rate, window_length) >= (
                best_burst["deny_rate"],
                best_burst["all"],
            ):
                best_burst = candidate
        elif best_burst:
            # After eviction the window already shrank to just the current
            # event, so reseed it. After a rate-drop the window still holds
            # many live events that belong to neither burst; discard them all.
            last = window[-1] if len(window) == 1 else None
            _flush(best_burst)
            window.clear()
            curr_deny = 0
            if last:
                window.append(last)
                curr_deny = int(last[1] == AuditOutcome.DENY)
            best_burst = None

    _flush(best_burst)
    return list_anomalies


def anomalies(
    client: Client,
    *,
    project_id: str,
    since_hours: int,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
) -> list[AuditAnomaly]:
    """
    Return a list of per-user anomaly summaries for the given time window.

    An anomaly is defined as an abnormal rate of denied requests for a user in a 1-hour window with more than
    ANOMALY_MIN_REQUESTS requests. The severity of the anomaly is determined by the deny rate:
    - High: deny rate >= 0.5
    - Medium: 0.3 <= deny rate < 0.5

    The current implementation loads all the data into memory and processes it in Python.
    Time complexity and space complexity are both O(n), with n the number of requests in the given time window.
    For large datasets, chunks of data can be processed in batches to avoid memory issues.
    An other approach is to pre-compute the anomalies in ClickHouse with a periodical job, and only compute the new anomalies in the API call.

    These optimizations should be implemented once the data volume grows and performance issues arise.
    """

    # Find qualifying users with more than ANOMALY_MIN_REQUESTS requests in the given time window
    where, params = _scope(
        project_id,
        since_hours,
        start_date=start_date,
        end_date=end_date,
    )
    where_sql = " AND ".join(where)
    params["min_requests"] = _ANOMALY_MIN_REQUESTS
    qualifying_users_sql = (
        f"SELECT user_id FROM policy_decision WHERE {where_sql} "
        "GROUP BY user_id HAVING count() >= {min_requests:UInt32}"
    )

    result_qualifying_users = client.query(qualifying_users_sql, parameters=params)
    qualifying_user_ids = [row[0] for row in result_qualifying_users.result_rows]
    if not qualifying_user_ids:
        return []

    params["uids"] = qualifying_user_ids
    anomalies_sql = (
        "SELECT user_id, occurred_at, outcome FROM policy_decision "
        f"WHERE {where_sql} AND user_id IN ({{uids:Array(String)}}) "
        "ORDER BY user_id, occurred_at"
    )
    result = client.query(anomalies_sql, parameters=params)
    return _sliding_window_anomalies(result.result_rows)


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
