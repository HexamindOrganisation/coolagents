"""Tests for /v1/audit/decisions and the audit Pydantic models.

Endpoint tests stub auth + ClickHouse via dependency_overrides. Integration
tests under @pytest.mark.integration round-trip against a real local ClickHouse.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from clickhouse_connect.driver.exceptions import (
    ClickHouseError,
    DataError,
    OperationalError,
)
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.features.audit import service as audit
from hexgate_api.features.audit.service import (
    CLOCK_SKEW_FUTURE,
    list_decisions,
    summarize,
    _sliding_window_anomalies,
)
from hexgate_api.core.keystore import FileKeyStore
from hexgate_api.core.db import get_session
from hexgate_api.deps.clickhouse import require_clickhouse
from hexgate_api.deps.identity import require_user
from hexgate_api.deps.org import require_org_member
from hexgate_api.deps.tokens import require_project
from hexgate_api.main import app
from hexgate_api.schemas import AnomalySeverity, AuditOutcome, DecisionEvent

from hexgate_api.features.audit.service import prepare_date_range

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _event(**overrides) -> dict:
    """Return a minimal-required event payload, with optional overrides."""
    base = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": _now().isoformat(),
        "agent_name": "example_agent",
        "tool_name": "read_file",
        "outcome": "deny",
    }
    return {**base, **overrides}


# ---------------------------------------------------------------------------
# Pydantic schema validation
# ---------------------------------------------------------------------------


def test_minimal_event_constructs_with_envelope_defaults() -> None:
    e = DecisionEvent(**_event())
    # Envelope defaults (agent_version_id is server-resolved, not in the wire model)
    assert e.session_id == ""
    assert e.user_id == ""
    # Decision-detail defaults
    assert e.role == ""
    assert e.error_type == ""
    assert e.violations == []
    assert e.hint is None
    assert e.arguments is None


def test_envelope_fields_inherited_via_mixin() -> None:
    """DecisionEvent inherits the wire envelope; server-resolved fields stay out."""
    expected = {"event_id", "occurred_at", "agent_name", "session_id", "user_id"}
    assert expected <= DecisionEvent.model_fields.keys()
    assert "project_id" not in DecisionEvent.model_fields
    assert "received_at" not in DecisionEvent.model_fields
    assert "agent_version_id" not in DecisionEvent.model_fields


def test_bad_outcome_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        DecisionEvent(**_event(outcome="maybe"))
    assert "outcome" in str(exc.value)


def test_missing_required_field_rejected() -> None:
    payload = _event()
    payload.pop("tool_name")
    with pytest.raises(ValidationError) as exc:
        DecisionEvent(**payload)
    assert "tool_name" in str(exc.value)


def test_oversized_agent_name_rejected() -> None:
    with pytest.raises(ValidationError) as exc:
        DecisionEvent(**_event(agent_name="x" * 300))
    assert "agent_name" in str(exc.value)


# ---------------------------------------------------------------------------
# Endpoint behaviour — auth + ClickHouse stubbed
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_clickhouse() -> MagicMock:
    """MagicMock for the ClickHouse client."""
    return MagicMock()


# Stub return value for the agent_version_id lookup; tests assert it lands in the row.
_STUB_AGENT_VERSION_ID = "stub_v_id_xyz"


@pytest.fixture
def client(
    fake_clickhouse: MagicMock, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> TestClient:
    """TestClient with auth, ClickHouse, session, and version-lookup stubbed."""
    app.dependency_overrides[require_project] = lambda: "proj_test"
    app.dependency_overrides[require_clickhouse] = lambda: fake_clickhouse
    app.dependency_overrides[get_session] = lambda: MagicMock()

    async def _stub_version_lookup(_session, _project_id, _agent_name) -> str:
        return _STUB_AGENT_VERSION_ID

    monkeypatch.setattr(
        "hexgate_api.features.audit.router.get_latest_agent_version_id",
        _stub_version_lookup,
    )
    # The dashboard-read gating tests run the real require_org_member chain,
    # whose cookie transport needs an initialised keystore (same swap as the
    # client fixture in test_auth.py).
    original_keystore = keystore_mod.keystore
    keystore_mod.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    keystore_mod.keystore.ensure_keypair()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        keystore_mod.keystore = original_keystore


def test_happy_path_returns_202_and_inserts_row(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    payload = _event()
    r = client.post("/v1/audit/decisions", json=payload)

    assert r.status_code == 202, r.text
    assert r.json() == {"event_id": payload["event_id"]}

    fake_clickhouse.insert.assert_called_once()
    args, kwargs = fake_clickhouse.insert.call_args
    assert args[0] == "policy_decision"
    rows = args[1]
    assert len(rows) == 1
    assert len(rows[0]) == 15
    # Indices match _DECISION_COLUMNS in audit.py.
    assert rows[0][2] == "proj_test"  # project_id (bearer)
    assert rows[0][4] == _STUB_AGENT_VERSION_ID  # agent_version_id (platform)
    assert kwargs["column_names"] == audit._DECISION_COLUMNS
    assert kwargs["settings"]["async_insert"] == 1
    # Durable: block until flush so insert failures surface synchronously.
    assert kwargs["settings"]["wait_for_async_insert"] == 1


def test_agent_version_id_comes_from_platform_lookup(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """Even if the SDK sneaks agent_version_id into the body, the platform lookup wins."""
    payload = {**_event(), "agent_version_id": "sdk_provided_should_be_ignored"}
    r = client.post("/v1/audit/decisions", json=payload)
    assert r.status_code == 202

    rows = fake_clickhouse.insert.call_args.args[1]
    assert rows[0][4] == _STUB_AGENT_VERSION_ID
    assert "sdk_provided_should_be_ignored" not in rows[0]


def test_future_occurred_at_rejected(client: TestClient) -> None:
    far_future = (_now() + timedelta(minutes=10)).isoformat()
    r = client.post("/v1/audit/decisions", json=_event(occurred_at=far_future))
    assert r.status_code == 400
    assert "future" in r.json()["detail"]


def test_too_old_occurred_at_rejected(client: TestClient) -> None:
    too_old = (_now() - timedelta(days=91)).isoformat()
    r = client.post("/v1/audit/decisions", json=_event(occurred_at=too_old))
    assert r.status_code == 400
    assert "retention" in r.json()["detail"]


def test_oversized_arguments_rejected(client: TestClient) -> None:
    big = {"key": "x" * (audit.MAX_ARGS_BYTES + 100)}
    r = client.post("/v1/audit/decisions", json=_event(arguments=big))
    assert r.status_code == 413
    assert "arguments" in r.json()["detail"]


def test_oversized_hint_rejected(client: TestClient) -> None:
    big = {"globs": "y" * (audit.MAX_HINT_BYTES + 100)}
    r = client.post("/v1/audit/decisions", json=_event(hint=big))
    assert r.status_code == 413
    assert "hint" in r.json()["detail"]


def test_oversized_violation_item_rejected(client: TestClient) -> None:
    # Item count is capped at 64, but each item must also be bounded —
    # otherwise 64 unbounded strings get a multi-MB body past validation.
    r = client.post("/v1/audit/decisions", json=_event(violations=["z" * 2048]))
    assert r.status_code == 422


def test_pydantic_validation_returns_422(client: TestClient) -> None:
    """Bad outcome trips Pydantic before the handler runs."""
    r = client.post("/v1/audit/decisions", json=_event(outcome="maybe"))
    assert r.status_code == 422


def test_transient_clickhouse_error_returns_503_with_retry_after(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """A transport/transient failure is retryable → 503 Retry-After."""
    fake_clickhouse.insert.side_effect = OperationalError("connection refused")
    r = client.post("/v1/audit/decisions", json=_event())
    assert r.status_code == 503
    assert r.headers.get("retry-after") == "5"
    assert "unavailable" in r.json()["detail"]


def test_deterministic_clickhouse_error_returns_422(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """A storage rejection (bad type/value) is permanent → 422, not a retryable 503."""
    fake_clickhouse.insert.side_effect = DataError("unknown enum value")
    r = client.post("/v1/audit/decisions", json=_event())
    assert r.status_code == 422
    assert "retry-after" not in {k.lower() for k in r.headers}
    assert "rejected" in r.json()["detail"]


def test_naive_occurred_at_accepted_as_utc(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """A timezone-naive occurred_at is treated as UTC, not a 500 from the skew check."""
    naive = _now().replace(tzinfo=None).isoformat()  # UTC wall-clock, no offset/Z
    r = client.post("/v1/audit/decisions", json=_event(occurred_at=naive))
    assert r.status_code == 202, r.text
    fake_clickhouse.insert.assert_called_once()
    # occurred_at lands tz-aware in the row (index 1 per _DECISION_COLUMNS).
    stored = fake_clickhouse.insert.call_args.args[1][0][1]
    assert stored.tzinfo is not None


def test_clickhouse_unreachable_at_connect_returns_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_clickhouse() raising during dependency resolution maps to 503, not 500."""
    from fastapi import HTTPException

    from hexgate_api.deps.clickhouse import require_clickhouse

    def _boom() -> None:
        raise ClickHouseError("connection refused")

    monkeypatch.setattr("hexgate_api.deps.clickhouse.get_clickhouse", _boom)
    with pytest.raises(HTTPException) as exc:
        require_clickhouse()
    assert exc.value.status_code == 503
    assert exc.value.headers.get("Retry-After") == "5"


# ---------------------------------------------------------------------------
# _scope() — WHERE-clause + params composition
# ---------------------------------------------------------------------------

_BASE_WHERE = [
    "project_id = {pid:String}",
    "occurred_at >= now() - INTERVAL {hrs:UInt32} HOUR",
]


def test_scope_no_filters() -> None:
    where, params = audit._scope("p1", 24)
    assert where == _BASE_WHERE
    assert params == {"pid": "p1", "hrs": 24}


def test_scope_agent_only() -> None:
    where, params = audit._scope("p1", 24, agent="example_agent")
    assert where == _BASE_WHERE + ["agent_name = {agent:String}"]
    assert params == {"pid": "p1", "hrs": 24, "agent": "example_agent"}


def test_scope_role_only() -> None:
    where, params = audit._scope("p1", 168, role="analyst")
    assert where == _BASE_WHERE + ["role = {role:String}"]
    assert params == {"pid": "p1", "hrs": 168, "role": "analyst"}


def test_scope_empty_role_filters_no_role_bucket() -> None:
    """role="" (the dashboard's "(none)" drill-down) must still emit the
    role clause — `if role:` instead of `if role is not None:` would
    silently widen the filter to every role."""
    where, params = audit._scope("p1", 24, role="")
    assert "role = {role:String}" in where
    assert params["role"] == ""


def test_scope_all_filters() -> None:
    where, params = audit._scope(
        "p1", 720, agent="example_agent", role="analyst", tool="read_file", user="Bob"
    )
    assert where == _BASE_WHERE + [
        "agent_name = {agent:String}",
        "role = {role:String}",
        "tool_name = {tool:String}",
        "user_id = {user:String}",
    ]
    assert params == {
        "pid": "p1",
        "hrs": 720,
        "agent": "example_agent",
        "role": "analyst",
        "tool": "read_file",
        "user": "Bob",
    }
    # Every dynamic value travels as a bound parameter, never spliced into
    # the SQL string — the injection-shape invariant for this module.
    assert all("{" in clause and ":" in clause for clause in where)


_START = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_END = datetime(2025, 1, 7, 23, 59, 59, tzinfo=timezone.utc)


def test_scope_appends_date_range_clause_when_both_dates_provided() -> None:
    where, params = audit._scope("p1", 24, start_date=_START, end_date=_END)

    expected_clauses = [
        "project_id = {pid:String}",
        "occurred_at >= {start_date:DateTime} AND occurred_at <= {end_date:DateTime}",
    ]

    assert where == expected_clauses
    assert params == {"pid": "p1", "start_date": _START, "end_date": _END}


def test_scope_falls_back_to_since_hours_when_one_date_missing() -> None:
    where_only_start, params = audit._scope("p1", 24, start_date=_START)
    assert where_only_start == _BASE_WHERE
    assert "start_date" not in params and "end_date" not in params

    where_only_end, params = audit._scope("p1", 24, end_date=_END)
    assert where_only_end == _BASE_WHERE
    assert "start_date" not in params and "end_date" not in params


def test_scope_falls_back_to_since_hours_when_start_date_is_after_end_date() -> None:
    where, params = audit._scope("p1", 24, start_date=_END, end_date=_START)
    assert where == _BASE_WHERE
    assert "start_date" not in params and "end_date" not in params


# ---------------------------------------------------------------------------
# bucket_minutes_for_timedelta() — granularity thresholds
# ---------------------------------------------------------------------------


def test_bucket_minutes_for_timedelta_thresholds() -> None:
    f = audit.bucket_minutes_for_timedelta
    assert f(timedelta(minutes=30)) == 1
    assert f(timedelta(hours=1)) == 5
    assert f(timedelta(hours=6)) == 15
    assert f(timedelta(hours=12)) == 30
    assert f(timedelta(hours=24)) == 60
    assert f(timedelta(days=7)) == 360
    assert f(timedelta(days=30)) == 1440
    assert f(timedelta(days=90)) == 1440


# ---------------------------------------------------------------------------
# timeseries() — bucket param derived from date range vs since_hours
# ---------------------------------------------------------------------------


def _timeseries_client() -> MagicMock:
    client = MagicMock()
    client.query.return_value.result_rows = []
    return client


def test_timeseries_bucket_uses_date_range_when_dates_provided() -> None:
    # _END - _START ≈ 7 days → 360-minute buckets
    client = _timeseries_client()
    audit.timeseries(
        client, project_id="p1", since_hours=24, start_date=_START, end_date=_END
    )
    assert client.query.call_args.kwargs["parameters"]["bucket"] == 360


def test_timeseries_bucket_uses_since_hours_when_no_dates() -> None:
    # since_hours=24 → 60-minute buckets
    client = _timeseries_client()
    audit.timeseries(client, project_id="p1", since_hours=24)
    assert client.query.call_args.kwargs["parameters"]["bucket"] == 60


# ---------------------------------------------------------------------------
# summarize() — GROUPING SETS row classification
# ---------------------------------------------------------------------------

# Rows are (agent, role, tool, outcome, g_agent, g_role, g_tool, g_outcome, n).
# GROUPING() flags: 1 = column rolled up. Only the () set rolls up outcome.


def _summary_result(rows: list[tuple]) -> MagicMock:
    client = MagicMock()
    client.query.return_value.result_rows = rows
    return client


def test_summarize_user_filter_reaches_query() -> None:
    client = _summary_result([])
    summarize(client, project_id="p1", since_hours=24, user="Bob")
    params = client.query.call_args.kwargs["parameters"]
    assert params.get("user") == "Bob"


def test_summarize_classifies_grouping_sets() -> None:
    client = _summary_result(
        [
            # agent_name, role, tool_name, user_id, outcome, g_agent, g_role, g_tool, g_user, g_outcome, n
            # () — grand total (the ONLY row where g_outcome=1)
            ("", "", "", "", "", 1, 1, 1, 1, 1, 10),
            # (outcome) — per-outcome totals
            ("", "", "", "", "allow", 1, 1, 1, 1, 0, 6),
            ("", "", "", "", "deny", 1, 1, 1, 1, 0, 4),
            # (agent_name, outcome)
            ("example_agent", "", "", "", "allow", 0, 1, 1, 1, 0, 6),
            ("example_agent", "", "", "", "deny", 0, 1, 1, 1, 0, 3),
            ("scraper", "", "", "", "deny", 0, 1, 1, 1, 0, 1),
            # (role, outcome) — empty role keeps its raw "" key on the wire
            ("", "analyst", "", "", "allow", 1, 0, 1, 1, 0, 6),
            ("", "", "", "", "deny", 1, 0, 1, 1, 0, 4),
            # (tool_name, outcome)
            ("", "", "read_file", "", "deny", 1, 1, 0, 1, 0, 4),
            # (user_id, outcome)
            ("", "", "", "Alice", "allow", 1, 1, 1, 0, 0, 6),
            ("", "", "", "Bob", "deny", 1, 1, 1, 0, 0, 4),
        ]
    )

    data = summarize(client, project_id="p1", since_hours=24)

    assert data["totals"] == {
        "all": 10,
        "allow": 6,
        "deny": 4,
        "needs_approval": 0,
    }
    # Breakdowns sorted by "all" desc; grand total must NOT leak into any.
    assert data["by_agent"] == [
        {"key": "example_agent", "all": 9, "allow": 6, "deny": 3, "needs_approval": 0},
        {"key": "scraper", "all": 1, "allow": 0, "deny": 1, "needs_approval": 0},
    ]
    assert data["by_role"] == [
        {"key": "analyst", "all": 6, "allow": 6, "deny": 0, "needs_approval": 0},
        {"key": "", "all": 4, "allow": 0, "deny": 4, "needs_approval": 0},
    ]
    assert data["by_tool"] == [
        {"key": "read_file", "all": 4, "allow": 0, "deny": 4, "needs_approval": 0},
    ]
    assert data["by_user"] == [
        {"key": "Alice", "all": 6, "allow": 6, "deny": 0, "needs_approval": 0},
        {"key": "Bob", "all": 4, "allow": 0, "deny": 4, "needs_approval": 0},
    ]


def test_summarize_empty_result() -> None:
    data = summarize(_summary_result([]), project_id="p1", since_hours=24)
    assert data == {
        "totals": {"all": 0, "allow": 0, "deny": 0, "needs_approval": 0},
        "by_agent": [],
        "by_role": [],
        "by_tool": [],
        "by_user": [],
    }


# ---------------------------------------------------------------------------
# list_decisions() — count() OVER () pagination contract
# ---------------------------------------------------------------------------

_LIST_COLUMN_NAMES = [c.strip() for c in audit._LIST_COLUMNS.split(",")] + [
    "total_matches"
]


def _decision_row(total: int, **overrides) -> tuple:
    base = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": _now(),
        "received_at": _now(),
        "agent_name": "example_agent",
        "agent_version_id": "v1",
        "session_id": "sess_1",
        "user_id": "u_1",
        "tool_name": "read_file",
        "role": "",
        "outcome": "deny",
        "error_type": "policy_denied",
        "reason": "",
        "violations": ["v1"],
        "hint": '{"globs": "/workspace/**"}',
        "arguments": "",
        "total_matches": total,
    }
    base.update(overrides)
    return tuple(base[c] for c in _LIST_COLUMN_NAMES)


def test_list_decisions_total_from_window_function() -> None:
    """An in-range page carries total via count() OVER () — one scan, no
    second count() query."""
    client = MagicMock()
    client.query.return_value.result_rows = [_decision_row(3), _decision_row(3)]
    client.query.return_value.column_names = _LIST_COLUMN_NAMES

    page = list_decisions(client, project_id="p1", since_hours=24, limit=2, offset=0)

    assert page["total"] == 3
    assert page["limit"] == 2 and page["offset"] == 0
    assert len(page["rows"]) == 2
    client.query.assert_called_once()
    # JSON columns decode; "" → None.
    assert page["rows"][0]["hint"] == {"globs": "/workspace/**"}
    assert page["rows"][0]["arguments"] is None
    assert "total_matches" not in page["rows"][0]


def test_list_decisions_past_end_page_falls_back_to_count() -> None:
    """A page past the end (offset > 0, zero rows) has no window value to
    read total from → the separate count() branch supplies it."""
    page_result = MagicMock()
    page_result.result_rows = []
    page_result.column_names = _LIST_COLUMN_NAMES
    count_result = MagicMock()
    count_result.result_rows = [[3]]
    client = MagicMock()
    client.query.side_effect = [page_result, count_result]

    page = list_decisions(client, project_id="p1", since_hours=24, limit=25, offset=75)

    assert page["rows"] == []
    assert page["total"] == 3
    assert client.query.call_count == 2
    assert "count()" in client.query.call_args_list[1].args[0]


def test_list_decisions_empty_first_page_skips_count() -> None:
    """offset=0 with no rows means a genuinely empty slice — total is 0
    and the fallback count() must not fire."""
    client = MagicMock()
    client.query.return_value.result_rows = []
    client.query.return_value.column_names = _LIST_COLUMN_NAMES

    page = list_decisions(client, project_id="p1", since_hours=24)

    assert page["total"] == 0 and page["rows"] == []
    client.query.assert_called_once()


# ---------------------------------------------------------------------------
# Dashboard read endpoints — require_org_member gating
# ---------------------------------------------------------------------------

# All four project-scoped reads share one trust envelope (require_org_member,
# same as the other dashboard reads); membership semantics (403 non-member,
# 404 unknown project) are covered against a real DB in test_auth.py.
_AUDIT_READ_PATHS = [
    "/v1/projects/proj_test/audit/summary",
    "/v1/projects/proj_test/audit/timeseries",
    "/v1/projects/proj_test/audit/decisions",
    "/v1/projects/proj_test/audit/anomalies",
]


@pytest.mark.parametrize("path", _AUDIT_READ_PATHS)
def test_audit_read_rejects_anonymous(
    client: TestClient, fake_clickhouse: MagicMock, path: str
) -> None:
    """No cookie / dev header → the require_org_member chain 401s before
    the handler runs, so ClickHouse is never queried."""
    r = client.get(path)
    assert r.status_code == 401
    fake_clickhouse.query.assert_not_called()


@pytest.mark.parametrize("path", _AUDIT_READ_PATHS)
def test_audit_read_allows_org_member(
    client: TestClient, fake_clickhouse: MagicMock, path: str
) -> None:
    """With membership satisfied, the same request reaches the handler —
    proving the 401 above comes from the auth gate, not the route."""
    app.dependency_overrides[require_org_member] = lambda: MagicMock()
    fake_clickhouse.query.return_value.result_rows = []
    r = client.get(path)
    assert r.status_code == 200, r.text


class _FakeAuthSession:
    """Just enough async-session surface for require_org_member: ``get``
    resolves the project, ``exec(...).first()`` resolves the membership."""

    def __init__(self, project, membership) -> None:
        self._project = project
        self._membership = membership

    async def get(self, _model, _pk):
        return self._project

    async def exec(self, _stmt):
        result = MagicMock()
        result.first.return_value = self._membership
        return result


def _login_as_stub_user(project, membership) -> None:
    """Authenticate as a stub user and point require_org_member's DB
    lookups at canned project/membership values."""
    app.dependency_overrides[require_user] = lambda: MagicMock()
    app.dependency_overrides[get_session] = lambda: _FakeAuthSession(
        project, membership
    )


@pytest.mark.parametrize("path", _AUDIT_READ_PATHS)
def test_audit_read_unknown_project_is_404(
    client: TestClient, fake_clickhouse: MagicMock, path: str
) -> None:
    """Authenticated but the project doesn't exist → 404, so project IDs
    can't be enumerated via 403-vs-404 differences."""
    _login_as_stub_user(project=None, membership=None)
    r = client.get(path)
    assert r.status_code == 404
    fake_clickhouse.query.assert_not_called()


@pytest.mark.parametrize("path", _AUDIT_READ_PATHS)
def test_audit_read_non_member_is_403(
    client: TestClient, fake_clickhouse: MagicMock, path: str
) -> None:
    """Authenticated, project exists, but the user isn't in its org → 403."""
    _login_as_stub_user(project=MagicMock(org_id="org_other"), membership=None)
    r = client.get(path)
    assert r.status_code == 403
    fake_clickhouse.query.assert_not_called()


def test_audit_read_empty_role_param_filters_no_role_bucket(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """``role=`` (empty value) must reach ClickHouse as ``role = ''`` —
    the no-role drill-down — while an absent ``role`` means no filter.
    No "(none)" sentinel exists on the wire."""
    app.dependency_overrides[require_org_member] = lambda: MagicMock()
    fake_clickhouse.query.return_value.result_rows = []

    r = client.get("/v1/projects/proj_test/audit/summary?role=")
    assert r.status_code == 200, r.text
    params = fake_clickhouse.query.call_args.kwargs["parameters"]
    assert params["role"] == ""

    fake_clickhouse.query.reset_mock()
    r = client.get("/v1/projects/proj_test/audit/summary")
    assert r.status_code == 200, r.text
    params = fake_clickhouse.query.call_args.kwargs["parameters"]
    assert "role" not in params


@pytest.mark.parametrize("path", _AUDIT_READ_PATHS)
def test_audit_read_member_is_200(
    client: TestClient, fake_clickhouse: MagicMock, path: str
) -> None:
    """Authenticated + membership row present → the real require_org_member
    passes and the handler answers."""
    _login_as_stub_user(project=MagicMock(org_id="org_1"), membership=MagicMock())
    fake_clickhouse.query.return_value.result_rows = []
    r = client.get(path)
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Health (liveness) vs readiness split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/v1/health"])
def test_liveness_does_not_ping_clickhouse(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    """Liveness must not touch ClickHouse, so an outage can't cascade into restarts."""

    def _fail() -> bool:
        raise AssertionError("liveness probe must not ping ClickHouse")

    monkeypatch.setattr("hexgate_api.main.clickhouse_ping", _fail)
    r = TestClient(app).get(path)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "clickhouse" not in r.json()


@pytest.mark.parametrize("path", ["/ready", "/v1/ready"])
def test_readiness_reports_clickhouse(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setattr("hexgate_api.health.clickhouse_ping", lambda: False)
    r = TestClient(app).get(path)
    assert r.status_code == 503
    assert r.json()["clickhouse"] == "unreachable"


# ---------------------------------------------------------------------------
# Integration — requires `make clickhouse-up` first; opt-in via marker
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_real_clickhouse_round_trip() -> None:
    """Insert through the real write path (``insert_decision`` with
    ``_DECISION_INSERT_SETTINGS``); SELECT it back; clean up."""
    from hexgate_api.features.audit.service import insert_decision
    from hexgate_api.core.clickhouse import get_clickhouse as real_get_clickhouse

    clickhouse_client = real_get_clickhouse()
    # The shared client is sessionless (autogenerate_session_id=False in
    # clickhouse.py) — a session would reject the concurrent queries the
    # dashboard reads + SDK ingest fire at the same pool.
    assert "session_id" not in clickhouse_client.params

    project_id = f"test_proj_{uuid.uuid4().hex[:8]}"
    event = DecisionEvent(
        **_event(
            session_id="sess_test",
            user_id="u_test",
            role="analyst",
            error_type="policy_denied",
            reason="integration test row",
            violations=["v1"],
            hint={"glob": "/workspace/**"},
            arguments={"path": "/etc/passwd"},
        )
    )
    event_id = event.event_id

    # wait_for_async_insert=1 (in _DECISION_INSERT_SETTINGS) blocks until the
    # flush — returning without raising IS the ack on the sessionless client.
    insert_decision(
        clickhouse_client,
        event=event,
        project_id=project_id,
        agent_version_id="9f1e3c5a-test",
    )

    try:
        rows = clickhouse_client.query(
            "SELECT event_id, project_id, outcome, received_at, agent_version_id "
            "FROM policy_decision WHERE project_id = {pid:String}",
            parameters={"pid": project_id},
        ).result_rows
        assert len(rows) == 1
        ev_id, pid, outcome, received_at, av_id = rows[0]
        assert str(ev_id) == str(event_id)
        assert pid == project_id
        assert outcome == "deny"
        assert received_at is not None  # server-stamped via column default
        assert av_id == "9f1e3c5a-test"
    finally:
        clickhouse_client.command(
            "ALTER TABLE policy_decision DELETE WHERE project_id = {pid:String}",
            parameters={"pid": project_id},
        )


# ---------------------------------------------------------------------------
# _prepare_date_range() — UTC normalization + 90-day retention clamping
# ---------------------------------------------------------------------------


def test_when_both_inputs_are_none_then_returns_none_none() -> None:
    start, end = prepare_date_range(None, None)
    assert start is None
    assert end is None


def test_when_naive_datetimes_provided_then_utc_is_attached() -> None:
    naive_start = datetime(2025, 1, 1, 0, 0, 0)
    naive_end = datetime(2025, 1, 7, 0, 0, 0)
    start, end = prepare_date_range(naive_start, naive_end)
    assert start.tzinfo == timezone.utc
    assert end.tzinfo == timezone.utc


def test_when_window_is_within_90d_then_start_date_is_unchanged() -> None:
    start, end = prepare_date_range(_START, _END)  # 7-day window
    assert start == _START
    assert end == _END


def test_when_window_exceeds_90d_then_start_date_is_clamped_to_end_minus_retention() -> (
    None
):
    far_start = datetime(2024, 9, 1, tzinfo=timezone.utc)  # >90d before _END
    start, _ = prepare_date_range(far_start, _END)
    assert start == _END - audit.RETENTION_WINDOW


def test_when_only_start_date_provided_then_no_clamping_occurs() -> None:
    start, end = prepare_date_range(_START, None)
    assert start == _START
    assert end is None


def test_when_start_date_is_after_end_date_then_no_clamping_occurs() -> None:
    # start > end: max(start, end - 90d) always returns start unchanged.
    # _date_range_valid handles the invalid pair downstream.
    start, end = prepare_date_range(_END, _START)
    assert start == _END
    assert end == _START


def test_when_end_date_is_in_the_future_then_end_date_is_clamped_to_now() -> None:
    future_end = datetime(2099, 12, 31, tzinfo=timezone.utc)
    _, end = prepare_date_range(None, future_end)
    assert end <= datetime.now(timezone.utc) + CLOCK_SKEW_FUTURE


# ---------------------------------------------------------------------------
# _sliding_window_anomalies() — pure sliding-window burst detector
# ---------------------------------------------------------------------------


class TestSlidingWindowAnomalies:
    BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    D = AuditOutcome.DENY
    A = AuditOutcome.ALLOW

    @staticmethod
    def rows(
        user: str,
        outcomes: list,
        *,
        gap_minutes: int = 5,
        base: datetime = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    ) -> list[tuple]:
        return [
            (user, base + timedelta(minutes=i * gap_minutes), outcome)
            for i, outcome in enumerate(outcomes)
        ]

    def test_when_rows_are_empty_then_returns_empty_list(self):
        assert _sliding_window_anomalies([]) == []

    def test_when_window_size_is_below_min_requests_then_no_anomaly(self):
        rows = self.rows("alice", [self.D, self.D, self.D, self.D])
        assert _sliding_window_anomalies(rows) == []

    def test_when_deny_rate_is_below_30_percent_then_no_anomaly(self):
        rows = self.rows("alice", [self.D, self.A, self.A, self.A, self.A])
        assert _sliding_window_anomalies(rows) == []

    def test_when_user_has_no_burst_then_no_emission_on_user_change(self):
        rows = self.rows("alice", [self.A] * 5) + self.rows("bob", [self.A] * 3)
        assert _sliding_window_anomalies(rows) == []

    def test_when_deny_rate_is_above_50_percent_then_severity_is_high(self):
        rows = self.rows("alice", [self.D] * 5)
        result = _sliding_window_anomalies(rows)
        assert len(result) == 1
        assert result[0].user_id == "alice"
        assert result[0].severity == AnomalySeverity.HIGH
        assert result[0].deny == 5
        assert result[0].all == 5
        assert result[0].deny_rate == pytest.approx(1.0)
        assert result[0].first_seen == self.BASE
        assert result[0].last_seen == self.BASE + timedelta(minutes=20)

    def test_when_deny_rate_is_between_30_and_50_percent_then_severity_is_medium(self):
        rows = self.rows("alice", [self.D, self.D, self.A, self.A, self.A])
        result = _sliding_window_anomalies(rows)
        assert len(result) == 1
        assert result[0].severity == AnomalySeverity.MEDIUM
        assert result[0].deny == 2
        assert result[0].all == 5

    def test_when_deny_rate_drops_below_threshold_then_anomaly_is_emitted(self):
        burst = self.rows("alice", [self.D] * 5, gap_minutes=2, base=self.BASE)
        cooldown = self.rows(
            "alice",
            [self.A] * 12,
            gap_minutes=2,
            base=self.BASE + timedelta(minutes=10),
        )
        result = _sliding_window_anomalies(burst + cooldown)
        assert len(result) == 1
        assert result[0].severity == AnomalySeverity.HIGH

    def test_when_deny_rate_increases_within_burst_then_peak_is_captured(self):
        # At event 5: 3/5 = 60%; at event 6: 4/6 ≈ 66.7% → best_burst updated
        burst = self.rows(
            "alice",
            [self.D, self.D, self.D, self.A, self.A, self.D],
            gap_minutes=5,
            base=self.BASE,
        )
        cooldown = self.rows(
            "alice",
            [self.A] * 12,
            gap_minutes=2,
            base=self.BASE + timedelta(minutes=30),
        )
        result = _sliding_window_anomalies(burst + cooldown)
        assert len(result) == 1
        assert result[0].deny_rate == pytest.approx(4 / 6)
        assert result[0].deny == 4
        assert result[0].all == 6

    def test_when_deny_rate_decreases_within_burst_then_peak_is_not_overwritten(self):
        # Peak at 5/5 = 100%; rate drops with allows but stays above threshold
        burst = self.rows("alice", [self.D] * 5, gap_minutes=5, base=self.BASE)
        dip = self.rows(
            "alice", [self.A] * 5, gap_minutes=5, base=self.BASE + timedelta(minutes=25)
        )
        cooldown = self.rows(
            "alice",
            [self.A] * 12,
            gap_minutes=2,
            base=self.BASE + timedelta(minutes=55),
        )
        result = _sliding_window_anomalies(burst + dip + cooldown)
        assert len(result) == 1
        assert result[0].deny_rate == pytest.approx(1.0)

    def test_when_deny_events_expire_from_window_then_burst_is_flushed(self):
        burst = self.rows("alice", [self.D] * 5, gap_minutes=5, base=self.BASE)
        late = [("alice", self.BASE + timedelta(hours=2), self.A)]
        result = _sliding_window_anomalies(burst + late)
        assert len(result) == 1
        assert result[0].deny == 5

    def test_when_allow_events_expire_from_window_then_deny_count_is_unchanged(self):
        early = self.rows(
            "alice",
            [self.A, self.A, self.A, self.A, self.D, self.D, self.D, self.D, self.D],
            gap_minutes=5,
            base=self.BASE,
        )
        late = [("alice", self.BASE + timedelta(hours=2), self.D)]
        result = _sliding_window_anomalies(early + late)
        assert len(result) == 1
        assert result[0].severity == AnomalySeverity.HIGH

    def test_when_two_bursts_are_separated_by_gap_then_two_anomalies_are_emitted(self):
        burst1 = self.rows("alice", [self.D] * 5, gap_minutes=5, base=self.BASE)
        bridge = [("alice", self.BASE + timedelta(hours=2), self.A)]
        burst2 = self.rows(
            "alice",
            [self.D] * 5,
            gap_minutes=5,
            base=self.BASE + timedelta(hours=2, minutes=10),
        )
        result = _sliding_window_anomalies(burst1 + bridge + burst2)
        assert len(result) == 2
        assert all(r.user_id == "alice" for r in result)
        assert all(r.severity == AnomalySeverity.HIGH for r in result)
        assert result[1].first_seen > result[0].last_seen

    def test_when_burst_ends_by_eviction_and_boundary_event_is_deny_then_it_seeds_next_burst(
        self,
    ):
        # Burst 1: 5 denies. 2 hours pass — eviction clears the entire window.
        # The next event is a DENY: window_length=1, below threshold, so the burst
        # is flushed. That DENY must be re-seeded into the cleared window so it
        # contributes curr_deny=1 toward a second burst. Without re-seeding, the
        # following 4 DENYs reach only window_length=4 and no second anomaly fires.
        burst1 = self.rows("alice", [self.D] * 5, gap_minutes=5, base=self.BASE)
        seed_deny = [("alice", self.BASE + timedelta(hours=2), self.D)]
        burst2 = self.rows(
            "alice",
            [self.D] * 4,
            gap_minutes=5,
            base=self.BASE + timedelta(hours=2, minutes=5),
        )
        result = _sliding_window_anomalies(burst1 + seed_deny + burst2)
        assert len(result) == 2
        assert result[1].deny == 5
        assert result[1].all == 5

    def test_when_burst_ends_by_rate_drop_then_live_window_events_are_discarded(self):
        # Burst 1: 5 denies then 12 allows drop the rate below threshold at
        # T+32min. All 17 events are still inside the 1-hour window when the
        # flush fires, but they belong to neither burst and must be discarded.
        # Without discarding them, those allows inflate the denominator of the
        # next burst and suppress its deny rate, masking the second anomaly.
        burst1 = self.rows("alice", [self.D] * 5, gap_minutes=2, base=self.BASE)
        cooldown = self.rows(
            "alice",
            [self.A] * 12,
            gap_minutes=2,
            base=self.BASE + timedelta(minutes=10),
        )
        burst2 = self.rows(
            "alice",
            [self.D] * 5,
            gap_minutes=2,
            base=self.BASE + timedelta(minutes=34),
        )
        result = _sliding_window_anomalies(burst1 + cooldown + burst2)
        assert len(result) == 2
        assert result[1].deny == 5
        assert result[1].all == 5

    def test_when_window_slides_at_constant_rate_then_last_seen_advances(self):
        # 5 DENYs at T+0..T+20 hit threshold (rate=1.0, all=5). Then 4 more
        # DENYs at T+65..T+80 — each evicts one old DENY, keeping rate=1.0
        # and all=5. With strict >, best_burst would never update and last_seen
        # would freeze at T+20. With >=, each new candidate replaces the old
        # one and last_seen advances to T+80.
        burst = self.rows("alice", [self.D] * 5, gap_minutes=5, base=self.BASE)
        slide = self.rows(
            "alice",
            [self.D] * 4,
            gap_minutes=5,
            base=self.BASE + timedelta(minutes=65),
        )
        result = _sliding_window_anomalies(burst + slide)
        assert len(result) == 1
        assert result[0].last_seen == self.BASE + timedelta(minutes=80)

    def test_when_multiple_users_each_have_bursts_then_one_anomaly_per_user(self):
        rows = self.rows("alice", [self.D] * 5, base=self.BASE) + self.rows(
            "bob", [self.D, self.D, self.A, self.A, self.A], base=self.BASE
        )
        result = _sliding_window_anomalies(rows)
        assert len(result) == 2
        by_user = {r.user_id: r for r in result}
        assert by_user["alice"].severity == AnomalySeverity.HIGH
        assert by_user["bob"].severity == AnomalySeverity.MEDIUM

    def test_when_user_changes_with_active_burst_then_burst_is_flushed(self):
        rows = self.rows("alice", [self.D] * 5, base=self.BASE) + self.rows(
            "bob", [self.A] * 3, base=self.BASE
        )
        result = _sliding_window_anomalies(rows)
        assert len(result) == 1
        assert result[0].user_id == "alice"


# ---------------------------------------------------------------------------
# anomalies() — two-pass ClickHouse wiring
# ---------------------------------------------------------------------------


class TestAnomalies:
    BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    @staticmethod
    def _client(
        qualifying_rows: list[tuple],
        decision_rows: list[tuple],
    ) -> MagicMock:
        pass1, pass2 = MagicMock(), MagicMock()
        pass1.result_rows = qualifying_rows
        pass2.result_rows = decision_rows
        client = MagicMock()
        client.query.side_effect = [pass1, pass2]
        return client

    @staticmethod
    def _burst(
        user: str,
        n: int = 5,
        base: datetime = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    ) -> list[tuple]:
        return [
            (user, base + timedelta(minutes=i * 5), AuditOutcome.DENY) for i in range(n)
        ]

    def test_when_no_qualifying_users_then_returns_empty_list_and_skips_second_query(
        self,
    ):
        client = MagicMock()
        client.query.return_value.result_rows = []
        result = audit.anomalies(client, project_id="p1", since_hours=24)
        assert result == []
        client.query.assert_called_once()

    def test_when_qualifying_users_exist_then_anomalies_are_returned(self):
        client = self._client(
            qualifying_rows=[("bob",)],
            decision_rows=self._burst("bob"),
        )
        result = audit.anomalies(client, project_id="p1", since_hours=24)
        assert len(result) == 1
        assert result[0].user_id == "bob"
        assert result[0].severity == AnomalySeverity.HIGH
        assert client.query.call_count == 2

    def test_pure_deny_burst_reports_full_window_size(self):
        # 20 denies all within 1 minute — all at 100% deny rate.  The best_burst
        # must grow with each event (tie-break by window size), not freeze at
        # the first qualifying window of 5.
        base = self.BASE
        rows = [
            ("bob", base + timedelta(seconds=i * 3), AuditOutcome.DENY)
            for i in range(20)
        ]
        client = self._client(qualifying_rows=[("bob",)], decision_rows=rows)
        result = audit.anomalies(client, project_id="p1", since_hours=24)
        assert len(result) == 1
        assert result[0].deny == 20
        assert result[0].all == 20


def test_audit_anomalies_clickhouse_error_returns_503(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    app.dependency_overrides[require_org_member] = lambda: MagicMock()
    fake_clickhouse.query.side_effect = ClickHouseError("unavailable")
    r = client.get("/v1/projects/proj_test/audit/anomalies")
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"]
