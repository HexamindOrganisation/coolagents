"""Tests for the LlmInvocationEvent Pydantic model and the ingest endpoint."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from clickhouse_connect.driver.exceptions import DataError, OperationalError
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.core.clickhouse import SchemaOutOfDate
from hexgate_api.core.db import get_session
from hexgate_api.core.keystore import FileKeyStore
from hexgate_api.deps.clickhouse import require_clickhouse
from hexgate_api.deps.org import require_org_member
from hexgate_api.deps.tokens import require_project
from hexgate_api.features.llm_invocations import service as llm_invocations
from hexgate_api.features.llm_invocations.service import summarize_llm_invocations
from hexgate_api.core.clickhouse import BatchItem
from hexgate_api.main import app
from hexgate_api.schemas import LlmInvocationEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _llm_event(**overrides) -> dict:
    """Return a minimal-required event payload, with optional overrides."""
    base = {
        "event_id": str(uuid.uuid4()),
        "occurred_at": _now().isoformat(),
        "agent_name": "researcher",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 5,
        "latency_ms": 100,
    }
    return {**base, **overrides}


# ---------------------------------------------------------------------------
# Pydantic schema validation
# ---------------------------------------------------------------------------


def test_insert_llm_invocations_batch_happy_path() -> None:
    """N per-item-resolved events become ONE insert call carrying N rows;
    project_id/agent_version_id stay per item (a consumer batch can span
    projects). See the audit tests for the shared batch-insert contract."""
    from hexgate_api.features.llm_invocations.service import (
        _LLM_INVOCATION_COLUMNS,
        insert_llm_invocations_batch,
    )

    clickhouse_client = MagicMock()
    items = [
        BatchItem(
            LlmInvocationEvent(**_llm_event()),
            project_id=f"proj_{i}",
            agent_version_id=f"ver_{i}",
        )
        for i in range(3)
    ]

    insert_llm_invocations_batch(clickhouse_client, items)

    clickhouse_client.insert.assert_called_once()
    args, kwargs = clickhouse_client.insert.call_args
    assert args[0] == "llm_invocation"
    rows = args[1]
    assert len(rows) == 3
    assert kwargs["column_names"] == _LLM_INVOCATION_COLUMNS
    # No async_insert on the batch path (pinned to 0) — see the audit batch tests.
    assert kwargs["settings"] == {"async_insert": 0}
    project_index = _LLM_INVOCATION_COLUMNS.index("project_id")
    assert [row[project_index] for row in rows] == ["proj_0", "proj_1", "proj_2"]


def test_when_the_batch_is_empty_then_clickhouse_is_not_called() -> None:
    from hexgate_api.features.llm_invocations.service import (
        insert_llm_invocations_batch,
    )

    clickhouse_client = MagicMock()

    insert_llm_invocations_batch(clickhouse_client, [])

    clickhouse_client.insert.assert_not_called()


def test_when_an_event_is_batched_then_its_row_matches_the_single_insert() -> None:
    """Single-row and batch paths share the row builder; identical input must
    produce identical rows so the two cannot drift."""
    from hexgate_api.features.llm_invocations.service import (
        insert_llm_invocation,
        insert_llm_invocations_batch,
    )

    event = LlmInvocationEvent(**_llm_event())
    single, batch = MagicMock(), MagicMock()

    insert_llm_invocation(single, event=event, project_id="p", agent_version_id="v")
    insert_llm_invocations_batch(
        batch, [BatchItem(event, project_id="p", agent_version_id="v")]
    )

    assert batch.insert.call_args.args[1][0] == single.insert.call_args.args[1][0]


def test_when_payload_is_minimal_then_defaults_are_applied() -> None:
    e = LlmInvocationEvent(**_llm_event())
    # Envelope defaults (agent_version_id is server-resolved, not in the wire model)
    assert e.session_id == ""
    assert e.user_id == ""
    # LLM-invocation-detail defaults
    assert e.status == "success"
    assert e.error_code == ""


def test_when_event_is_constructed_then_envelope_fields_are_inherited_and_server_resolved_fields_are_excluded() -> (
    None
):
    """LlmInvocationEvent inherits the wire envelope; server-resolved fields stay out."""
    expected = {"event_id", "occurred_at", "agent_name", "session_id", "user_id"}
    assert expected <= LlmInvocationEvent.model_fields.keys()
    assert "project_id" not in LlmInvocationEvent.model_fields
    assert "received_at" not in LlmInvocationEvent.model_fields
    assert "agent_version_id" not in LlmInvocationEvent.model_fields


@pytest.mark.parametrize("field", ["input_tokens", "output_tokens", "latency_ms"])
def test_when_field_is_negative_then_validation_error_is_raised(field: str) -> None:
    with pytest.raises(ValidationError) as exc:
        LlmInvocationEvent(**_llm_event(**{field: -1}))
    assert field in str(exc.value)


@pytest.mark.parametrize(
    "field", ["model", "input_tokens", "output_tokens", "latency_ms"]
)
def test_when_required_field_is_missing_then_validation_error_is_raised(
    field: str,
) -> None:
    payload = _llm_event()
    payload.pop(field)
    with pytest.raises(ValidationError) as exc:
        LlmInvocationEvent(**payload)
    assert field in str(exc.value)


def test_when_model_exceeds_max_length_then_validation_error_is_raised() -> None:
    with pytest.raises(ValidationError) as exc:
        LlmInvocationEvent(**_llm_event(model="x" * 300))
    assert "model" in str(exc.value)


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
        "hexgate_api.features.llm_invocations.router.get_latest_agent_version_id",
        _stub_version_lookup,
    )
    # The /llm/summary gating tests run the real require_org_member chain,
    # whose cookie transport needs an initialised keystore (same swap as the
    # client fixture in test_audit.py).
    original_keystore = keystore_mod.keystore
    keystore_mod.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    keystore_mod.keystore.ensure_keypair()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        keystore_mod.keystore = original_keystore


def test_ingest_llm_invocation_happy_path(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    payload = _llm_event()
    r = client.post("/v1/audit/llm-invocations", json=payload)

    assert r.status_code == 202, r.text
    assert r.json() == {"event_id": payload["event_id"]}

    fake_clickhouse.insert.assert_called_once()
    args, kwargs = fake_clickhouse.insert.call_args
    assert args[0] == "llm_invocation"
    rows = args[1]
    assert len(rows) == 1
    assert len(rows[0]) == 13
    # Indices match _LLM_INVOCATION_COLUMNS in service.py.
    assert rows[0][2] == "proj_test"  # project_id (bearer)
    assert rows[0][4] == _STUB_AGENT_VERSION_ID  # agent_version_id (platform)
    assert kwargs["column_names"] == llm_invocations._LLM_INVOCATION_COLUMNS
    assert kwargs["settings"]["async_insert"] == 1
    # Durable: block until flush so insert failures surface synchronously.
    assert kwargs["settings"]["wait_for_async_insert"] == 1


def test_when_occurred_at_is_in_the_future_then_400_is_returned(
    client: TestClient,
) -> None:
    far_future = (_now() + timedelta(minutes=10)).isoformat()
    r = client.post(
        "/v1/audit/llm-invocations", json=_llm_event(occurred_at=far_future)
    )
    assert r.status_code == 400
    assert "future" in r.json()["detail"]


def test_when_occurred_at_is_too_old_then_400_is_returned(client: TestClient) -> None:
    too_old = (_now() - timedelta(days=91)).isoformat()
    r = client.post("/v1/audit/llm-invocations", json=_llm_event(occurred_at=too_old))
    assert r.status_code == 400
    assert "retention" in r.json()["detail"]


def test_when_payload_fails_pydantic_validation_then_422_is_returned(
    client: TestClient,
) -> None:
    """A non-numeric input_tokens trips FastAPI's request validation before the handler runs."""
    r = client.post(
        "/v1/audit/llm-invocations", json=_llm_event(input_tokens="not-a-number")
    )
    assert r.status_code == 422


def test_when_clickhouse_insert_fails_transiently_then_503_is_returned(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """A transport/transient failure is retryable → 503 Retry-After."""
    fake_clickhouse.insert.side_effect = OperationalError("connection refused")
    r = client.post("/v1/audit/llm-invocations", json=_llm_event())
    assert r.status_code == 503
    assert r.headers.get("retry-after") == "5"
    assert "unavailable" in r.json()["detail"]


def test_when_clickhouse_rejects_the_row_then_422_is_returned(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """A storage rejection (bad type/value) is permanent → 422, not a retryable 503."""
    fake_clickhouse.insert.side_effect = DataError("unknown enum value")
    r = client.post("/v1/audit/llm-invocations", json=_llm_event())
    assert r.status_code == 422
    assert "retry-after" not in {k.lower() for k in r.headers}
    assert "rejected" in r.json()["detail"]


# ---------------------------------------------------------------------------
# _scope() — llm_invocation's own filters layered on the shared scope_filters
# ---------------------------------------------------------------------------

_BASE_WHERE = [
    "project_id = {pid:String}",
    "occurred_at >= {since:DateTime}",
]


# The window is a wall-clock instant, so compare the bag without it.
def _params_besides_window(params: dict) -> dict:
    assert "since" in params
    return {k: v for k, v in params.items() if k != "since"}


def test_scope_no_filters() -> None:
    where, params = llm_invocations._scope("p1", 24)
    assert where == _BASE_WHERE
    assert _params_besides_window(params) == {"pid": "p1"}


def test_scope_all_filters() -> None:
    where, params = llm_invocations._scope(
        "p1", 24, agent="researcher", user="u_1", model="gpt-4o"
    )
    assert where == _BASE_WHERE + [
        "agent_name = {agent:String}",
        "user_id = {user:String}",
        "model = {model:String}",
    ]
    assert _params_besides_window(params) == {
        "pid": "p1",
        "agent": "researcher",
        "user": "u_1",
        "model": "gpt-4o",
    }


def test_scope_empty_user_filters_no_user_bucket() -> None:
    """user="" (no-user drill-down) must still emit the filter clause —
    `if user:` instead of `if user is not None:` would silently widen it."""
    where, params = llm_invocations._scope("p1", 24, user="")
    assert "user_id = {user:String}" in where
    assert params["user"] == ""


# ---------------------------------------------------------------------------
# summarize_llm_invocations() — GROUPING SETS row classification
# ---------------------------------------------------------------------------

# Rows are (model, agent_name, user_id, g_model, g_agent, g_user, calls,
# input_tokens, output_tokens). GROUPING() flags: 1 = column rolled up.
# Only the () set rolls up every dimension.


def _summary_result(rows: list[tuple]) -> MagicMock:
    client = MagicMock()
    client.query.return_value.result_rows = rows
    return client


def test_summarize_filters_reach_query() -> None:
    client = _summary_result([])
    summarize_llm_invocations(
        client,
        project_id="p1",
        since_hours=24,
        agent="researcher",
        user="u_1",
        model="gpt-4o",
    )
    params = client.query.call_args.kwargs["parameters"]
    assert params["agent"] == "researcher"
    assert params["user"] == "u_1"
    assert params["model"] == "gpt-4o"


def test_summarize_classifies_grouping_sets() -> None:
    client = _summary_result(
        [
            # () — grand total (the ONLY row where every grouping flag is 1)
            ("", "", "", 1, 1, 1, 10, 1000, 400),
            # (model)
            ("gpt-4o", "", "", 0, 1, 1, 7, 700, 300),
            ("gpt-4o-mini", "", "", 0, 1, 1, 3, 300, 100),
            # (agent_name)
            ("", "researcher", "", 1, 0, 1, 6, 600, 250),
            ("", "scraper", "", 1, 0, 1, 4, 400, 150),
            # (user_id) — empty user_id keeps its raw "" key on the wire
            ("", "", "Alice", 1, 1, 0, 6, 600, 250),
            ("", "", "Bob", 1, 1, 0, 4, 400, 150),
        ]
    )

    data = summarize_llm_invocations(client, project_id="p1", since_hours=24)

    assert data["totals"] == {
        "calls": 10,
        "input_tokens": 1000,
        "output_tokens": 400,
        "total_tokens": 1400,
    }
    assert data["by_model"] == [
        {
            "key": "gpt-4o",
            "calls": 7,
            "input_tokens": 700,
            "output_tokens": 300,
            "total_tokens": 1000,
        },
        {
            "key": "gpt-4o-mini",
            "calls": 3,
            "input_tokens": 300,
            "output_tokens": 100,
            "total_tokens": 400,
        },
    ]
    assert data["by_agent"] == [
        {
            "key": "researcher",
            "calls": 6,
            "input_tokens": 600,
            "output_tokens": 250,
            "total_tokens": 850,
        },
        {
            "key": "scraper",
            "calls": 4,
            "input_tokens": 400,
            "output_tokens": 150,
            "total_tokens": 550,
        },
    ]
    assert data["by_user"] == [
        {
            "key": "Alice",
            "calls": 6,
            "input_tokens": 600,
            "output_tokens": 250,
            "total_tokens": 850,
        },
        {
            "key": "Bob",
            "calls": 4,
            "input_tokens": 400,
            "output_tokens": 150,
            "total_tokens": 550,
        },
    ]


def test_summarize_empty_result() -> None:
    data = summarize_llm_invocations(
        _summary_result([]), project_id="p1", since_hours=24
    )
    assert data == {
        "totals": {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
        "by_model": [],
        "by_agent": [],
        "by_user": [],
    }


# ---------------------------------------------------------------------------
# GET /v1/projects/{project_id}/llm/summary — require_org_member gating
# ---------------------------------------------------------------------------


def test_llm_summary_rejects_anonymous(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """No cookie / dev header → the require_org_member chain 401s before
    the handler runs, so ClickHouse is never queried."""
    r = client.get("/v1/projects/proj_test/llm/summary")
    assert r.status_code == 401
    fake_clickhouse.query.assert_not_called()


def test_llm_summary_allows_org_member(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    """With membership satisfied, the same request reaches the handler —
    proving the 401 above comes from the auth gate, not the route."""
    app.dependency_overrides[require_org_member] = lambda: MagicMock()
    fake_clickhouse.query.return_value.result_rows = []
    r = client.get("/v1/projects/proj_test/llm/summary")
    assert r.status_code == 200, r.text
    assert r.json() == {
        "totals": {
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
        "by_model": [],
        "by_agent": [],
        "by_user": [],
    }


def test_llm_summary_passes_filters_to_clickhouse_query(
    client: TestClient, fake_clickhouse: MagicMock
) -> None:
    app.dependency_overrides[require_org_member] = lambda: MagicMock()
    fake_clickhouse.query.return_value.result_rows = []
    r = client.get(
        "/v1/projects/proj_test/llm/summary",
        params={
            "window": "7d",
            "agent": "researcher",
            "user": "u_1",
            "model": "gpt-4o",
        },
    )
    assert r.status_code == 200, r.text
    params = fake_clickhouse.query.call_args.kwargs["parameters"]
    assert params["agent"] == "researcher"
    assert params["user"] == "u_1"
    assert params["model"] == "gpt-4o"
    # window=7d arrives as a bound cutoff, not an hour count.
    expected_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    assert abs(params["since"] - expected_cutoff) < timedelta(seconds=5)


# ---------------------------------------------------------------------------
# Integration — requires `make clickhouse-up` first; opt-in via marker
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_real_clickhouse_round_trip() -> None:
    """Insert through the real write path (``insert_llm_invocation`` with
    ``_LLM_INVOCATION_INSERT_SETTINGS``); SELECT it back; clean up.

    This also proves the ``llm_invocation`` table actually exists on
    whatever ClickHouse this runs against — a missing table fails the
    insert with UNKNOWN_TABLE rather than the assertions below.
    """
    from hexgate_api.core.clickhouse import get_clickhouse as real_get_clickhouse

    clickhouse_client = real_get_clickhouse()
    # The shared client is sessionless (autogenerate_session_id=False in
    # clickhouse.py) — a session would reject the concurrent queries the
    # dashboard reads + SDK ingest fire at the same pool.
    assert "session_id" not in clickhouse_client.params

    project_id = f"test_proj_{uuid.uuid4().hex[:8]}"
    event = LlmInvocationEvent(
        **_llm_event(
            session_id="sess_test",
            user_id="u_test",
            model="gpt-4o-2024-08-06",
            input_tokens=123,
            output_tokens=45,
            latency_ms=987,
        )
    )
    event_id = event.event_id

    # wait_for_async_insert=1 (in _LLM_INVOCATION_INSERT_SETTINGS) blocks until
    # the flush — returning without raising IS the ack on the sessionless client.
    llm_invocations.insert_llm_invocation(
        clickhouse_client,
        event=event,
        project_id=project_id,
        agent_version_id="9f1e3c5a-test",
    )

    try:
        rows = clickhouse_client.query(
            "SELECT event_id, project_id, model, input_tokens, output_tokens, "
            "received_at, agent_version_id FROM llm_invocation "
            "WHERE project_id = {pid:String}",
            parameters={"pid": project_id},
        ).result_rows
        assert len(rows) == 1
        ev_id, pid, model, input_tokens, output_tokens, received_at, av_id = rows[0]
        assert str(ev_id) == str(event_id)
        assert pid == project_id
        assert model == "gpt-4o-2024-08-06"
        assert input_tokens == 123
        assert output_tokens == 45
        assert received_at is not None  # server-stamped via column default
        assert av_id == "9f1e3c5a-test"
    finally:
        clickhouse_client.command(
            "ALTER TABLE llm_invocation DELETE WHERE project_id = {pid:String}",
            parameters={"pid": project_id},
        )


@pytest.mark.integration
def test_summarize_llm_invocations_happy_path() -> None:
    """Insert a handful of rows through the real write path, then exercise the
    actual GROUPING SETS SQL (never run against real ClickHouse anywhere else)
    to confirm it's valid ClickHouse syntax and classifies rows correctly."""
    from hexgate_api.core.clickhouse import get_clickhouse as real_get_clickhouse

    clickhouse_client = real_get_clickhouse()
    project_id = f"test_proj_{uuid.uuid4().hex[:8]}"

    # Distinct totals per bucket so sort order (desc by total_tokens) is
    # unambiguous — no two rows in the same breakdown should tie.
    rows = [
        _llm_event(
            agent_name="researcher",
            model="gpt-4o",
            user_id="alice",
            input_tokens=100,
            output_tokens=50,
        ),
        _llm_event(
            agent_name="researcher",
            model="gpt-4o",
            user_id="bob",
            input_tokens=200,
            output_tokens=100,
        ),
        _llm_event(
            agent_name="scraper",
            model="gpt-4o-mini",
            user_id="alice",
            input_tokens=50,
            output_tokens=25,
        ),
    ]
    for payload in rows:
        llm_invocations.insert_llm_invocation(
            clickhouse_client,
            event=LlmInvocationEvent(**payload),
            project_id=project_id,
            agent_version_id="9f1e3c5a-test",
        )

    try:
        data = summarize_llm_invocations(
            clickhouse_client, project_id=project_id, since_hours=24
        )
        assert data["totals"] == {
            "calls": 3,
            "input_tokens": 350,
            "output_tokens": 175,
            "total_tokens": 525,
        }
        assert data["by_model"] == [
            {
                "key": "gpt-4o",
                "calls": 2,
                "input_tokens": 300,
                "output_tokens": 150,
                "total_tokens": 450,
            },
            {
                "key": "gpt-4o-mini",
                "calls": 1,
                "input_tokens": 50,
                "output_tokens": 25,
                "total_tokens": 75,
            },
        ]
        assert data["by_agent"] == [
            {
                "key": "researcher",
                "calls": 2,
                "input_tokens": 300,
                "output_tokens": 150,
                "total_tokens": 450,
            },
            {
                "key": "scraper",
                "calls": 1,
                "input_tokens": 50,
                "output_tokens": 25,
                "total_tokens": 75,
            },
        ]
        assert data["by_user"] == [
            {
                "key": "bob",
                "calls": 1,
                "input_tokens": 200,
                "output_tokens": 100,
                "total_tokens": 300,
            },
            {
                "key": "alice",
                "calls": 2,
                "input_tokens": 150,
                "output_tokens": 75,
                "total_tokens": 225,
            },
        ]
    finally:
        clickhouse_client.command(
            "ALTER TABLE llm_invocation DELETE WHERE project_id = {pid:String}",
            parameters={"pid": project_id},
        )


# ---------------------------------------------------------------------------
# verify_schema() — this feature's slice of the startup guard
# ---------------------------------------------------------------------------


def _describing(columns: list[str]) -> MagicMock:
    """A client whose DESCRIBE returns the given columns for llm_invocation."""
    client = MagicMock()
    result = MagicMock()
    result.column_names = ["name", "type"]
    result.result_rows = [[c, "String"] for c in columns]
    client.query.return_value = result
    return client


def test_verify_schema_passes_on_a_current_schema() -> None:
    columns = list(llm_invocations._LLM_INVOCATION_COLUMNS)
    llm_invocations.verify_schema(_describing(columns))  # no raise


def test_when_a_written_column_is_missing_then_verify_schema_raises() -> None:
    """The gap this closes: llm_invocation was never in the startup check, so a
    stale volume surfaced as runtime insert failures instead of a boot error."""
    columns = [
        c for c in llm_invocations._LLM_INVOCATION_COLUMNS if c != "input_tokens"
    ]
    with pytest.raises(SchemaOutOfDate) as exc:
        llm_invocations.verify_schema(_describing(columns))
    assert exc.value.missing == {"llm_invocation": ["input_tokens"]}
