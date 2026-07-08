"""Tests for the LlmInvocationEvent Pydantic model and the ingest endpoint."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from clickhouse_connect.driver.exceptions import DataError, OperationalError
from fastapi.testclient import TestClient
from pydantic import ValidationError

from hexgate_api.core.db import get_session
from hexgate_api.deps.clickhouse import require_clickhouse
from hexgate_api.deps.tokens import require_project
from hexgate_api.features.llm_invocations import service as llm_invocations
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
def client(fake_clickhouse: MagicMock, monkeypatch: pytest.MonkeyPatch) -> TestClient:
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
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


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
