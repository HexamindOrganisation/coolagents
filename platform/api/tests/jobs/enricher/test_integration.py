"""End-to-end _process_poll against a real local ClickHouse.

Real protobuf decode, real batch inserts, fake Kafka clients — the broker
round-trip belongs to the staging wire-up. Opt-in via `pytest -m integration`
(`make platform-api-test-integration`).
"""

from __future__ import annotations

import uuid

import pytest

from hexgate.tracing import semconv
from hexgate_api.jobs.enricher.consumer import EnricherJob
from hexgate_api.settings import Settings
from tests.jobs.enricher.conftest import (
    FakeConsumer,
    FakeProducer,
    FakeRecord,
    ban_attrs,
    decision_attrs,
    make_request_bytes,
    make_span,
    usage_attrs,
)

_TABLES = ("policy_decision", "llm_invocation", "ban_enforcement")


def _count(client, table: str, project_id: str) -> int:
    return client.query(
        f"SELECT count() FROM {table} FINAL WHERE project_id = {{pid:String}}",
        parameters={"pid": project_id},
    ).result_rows[0][0]


@pytest.mark.integration
async def test_process_poll_round_trip_and_reprocess_dedup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hexgate_api.core.clickhouse import get_clickhouse

    client = get_clickhouse()
    project_id = f"test_proj_{uuid.uuid4().hex[:8]}"

    async def _stub_resolve(pairs):
        return {pair: "ver_int" for pair in pairs}

    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.resolve_versions", _stub_resolve
    )
    calls: list[str] = []
    job = EnricherJob(
        Settings(enricher_insert_max_backoff_s=0.01),
        clickhouse_client=client,
        consumer=FakeConsumer(calls),
        producer=FakeProducer(calls),
    )
    records = [
        FakeRecord(
            key=project_id.encode(),
            value=make_request_bytes(
                [
                    (semconv.SCOPE_AUDIT, [make_span(decision_attrs())]),
                    (semconv.SCOPE_USAGE, [make_span(usage_attrs())]),
                    (semconv.SCOPE_BANS, [make_span(ban_attrs())]),
                ]
            ),
        )
    ]
    try:
        await job._process_poll(records)
        assert [_count(client, t, project_id) for t in _TABLES] == [1, 1, 1]

        # Reprocessing the same records (crash-before-commit replay) must not
        # double-count: event_id dedup via ReplacingMergeTree, FINAL applies
        # merge semantics at read time.
        await job._process_poll(records)
        assert [_count(client, t, project_id) for t in _TABLES] == [1, 1, 1]
    finally:
        for table in _TABLES:
            client.command(
                f"ALTER TABLE {table} DELETE WHERE project_id = {{pid:String}}",
                parameters={"pid": project_id},
            )
