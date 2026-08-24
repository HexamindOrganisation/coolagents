"""consumer.py — one _process_poll cycle driven with fakes.

The ordering contract under test: inserts → DLQ sends → offset commit.
"""

from __future__ import annotations

import json

from clickhouse_connect.driver.exceptions import OperationalError

from hexgate.tracing import semconv
from tests.jobs.enricher.conftest import (
    FakeRecord,
    ban_attrs,
    decision_attrs,
    make_request_bytes,
    make_span,
    usage_attrs,
)


def _record(groups, key: bytes | None = b"proj_1", offset: int = 0) -> FakeRecord:
    return FakeRecord(key=key, value=make_request_bytes(groups), offset=offset)


async def test_process_poll_happy_path_inserts_then_commits(make_job) -> None:
    """All three event types in one poll → three batch inserts, no DLQ,
    one commit, strictly after the inserts."""
    job, clickhouse, consumer, producer, calls = make_job()
    records = [
        _record(
            [
                (semconv.SCOPE_AUDIT, [make_span(decision_attrs())]),
                (semconv.SCOPE_USAGE, [make_span(usage_attrs())]),
                (semconv.SCOPE_BANS, [make_span(ban_attrs())]),
            ]
        )
    ]

    await job._process_poll(records)

    assert calls == ["insert", "insert", "insert", "commit"]
    tables = [c.args[0] for c in clickhouse.insert.call_args_list]
    assert tables == ["policy_decision", "llm_invocation", "ban_enforcement"]
    assert producer.sent == []
    # project_id from the record key, agent_version_id from the resolver.
    decision_rows = clickhouse.insert.call_args_list[0].args[1]
    assert decision_rows[0][2] == "proj_1"
    assert decision_rows[0][4] == "ver_researcher"


async def test_when_an_insert_fails_then_whole_batch_retried_and_committed_once(
    make_job,
) -> None:
    job, clickhouse, consumer, producer, calls = make_job(
        insert_side_effect=[OperationalError("clickhouse briefly down")]
    )
    records = [_record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])])]

    await job._process_poll(records)

    # First attempt fails, second succeeds; the empty llm/ban batches
    # early-return without touching the client.
    assert calls == ["insert", "insert", "commit"]
    assert consumer.commits == 1


async def test_when_one_span_is_invalid_then_siblings_insert_and_dlq_receives_it(
    make_job,
) -> None:
    bad = decision_attrs()
    del bad[semconv.TOOL_NAME]
    job, clickhouse, consumer, producer, calls = make_job()
    records = [
        _record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs()), make_span(bad)])])
    ]

    await job._process_poll(records)

    assert calls == ["insert", "dlq", "commit"]  # inserts before DLQ before commit
    assert len(clickhouse.insert.call_args_list[0].args[1]) == 1  # sibling survived
    topic, key, envelope = producer.sent[0]
    assert topic == "hexgate.otlp.dlq"
    assert key == b"proj_1"
    assert json.loads(envelope)["error_class"] == "validation"


async def test_when_the_record_key_is_missing_then_whole_record_to_dlq(
    make_job,
) -> None:
    job, clickhouse, consumer, producer, calls = make_job()
    records = [
        _record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])], key=None)
    ]

    await job._process_poll(records)

    clickhouse.insert.assert_not_called()
    assert json.loads(producer.sent[0][2])["error_class"] == "missing_key"
    assert consumer.commits == 1  # parked, not stuck: the poll still completes


async def test_when_the_payload_is_undecodable_then_whole_record_to_dlq(
    make_job,
) -> None:
    job, clickhouse, consumer, producer, calls = make_job()
    records = [FakeRecord(key=b"proj_1", value=b"\xff\xff garbage")]

    await job._process_poll(records)

    clickhouse.insert.assert_not_called()
    assert json.loads(producer.sent[0][2])["error_class"] == "decode"
    assert consumer.commits == 1


async def test_when_the_agent_version_is_unresolved_then_inserted_with_empty_string(
    make_job,
) -> None:
    job, clickhouse, consumer, producer, calls = make_job(unresolved=True)
    records = [_record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])])]

    await job._process_poll(records)

    decision_rows = clickhouse.insert.call_args_list[0].args[1]
    assert decision_rows[0][4] == ""
    assert consumer.commits == 1
