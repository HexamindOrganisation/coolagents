"""consumer.py — one _process_poll cycle driven with fakes.

The ordering contract under test: inserts → DLQ sends → offset commit.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from clickhouse_connect.driver.exceptions import OperationalError

from hexgate.tracing import semconv
from tests.jobs.enricher.conftest import (
    FakeConsumer,
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


async def test_when_the_same_event_id_arrives_twice_in_one_poll_then_inserted_once(
    make_job,
) -> None:
    # A Collector produce retry whose first attempt landed: two records, same
    # span. ClickHouse only collapses these at insert time if they share a
    # block, so the consumer dedups before building the batch.
    job, clickhouse, consumer, producer, calls = make_job()
    attrs = decision_attrs()
    records = [
        _record([(semconv.SCOPE_AUDIT, [make_span(attrs)])], offset=0),
        _record([(semconv.SCOPE_AUDIT, [make_span(attrs)])], offset=1),
    ]

    await job._process_poll(records)

    decision_rows = clickhouse.insert.call_args_list[0].args[1]
    assert len(decision_rows) == 1
    assert producer.sent == []  # a duplicate is not an error
    assert consumer.commits == 1


async def test_when_two_projects_share_an_event_id_then_both_are_inserted(
    make_job,
) -> None:
    # event_id is client-set; only the record key is auth-derived. A tenant
    # reusing another tenant's id is a different event, not a duplicate.
    job, clickhouse, consumer, producer, calls = make_job()
    attrs = decision_attrs()
    records = [
        _record([(semconv.SCOPE_AUDIT, [make_span(attrs)])], key=b"proj_1"),
        _record([(semconv.SCOPE_AUDIT, [make_span(attrs)])], key=b"proj_2"),
    ]

    await job._process_poll(records)

    decision_rows = clickhouse.insert.call_args_list[0].args[1]
    assert sorted(row[2] for row in decision_rows) == ["proj_1", "proj_2"]


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


async def test_when_the_record_key_is_missing_then_each_span_to_dlq_redacted(
    make_job,
) -> None:
    # A keyless record is still a decodable request; it must be parked span by
    # span through the redacting envelope, never as raw bytes.
    job, clickhouse, consumer, producer, calls = make_job()
    secret_args = json.dumps({"password": "hunter2", "query": "q"})
    spans = [
        make_span(decision_attrs(**{semconv.ARGUMENTS: secret_args})),
        make_span(decision_attrs()),
    ]
    records = [_record([(semconv.SCOPE_AUDIT, spans)], key=None)]

    await job._process_poll(records)

    clickhouse.insert.assert_not_called()
    assert len(producer.sent) == 2
    envelopes = [json.loads(sent[2]) for sent in producer.sent]
    assert {env["error_class"] for env in envelopes} == {"missing_key"}
    assert all(env["project_id"] == "" for env in envelopes)
    assert all("record_value_base64" not in env for env in envelopes)
    assert envelopes[0]["span"]["attributes"][semconv.ARGUMENTS] == {
        "password": "[REDACTED]",
        "query": "q",
    }
    assert consumer.commits == 1  # parked, not stuck: the poll still completes


async def test_when_a_keyless_record_is_undecodable_then_whole_record_to_dlq(
    make_job,
) -> None:
    job, clickhouse, consumer, producer, calls = make_job()
    records = [FakeRecord(key=None, value=b"\xff\xff garbage")]

    await job._process_poll(records)

    clickhouse.insert.assert_not_called()
    envelope = json.loads(producer.sent[0][2])
    assert envelope["error_class"] == "decode"
    assert envelope["project_id"] is None
    assert consumer.commits == 1


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


# ---------------------------------------------------------------------------
# run() lifecycle + the two availability-critical failure branches
# ---------------------------------------------------------------------------


async def _noop(*_args, **_kwargs):
    return None


class _LifecycleConsumer(FakeConsumer):
    """FakeConsumer plus the lifecycle surface run() touches. Serves one
    poll of `records`, then requests a stop so run() returns."""

    def __init__(self, calls, records, topics, job_ref):
        super().__init__(calls)
        self._records = records
        self._topics = topics
        self._job_ref = job_ref
        self.started = self.stopped = False

    async def start(self):
        self.started = True

    async def stop(self):
        self.stopped = True

    async def topics(self):
        return self._topics

    async def getmany(self, timeout_ms, max_records):
        self._job_ref[0].request_stop()  # one poll, then exit the loop
        return {"tp0": self._records} if self._records else {}


def _lifecycle_job(monkeypatch, make_job, *, records, topics):
    job, clickhouse, _consumer, producer, calls = make_job()
    consumer = _LifecycleConsumer(calls, records, topics, [job])
    producer.start = producer.stop = _noop  # type: ignore[attr-defined]
    job._consumer = consumer
    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.verify_audit_schema", lambda c: None
    )
    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.verify_llm_schema", lambda c: None
    )
    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.engine", SimpleNamespace(dispose=_noop)
    )
    return job, clickhouse, consumer, calls


async def test_run_happy_path_processes_a_poll_then_stops_cleanly(
    monkeypatch, make_job
) -> None:
    records = [_record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])])]
    job, clickhouse, consumer, calls = _lifecycle_job(
        monkeypatch,
        make_job,
        records=records,
        topics={"hexgate.otlp.raw", "hexgate.otlp.dlq"},
    )

    await job.run()

    assert consumer.started and consumer.stopped
    assert calls == ["insert", "commit"]


async def test_when_a_topic_is_missing_then_run_fails_fast(
    monkeypatch, make_job
) -> None:
    from hexgate_api.jobs.enricher.consumer import TopicsMissing

    job, clickhouse, consumer, calls = _lifecycle_job(
        monkeypatch, make_job, records=[], topics={"hexgate.otlp.raw"}
    )

    with pytest.raises(TopicsMissing) as exc:
        await job.run()

    assert "hexgate.otlp.dlq" in str(exc.value)
    assert "make redpanda-topics" in str(exc.value)
    assert consumer.stopped  # finally-block cleanup still ran


async def test_when_two_tables_are_stale_then_run_reports_both_gaps_at_once(
    monkeypatch, make_job
) -> None:
    # The two per-feature checks are aggregated: a volume behind on both
    # policy_decision and llm_invocation must name both in one boot, not one
    # per restart.
    from hexgate_api.core.clickhouse import SchemaOutOfDate

    job, clickhouse, consumer, calls = _lifecycle_job(
        monkeypatch,
        make_job,
        records=[],
        topics={"hexgate.otlp.raw", "hexgate.otlp.dlq"},
    )

    def _audit_stale(_client):
        raise SchemaOutOfDate({"policy_decision": ["deciding_role"]})

    def _llm_stale(_client):
        raise SchemaOutOfDate({"llm_invocation": ["latency_ms"]})

    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.verify_audit_schema", _audit_stale
    )
    monkeypatch.setattr(
        "hexgate_api.jobs.enricher.consumer.verify_llm_schema", _llm_stale
    )

    with pytest.raises(SchemaOutOfDate) as exc:
        await job.run()

    assert exc.value.missing == {
        "policy_decision": ["deciding_role"],
        "llm_invocation": ["latency_ms"],
    }
    assert not consumer.started  # the check runs before any broker connect


async def test_when_the_producer_fails_to_start_then_the_consumer_still_stops(
    monkeypatch, make_job
) -> None:
    from aiokafka.errors import KafkaConnectionError

    job, clickhouse, consumer, calls = _lifecycle_job(
        monkeypatch,
        make_job,
        records=[],
        topics={"hexgate.otlp.raw", "hexgate.otlp.dlq"},
    )

    async def _refuse_to_start():
        raise KafkaConnectionError("producer bootstrap unreachable")

    job._producer.start = _refuse_to_start  # type: ignore[method-assign]

    with pytest.raises(KafkaConnectionError):
        await job.run()

    # The consumer had already joined the group; it must leave it.
    assert consumer.started and consumer.stopped


async def test_when_stop_is_requested_mid_outage_then_no_commit(
    monkeypatch, make_job
) -> None:
    """The data-loss guard: a SIGTERM while ClickHouse is down must exit the
    retry loop WITHOUT committing, so the poll replays after restart."""
    import hexgate_api.jobs.enricher.consumer as consumer_mod

    job, clickhouse, consumer, producer, calls = make_job(
        insert_side_effect=[OperationalError("down"), OperationalError("still down")]
    )
    records = [_record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])])]

    async def _stop_instead_of_sleeping(_delay):
        job.request_stop()

    # The first failure sleeps; hijack that sleep to request the stop.
    monkeypatch.setattr(consumer_mod.asyncio, "sleep", _stop_instead_of_sleeping)

    await job._process_poll(records)

    assert consumer.commits == 0
    assert producer.sent == []


def _one_bad_span_record():
    bad = decision_attrs()
    del bad[semconv.TOOL_NAME]
    return _record([(semconv.SCOPE_AUDIT, [make_span(bad)])])


async def test_when_a_dlq_send_fails_then_it_is_retried_and_committed_once(
    make_job,
) -> None:
    from aiokafka.errors import KafkaTimeoutError

    job, clickhouse, consumer, producer, calls = make_job(
        send_side_effect=[KafkaTimeoutError("dlq leader unavailable")]
    )

    await job._process_poll([_one_bad_span_record()])

    # First send fails, second lands; the envelope is written exactly once.
    assert calls == ["dlq", "dlq", "commit"]
    assert len(producer.sent) == 1
    assert consumer.commits == 1


async def test_when_a_dlq_envelope_is_too_large_then_dropped_and_committed(
    make_job,
) -> None:
    """MessageSizeTooLargeError is client-side and permanent: no retry can
    ever land the envelope, so it is dropped (the source record still holds
    the original bytes) and the poll completes instead of wedging."""
    from aiokafka.errors import MessageSizeTooLargeError

    job, clickhouse, consumer, producer, calls = make_job(
        send_side_effect=[MessageSizeTooLargeError()]
    )

    await job._process_poll([_one_bad_span_record()])

    assert calls == ["dlq", "commit"]  # one attempt, no retry loop
    assert producer.sent == []  # dropped, not delivered
    assert consumer.commits == 1


async def test_when_stop_is_requested_mid_dlq_outage_then_no_commit(
    monkeypatch, make_job
) -> None:
    """Same guard as the ClickHouse path: a SIGTERM while the DLQ topic is
    unreachable must leave the offset uncommitted so the poll replays."""
    import hexgate_api.jobs.enricher.consumer as consumer_mod
    from aiokafka.errors import KafkaTimeoutError

    job, clickhouse, consumer, producer, calls = make_job(
        send_side_effect=[KafkaTimeoutError("down"), KafkaTimeoutError("still down")]
    )

    async def _stop_instead_of_sleeping(_delay):
        job.request_stop()

    monkeypatch.setattr(consumer_mod.asyncio, "sleep", _stop_instead_of_sleeping)

    await job._process_poll([_one_bad_span_record()])

    assert consumer.commits == 0
    assert producer.sent == []


async def test_when_commit_fails_on_rebalance_then_poll_is_dropped_not_fatal(
    make_job,
) -> None:
    from aiokafka.errors import CommitFailedError

    job, clickhouse, consumer, producer, calls = make_job()

    async def _failing_commit():
        raise CommitFailedError("rebalance")

    consumer.commit = _failing_commit  # type: ignore[method-assign]
    records = [_record([(semconv.SCOPE_AUDIT, [make_span(decision_attrs())])])]

    await job._process_poll(records)  # no raise: the new owner replays it

    assert calls == ["insert"]
