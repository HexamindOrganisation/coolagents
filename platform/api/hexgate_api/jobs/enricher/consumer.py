"""The enricher's Kafka lifecycle and poll loop.

Correctness contract, in processing order per poll:
decode → per-span map/validate (rejects → DLQ envelopes, siblings survive)
→ resolve agent versions → three batch inserts (retried as a whole until
ClickHouse acks) → DLQ sends → offset commit. Committing only after the
ClickHouse ack means a crash anywhere in the cycle replays the poll on
restart, which is safe: event_id is the idempotency key and
ReplacingMergeTree collapses the duplicates.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import CommitFailedError
from clickhouse_connect.driver.client import Client

from hexgate_api.core.clickhouse import BatchItem, get_clickhouse
from hexgate_api.core.db import engine
from hexgate_api.features.audit.service import (
    insert_ban_enforcements_batch,
    insert_decisions_batch,
)
from hexgate_api.features.audit.service import verify_schema as verify_audit_schema
from hexgate_api.features.llm_invocations.service import (
    insert_llm_invocations_batch,
)
from hexgate_api.features.llm_invocations.service import (
    verify_schema as verify_llm_schema,
)
from hexgate_api.jobs.enricher import dlq
from hexgate_api.jobs.enricher.coerce import SpanRejected
from hexgate_api.jobs.enricher.decode import RecordDecodeError, decode_record
from hexgate_api.jobs.enricher.mapping import Event, map_span
from hexgate_api.jobs.enricher.resolver import resolve_versions
from hexgate_api.schemas import BanEnforcementEvent, DecisionEvent, LlmInvocationEvent
from hexgate_api.settings import Settings

_log = logging.getLogger(__name__)

# A CH-outage retry longer than this evicts us from the consumer group and
# hands the partition to a replica that will hit the same outage. Generous
# beats the 5-minute default; an eviction would only add rebalance churn.
_MAX_POLL_INTERVAL_MS = 30 * 60 * 1000


class TopicsMissing(Exception):
    """A required topic does not exist (auto-create is disabled)."""

    def __init__(self, missing: list[str]) -> None:
        super().__init__(
            f"missing Kafka topic(s) {', '.join(missing)} — run `make redpanda-topics`"
        )


class EnricherJob:
    """One consumer-group member. Instantiate once per process."""

    def __init__(
        self,
        settings: Settings,
        *,
        clickhouse_client: Client | None = None,
        consumer: Any | None = None,
        producer: Any | None = None,
    ) -> None:
        # Kafka clients are injectable so unit tests drive _process_poll with
        # fakes; production leaves them None and run() builds real ones.
        self._settings = settings
        self._clickhouse = clickhouse_client
        self._consumer = consumer
        self._producer = producer
        self._stop = asyncio.Event()

    def request_stop(self) -> None:
        self._stop.set()

    async def run(self) -> None:
        settings = self._settings
        # Fail fast on a stale ClickHouse volume — same guard the API runs at
        # startup, per feature, covering every table this job writes.
        self._clickhouse = self._clickhouse or get_clickhouse()
        verify_audit_schema(self._clickhouse)
        verify_llm_schema(self._clickhouse)

        if self._consumer is None:
            self._consumer = AIOKafkaConsumer(
                settings.redpanda_raw_topic,
                bootstrap_servers=settings.redpanda_bootstrap_server,
                group_id=settings.enricher_consumer_group,
                # Offsets are the job's progress marker; committing them is
                # the last step of a cycle, never automatic.
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                max_poll_interval_ms=_MAX_POLL_INTERVAL_MS,
            )
        if self._producer is None:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=settings.redpanda_bootstrap_server, acks="all"
            )
        await self._consumer.start()
        await self._producer.start()
        try:
            # Auto-create is disabled cluster-wide, so a missing topic is an
            # operator error worth an actionable exit, not a silent hang.
            existing = await self._consumer.topics()
            missing = [
                topic
                for topic in (settings.redpanda_raw_topic, settings.redpanda_dlq_topic)
                if topic not in existing
            ]
            if missing:
                raise TopicsMissing(missing)

            loop = asyncio.get_running_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, self._stop.set)

            _log.info(
                "enricher consuming %s (group %s) → ClickHouse",
                settings.redpanda_raw_topic,
                settings.enricher_consumer_group,
            )
            while not self._stop.is_set():
                batches = await self._consumer.getmany(
                    timeout_ms=settings.enricher_poll_timeout_ms,
                    max_records=settings.enricher_max_poll_records,
                )
                records = [record for part in batches.values() for record in part]
                if records:
                    await self._process_poll(records)
        finally:
            await self._consumer.stop()
            await self._producer.stop()
            await engine.dispose()

    async def _process_poll(self, records: list[Any]) -> None:
        """One full cycle over one poll's records. See the module docstring
        for the ordering contract."""
        events: list[tuple[Event, str]] = []  # (event, project_id)
        dlq_messages: list[tuple[bytes | None, bytes]] = []  # (key, envelope)
        for record in records:
            if record.key is None:
                # No auth-derived project attribution → unattributable, park it.
                dlq_messages.append(
                    (
                        None,
                        dlq.record_envelope(
                            error="record has no project_id key",
                            error_class="missing_key",
                            project_id=None,
                            topic=record.topic,
                            partition=record.partition,
                            offset=record.offset,
                            raw_value=record.value,
                        ),
                    )
                )
                continue
            project_id = record.key.decode("utf-8")
            try:
                decoded = decode_record(record.value)
            except RecordDecodeError as exc:
                dlq_messages.append(
                    (
                        record.key,
                        dlq.record_envelope(
                            error=f"undecodable OTLP payload: {exc}",
                            error_class="decode",
                            project_id=project_id,
                            topic=record.topic,
                            partition=record.partition,
                            offset=record.offset,
                            raw_value=record.value,
                        ),
                    )
                )
                continue
            for scope_name, span, resource_attrs in decoded:
                try:
                    events.append(
                        (map_span(scope_name, span, resource_attrs), project_id)
                    )
                except SpanRejected as rejected:
                    # One bad span never rejects its siblings.
                    dlq_messages.append(
                        (
                            record.key,
                            dlq.span_envelope(
                                error=rejected.error,
                                error_class=rejected.error_class,
                                scope=rejected.scope,
                                project_id=project_id,
                                topic=record.topic,
                                partition=record.partition,
                                offset=record.offset,
                                span=span,
                            ),
                        )
                    )

        versions = await resolve_versions(
            {(project_id, event.agent_name) for event, project_id in events}
        )
        decisions = [
            BatchItem(
                event,
                project_id=pid,
                agent_version_id=versions[(pid, event.agent_name)],
            )
            for event, pid in events
            if isinstance(event, DecisionEvent)
        ]
        llms = [
            BatchItem(
                event,
                project_id=pid,
                agent_version_id=versions[(pid, event.agent_name)],
            )
            for event, pid in events
            if isinstance(event, LlmInvocationEvent)
        ]
        bans = [
            BatchItem(
                event,
                project_id=pid,
                agent_version_id=versions[(pid, event.agent_name)],
            )
            for event, pid in events
            if isinstance(event, BanEnforcementEvent)
        ]

        # Retry the whole batch until ClickHouse acks. Only infra failures can
        # land here (bad input was already diverted to the DLQ above), so
        # halting this partition is correct: committing would drop data, and
        # redelivery after a restart dedups. Re-running all three inserts on a
        # partial failure is safe per the batch functions' contract.
        # Initial backoff never exceeds the cap, so tests (and operators) can
        # shrink the whole retry cadence with one setting.
        backoff = min(1.0, self._settings.enricher_insert_max_backoff_s)
        while True:
            try:
                await asyncio.to_thread(
                    insert_decisions_batch, self._clickhouse, decisions
                )
                await asyncio.to_thread(
                    insert_llm_invocations_batch, self._clickhouse, llms
                )
                await asyncio.to_thread(
                    insert_ban_enforcements_batch, self._clickhouse, bans
                )
                break
            except Exception:
                if self._stop.is_set():
                    # Stopping mid-outage: don't wait, don't commit — the poll
                    # replays after restart. A healthy in-flight poll is never
                    # abandoned; the check lives here, not at the loop top.
                    return
                _log.exception(
                    "ClickHouse insert failed; retrying whole batch in %.0fs", backoff
                )
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self._settings.enricher_insert_max_backoff_s)

        for key, envelope in dlq_messages:
            await self._producer.send_and_wait(
                self._settings.redpanda_dlq_topic, envelope, key=key
            )

        try:
            await self._consumer.commit()
        except CommitFailedError:
            # A rebalance took our partitions mid-cycle. Drop this poll — the
            # new owner replays it and ClickHouse dedup absorbs the rows (DLQ
            # consumers must tolerate the duplicate envelopes).
            _log.warning("offset commit failed after a rebalance; poll will replay")
