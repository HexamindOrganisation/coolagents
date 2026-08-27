"""The enricher's Kafka lifecycle and poll loop.

Correctness contract, in processing order per poll:
decode → per-span map/validate (rejects → DLQ envelopes, siblings survive)
→ resolve agent versions → three batch inserts (retried as a whole until
ClickHouse acks) → DLQ sends → offset commit. Committing only after the
ClickHouse ack means a crash anywhere in the cycle replays the poll on
restart, which is safe for the tables: event_id is the idempotency key and
ReplacingMergeTree collapses the duplicates. DLQ envelopes have no such key
and are simply re-sent on replay (see dlq.py).
"""

from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from aiokafka.errors import CommitFailedError
from clickhouse_connect.driver.client import Client

from hexgate_api.core.clickhouse import BatchItem, get_clickhouse, verify_all
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
        # Installed first: until this runs SIGTERM has the default disposition
        # and kills the process outright, skipping the finally below — so a
        # signal during the broker connects would leave a dead group member
        # until the session times out. The handler only flags an Event, so
        # nothing it needs is created later.
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._stop.set)

        # Fail fast on a stale ClickHouse volume — same guard the API runs at
        # startup, aggregated so a volume behind on two tables reports both in
        # one boot. Sync clickhouse-connect call, so off the loop like the
        # inserts below.
        self._clickhouse = self._clickhouse or get_clickhouse()
        await asyncio.to_thread(
            verify_all, self._clickhouse, (verify_audit_schema, verify_llm_schema)
        )

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
        # Both starts live inside the try: the consumer joins the group on
        # start(), so a producer that then fails to connect must still leave
        # the group cleanly instead of holding its partitions until the
        # session times out. stop() on a never-started client is a no-op.
        try:
            await self._consumer.start()
            await self._producer.start()
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

    async def _retry_until_acked(
        self, attempt: Callable[[], Awaitable[None]], what: str
    ) -> bool:
        """Run ``attempt`` until it succeeds; False if a stop arrived first.

        A False return means the caller must not commit: the poll replays
        after restart. A healthy in-flight attempt is never abandoned — the
        stop check lives in the failure branch, not at the loop top. Initial
        backoff never exceeds the cap, so tests (and operators) can shrink
        the whole retry cadence with one setting.
        """
        cap = self._settings.enricher_insert_max_backoff_s
        backoff = min(1.0, cap)
        while True:
            try:
                await attempt()
                return True
            except Exception:
                if self._stop.is_set():
                    return False
                _log.exception("%s failed; retrying in %.0fs", what, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, cap)

    async def _process_poll(self, records: list[Any]) -> None:
        """One full cycle over one poll's records. See the module docstring
        for the ordering contract."""
        events: list[tuple[Event, str]] = []  # (event, project_id)
        # A produce retry whose first attempt landed puts the same span on the
        # topic twice, often adjacent and so inside one poll. ClickHouse only
        # collapses such a pair at insert time when both fall in the same
        # block, so the batch functions ask the caller to dedup by event_id
        # first (see insert_decisions_batch). First copy wins.
        seen_event_ids: set[str] = set()
        dlq_messages: list[tuple[bytes | None, bytes]] = []  # (key, envelope)
        for record in records:
            project_id = record.key.decode("utf-8") if record.key is not None else None
            # Decode before looking at the key: a keyless record is usually a
            # valid request that lost its auth attribution upstream, and only
            # a decoded span can be redacted before it is parked.
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
            if project_id is None:
                # No auth-derived project attribution → unattributable, park
                # every span (redacted) rather than the raw record.
                for scope_name, span, _resource_attrs in decoded:
                    dlq_messages.append(
                        (
                            None,
                            dlq.span_envelope(
                                error="record has no project_id key",
                                error_class="missing_key",
                                scope=scope_name,
                                project_id="",
                                topic=record.topic,
                                partition=record.partition,
                                offset=record.offset,
                                span=span,
                            ),
                        )
                    )
                continue
            for scope_name, span, resource_attrs in decoded:
                try:
                    event = map_span(scope_name, span, resource_attrs)
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
                    continue
                if event.event_id in seen_event_ids:
                    continue
                seen_event_ids.add(event.event_id)
                events.append((event, project_id))

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
        async def _insert_all() -> None:
            await asyncio.to_thread(insert_decisions_batch, self._clickhouse, decisions)
            await asyncio.to_thread(
                insert_llm_invocations_batch, self._clickhouse, llms
            )
            await asyncio.to_thread(
                insert_ban_enforcements_batch, self._clickhouse, bans
            )

        if not await self._retry_until_acked(_insert_all, "ClickHouse insert"):
            return

        # Same posture for the DLQ: an envelope that never lands would be lost
        # for good once the offset commits, so a send failure halts here too.
        # Per message, so a mid-list failure re-sends only what is left.
        for key, envelope in dlq_messages:
            send = partial(
                self._producer.send_and_wait,
                self._settings.redpanda_dlq_topic,
                envelope,
                key=key,
            )
            if not await self._retry_until_acked(send, "DLQ send"):
                return

        try:
            await self._consumer.commit()
        except CommitFailedError:
            # A rebalance took our partitions mid-cycle. Drop this poll — the
            # new owner replays it and ClickHouse dedup absorbs the rows (DLQ
            # consumers must tolerate the duplicate envelopes).
            _log.warning("offset commit failed after a rebalance; poll will replay")
