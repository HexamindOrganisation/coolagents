#!/usr/bin/env bash
# Creates the topics that buffer OTLP spans between the ingestion
# Collector and the enrichment job that writes them to ClickHouse. Not
# auto-run on container start (Kafka has no docker-entrypoint-initdb.d
# equivalent) — invoked via `make kafka-topics` once the broker is up.
# Idempotent (--if-not-exists), safe to re-run.
#
# Partition count (3) is a local-dev placeholder for parallelism, not a
# load-tested figure — revisit once real throughput numbers exist.
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVER:-localhost:9092}"
TOPICS_SH=/opt/kafka/bin/kafka-topics.sh

# Buffer, not the system of record — ClickHouse is. Short retention is
# fine: the enrichment job is expected to keep up, this only needs to
# survive a brief consumer outage/redeploy.
"$TOPICS_SH" --bootstrap-server "$BOOTSTRAP" \
  --create --if-not-exists --topic hexgate.otlp.raw \
  --partitions 3 --replication-factor 1 \
  --config retention.ms=259200000 # 3 days

# Intended for permanently-rejected events (unfixable validation,
# unresolvable agent_version_id) reaching the enrichment job — once that
# job and the ingestion Collector exist. Neither does yet, and this
# broker has no auth in front of it at all (PLAINTEXT, no ACLs): today,
# anything that can reach it can write here directly. Nothing currently
# enforces "auth rejections never reach this topic" as an actual
# guarantee — that's a property the Collector work still has to build.
"$TOPICS_SH" --bootstrap-server "$BOOTSTRAP" \
  --create --if-not-exists --topic hexgate.otlp.dlq \
  --partitions 3 --replication-factor 1 \
  --config retention.ms=2592000000 # 30 days

"$TOPICS_SH" --bootstrap-server "$BOOTSTRAP" --list
