#!/usr/bin/env bash
# Creates the topics that buffer OTLP spans between the ingestion
# Collector and the enrichment job that writes them to ClickHouse. Not
# auto-run on container start — invoked via `make redpanda-topics` once
# the broker is up. Idempotent (--if-not-exists), safe to re-run.
#
# Partition count (3) is a local-dev placeholder for parallelism, not a
# load-tested figure — revisit once real throughput numbers exist.
set -euo pipefail

BOOTSTRAP="${HEXGATE_REDPANDA_BOOTSTRAP_SERVER:-localhost:9092}"

# Buffer, not the system of record — ClickHouse is. Short retention is
# fine: the enrichment job is expected to keep up, this only needs to
# survive a brief consumer outage/redeploy.
rpk topic create hexgate.otlp.raw --if-not-exists \
  --partitions 3 --replicas 1 \
  -c retention.ms=259200000 `#3 days` \
  --brokers "$BOOTSTRAP"

# Intended for permanently-rejected events (unfixable validation,
# unresolvable agent_version_id) reaching the enrichment job — once that
# job and the ingestion Collector exist. Neither does yet, and this
# broker has no auth in front of it at all (PLAINTEXT, no ACLs): today,
# anything that can reach it can write here directly. Nothing currently
# enforces "auth rejections never reach this topic" as an actual
# guarantee — that's a property the Collector work still has to build.
rpk topic create hexgate.otlp.dlq --if-not-exists \
  --partitions 3 --replicas 1 \
  -c retention.ms=2592000000 `#30 days` \
  --brokers "$BOOTSTRAP"

rpk topic list --brokers "$BOOTSTRAP"
