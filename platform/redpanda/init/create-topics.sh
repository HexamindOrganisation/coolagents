#!/usr/bin/env bash
# Creates the topics that buffer OTLP spans between the ingestion
# Collector and the enrichment job that writes them to ClickHouse. Not
# auto-run on container start — invoked via `make redpanda-topics` once
# the broker is up. Safe to re-run.
#
# Partition count (3) is a local-dev placeholder for parallelism, not a
# load-tested figure — revisit once real throughput numbers exist.
set -euo pipefail

BOOTSTRAP="${HEXGATE_REDPANDA_BOOTSTRAP_SERVER:-localhost:9092}"

# rpk auto-detects a container environment and applies dev-container
# cluster defaults (including this) regardless of whether --mode
# dev-container was actually passed — confirmed the image's own shipped
# config has no such key, so this isn't something the compose command
# controls. Left enabled, a producer using a wrong/stale topic name (or
# hitting the broker before this script has ever run) gets the topic
# silently fabricated with cluster defaults — 1 partition, 7-day
# retention — instead of a clear error. Applies live, no restart.
rpk cluster config set auto_create_topics_enabled false --no-confirm

# `create --if-not-exists` only applies -c/--partitions on the branch
# where it actually creates the topic — on a topic that already exists
# (e.g. created earlier with different settings, or left over from a
# retention value this script used to set before a config change), it's
# a pure no-op: still exits 0, still prints "OK (topic already exists)",
# but the existing config is untouched. So retention is reconciled
# separately below, every run, regardless of whether create just made
# the topic or found it already there.
#
# Partition count is NOT reconciled the same way: rpk's only knob is
# `add-partitions --num N`, which ADDS N rather than setting a target,
# so it isn't idempotent and can't be dropped into a re-runnable script
# as-is. A topic created with the wrong partition count has to be
# recreated by hand — this script can't fix that drift. Disabling
# auto-creation above removes the main way that drift would happen
# unnoticed.
create_topic() {
  local topic="$1" retention_ms="$2"
  rpk topic create "$topic" --if-not-exists \
    --partitions 3 --replicas 1 \
    -c "retention.ms=$retention_ms" \
    --brokers "$BOOTSTRAP"
  rpk topic alter-config "$topic" --set "retention.ms=$retention_ms" --no-confirm \
    --brokers "$BOOTSTRAP"
}

# Buffer, not the system of record — ClickHouse is. Short retention is
# fine: the enrichment job is expected to keep up, this only needs to
# survive a brief consumer outage/redeploy.
create_topic hexgate.otlp.raw 259200000 # 3 days

# Permanently-rejected events from the enrichment job: undecodable
# payloads, keyless records, spans failing validation. NOT unresolvable
# agent_version_id — those insert with "" like the HTTP ingest does. This
# broker has no auth in front of it at all (PLAINTEXT, no ACLs): today,
# anything that can reach it can write here directly. Nothing currently
# enforces "auth rejections never reach this topic" as an actual
# guarantee — that's a property the Collector work still has to build.
create_topic hexgate.otlp.dlq 2592000000 # 30 days

rpk topic list --brokers "$BOOTSTRAP"