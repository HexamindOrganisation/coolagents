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
# The cluster-config call below goes to the ADMIN API (9644), not the Kafka
# listener. The localhost default fits how dev runs this script (docker exec
# inside the broker container); the deploy stack runs it from a one-shot
# sibling container and overrides both addresses to the service name.
ADMIN_API="${HEXGATE_REDPANDA_ADMIN_API:-localhost:9644}"

# Bounded retry around every rpk call. rpk has none of its own, and the deploy
# stack runs this the moment the broker's healthcheck passes — which can still
# be before the controller has a leader or the Kafka listener is bound. There
# the script runs as a one-shot container that collector and enricher gate on
# (service_completed_successfully, restart "no"), so a single transient exit 1
# would block both until someone re-runs `up`. ~1 minute total.
RETRY_ATTEMPTS=12
RETRY_DELAY_S=5
retry() {
  local attempt
  for attempt in $(seq 1 "$RETRY_ATTEMPTS"); do
    if "$@"; then
      return 0
    fi
    echo "attempt $attempt/$RETRY_ATTEMPTS failed: $*; retrying in ${RETRY_DELAY_S}s" >&2
    sleep "$RETRY_DELAY_S"
  done
  echo "giving up after $RETRY_ATTEMPTS attempts: $*" >&2
  return 1
}

# rpk auto-detects a container environment and applies dev-container
# cluster defaults (including this) regardless of whether --mode
# dev-container was actually passed — confirmed the image's own shipped
# config has no such key, so this isn't something the compose command
# controls. Left enabled, a producer using a wrong/stale topic name (or
# hitting the broker before this script has ever run) gets the topic
# silently fabricated with cluster defaults — 1 partition, 7-day
# retention — instead of a clear error. Applies live, no restart.
retry rpk cluster config set auto_create_topics_enabled false --no-confirm \
    -X admin.hosts="$ADMIN_API"

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
  retry rpk topic create "$topic" --if-not-exists \
    --partitions 3 --replicas 1 \
    -c "retention.ms=$retention_ms" \
    --brokers "$BOOTSTRAP"
  retry rpk topic alter-config "$topic" --set "retention.ms=$retention_ms" --no-confirm \
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

retry rpk topic list --brokers "$BOOTSTRAP"
