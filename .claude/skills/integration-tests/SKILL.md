---
name: integration-tests
description: Run the opt-in integration test suites (pytest -m integration) for the SDK and/or the platform API — the ones that hit a live ClickHouse (and, for the SDK, the full OTLP pipeline: platform-api, Collector, Redpanda, span-enricher). Use when asked to run, verify, or debug integration tests, as opposed to the default unit test suite.
---

# Run Integration Tests

## SDK integration tests (repo root — `tests/adapters/*/test_integration.py`, `tests/audit/test_integration.py`)

Infra (idempotent):
```bash
make postgres-init
make clickhouse-up
make redpanda-topics
```

Mint a key — prints `fty_live_…` on stdout, and creates the keypair the Collector needs:
```bash
cd platform/api && DATABASE_URL=postgresql+asyncpg://hexgate:hexgate-dev-password@localhost:5433/hexgate \
    PYTHONPATH=$PWD uv run python ../../deploy/provision.py
```

Three blocking servers, one terminal each. Check first — they bind fixed ports and die with "Address already in use":
```bash
curl -sf http://localhost:8000/health   # platform-api already up?
ss -ltn | grep -q 4318                  # collector already up?

make platform-api-pg    # :8000 — must be -pg, never `make platform-api`
make collector-run      # :4317 / :4318
make enricher-run
```

Run:
```bash
export HEXGATE_API_KEY=<the fty_live_… from above>
export HEXGATE_API_URL=http://localhost:8000
pytest -m integration   # expect 5 passed, ~20s
```

Unset afterward — some unit tests require no API key:
```bash
unset HEXGATE_API_KEY HEXGATE_API_URL HEXGATE_OTLP_ENDPOINT \
      LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY LANGFUSE_HOST
```

On `row never landed in ClickHouse`, read the export error in the captured log, then:
```bash
curl -s "http://localhost:8124/?query=SELECT+count()+FROM+hexgate_audit.policy_decision" \
     -u hexgate:hexgate-dev-password
# DLQ: want HIGH-WATERMARK 0 on every partition
docker exec hexgate-redpanda rpk topic describe hexgate.otlp.dlq -p --brokers localhost:9092
```

## Platform API integration tests (`platform/api/tests/...`)
ClickHouse only — no live server, no Collector, no `HEXGATE_API_KEY`.
```bash
make platform-api-test-integration
```
