# Run Integration Tests

## SDK integration tests (repo root — `tests/adapters/*/test_integration.py`, `tests/audit/test_integration.py`)
Hits a live platform server + ClickHouse end-to-end. Needs ClickHouse running, `platform-api` running, and a real `HEXGATE_API_KEY` minted via the dashboard (repo-root `.env`).
```bash
make clickhouse-up   # idempotent — safe to run even if already up, no-ops if unchanged

# Check platform-api first — it's NOT idempotent. uvicorn binds :8000 directly,
# so running `make platform-api` while one's already up fails with
# "Address already in use" instead of reusing the running instance.
curl -sf http://localhost:8000/health
# ^ if this 200s, platform-api is already up — skip starting it.
# If it fails, start `make platform-api` in a separate terminal (it's a
# foreground/blocking dev server — don't chain it into this script).

set -a && source .env && set +a   # loads HEXGATE_API_KEY etc. from .env into the shell
pytest -m integration
```
Unset afterward because some unit tests rely on not having any API key defined:
```bash
unset HEXGATE_API_KEY HEXGATE_API_URL LANGFUSE_PUBLIC_KEY LANGFUSE_SECRET_KEY LANGFUSE_HOST
```

## Platform API integration tests (`platform/api/tests/...`)
Call the service layer directly against ClickHouse, in-process — no live platform server, no `HEXGATE_API_KEY`, just ClickHouse running.
```bash
make clickhouse-up   # only prerequisite (creates schema on first run)
cd platform/api && uv run pytest -m integration
```
