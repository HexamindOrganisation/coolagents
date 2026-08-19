# Hexgate — Claude Code Instructions

## Tech Stack
- Python ≥ 3.13 (`uv`), FastAPI (`platform/api/`), ClickHouse (Docker), Redpanda (Docker, Kafka-protocol-compatible, dev-infra only for now — see `platform/docker-compose.yml`)
- React, Vite, pnpm (`platform/dashboard/`)
- Ruff (Python). WASM via `wasmtime`.

## Cross-package
After you make changes across multiple packages, run: `make check-all`  # all packages

## Repo Layout
hexgate/              # SDK source
platform/api/         # FastAPI control plane (separate uv project)
platform/api/tests/   # API tests
platform/collector/   # OTLP ingestion Collector (Go)
platform/dashboard/   # React/Vite frontend
tests/                # hexgate package tests (agents, cli, security, tracing, streaming…)

## AI Constraints (CRITICAL)
- NEVER fabricate code examples, config snippets, or file contents. If unknown, read the file first.
- Verify third-party or config behavior against actual files in this repo before generating code.

## Rules & Constants
- **Branches:** `{initials}/{type}/{short_description}` (e.g., `vl/feat/web_search`)
- **Commits:** `type(scope): description` (lowercase, imperative, no period). Scopes: `platform-api`, `dashboard`, `sdk`, `cli`, `clickhouse`, `redpanda`, `collector`. Types: `feat`, `fix`, `docs`, `build`, `refactor`, `test`.
- **Envs:** All prefixed with `HEXGATE_`. Never commit private keys.
