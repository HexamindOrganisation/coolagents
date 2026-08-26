# HexaGate SDK — dev/test/build helpers.
#
# Most targets shell out to `uv`. The default flow assumes a uv-managed
# virtualenv (created by `make install-dev`). If you're driving uv with
# a pre-existing conda/micromamba environment, export the env path
# before invoking make:
#
#     export UV_PROJECT_ENVIRONMENT=$HOME/micromamba/envs/hexanlp-demo
#     make test
#
# `uv` picks up that variable and runs against your existing env
# instead of bootstrapping its own.

UV ?= uv run --active
TESTS ?= tests/

.DEFAULT_GOAL := help

# -------- Meta --------

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "\nHexaGate SDK targets:\n\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# -------- Setup --------

.PHONY: install
install: ## Install runtime deps via uv (creates .venv if needed)
	uv sync

.PHONY: install-dev
install-dev: ## Install with dev extras (pytest, ruff)
	uv sync --extra dev

# -------- Dev loop --------

.PHONY: test
test: ## Run the full test suite quietly
	$(UV) pytest $(TESTS) -q

.PHONY: test-verbose
test-verbose: ## Run tests with -v output
	$(UV) pytest $(TESTS) -v

.PHONY: test-failed
test-failed: ## Re-run only the tests that failed last time
	$(UV) pytest $(TESTS) --lf -v

.PHONY: test-one
test-one: ## Run one test path: make test-one T=tests/security/test_bundle.py
	@test -n "$(T)" || (echo "Set T=<path>, e.g. make test-one T=tests/security/test_bundle.py" && exit 1)
	$(UV) pytest $(T) -v

.PHONY: framework-compat
framework-compat: ## Run the opt-in framework-compat probes on installed versions
	$(UV) pytest -m framework_compat tests/framework_compat/ -v

.PHONY: framework-matrix
framework-matrix: ## Run the framework-matrix driver: make framework-matrix ARGS="--dry-run"
	$(UV) python scripts/framework_matrix.py $(ARGS)

.PHONY: coverage
coverage: ## Run the SDK suite with branch coverage (terminal + xml for CI)
	# `uv run` without --active so pytest-cov resolves from the project's
	# .venv. If you drive uv with UV_PROJECT_ENVIRONMENT (micromamba etc.)
	# you'll need pytest-cov installed there too — `uv sync --extra dev`
	# against the same env.
	uv run pytest --cov --cov-report=xml --cov-report=term $(TESTS)

.PHONY: coverage-html
coverage-html: ## Coverage with a browsable HTML report under htmlcov/
	uv run pytest --cov --cov-report=html --cov-report=term $(TESTS)
	@echo "Open htmlcov/index.html in a browser."

.PHONY: lint
lint: ## Static check via ruff
	$(UV) ruff check hexgate tests

.PHONY: lint-fix
lint-fix: ## Apply ruff autofixes
	$(UV) ruff check --fix hexgate tests

.PHONY: fmt
fmt: ## Format with ruff (SDK + platform/api)
	$(UV) ruff format hexgate tests platform/api

.PHONY: fmt-check
fmt-check: ## Check formatting without writing changes
	$(UV) ruff format --check hexgate tests platform/api

.PHONY: check
check: lint fmt-check test ## Python CI parity: lint + fmt-check + test (no coverage overhead)

.PHONY: check-all
check-all: lint fmt-check coverage platform-api-check dashboard-lint dashboard-typecheck dashboard-fmt-check collector-check ## Full stack: lint + fmt + tests with coverage on all four surfaces
	# Dashboard tests via the coverage script (vitest --coverage); same
	# entry point CI uses so a green `check-all` proves the surfaces
	# Codecov sees are the same surfaces a contributor saw locally.
	cd platform/dashboard && pnpm test:coverage

.PHONY: platform-api-check
platform-api-check: ## Lint + test (with coverage) on the platform API
	cd platform/api && uv run ruff check .
	cd platform/api && uv run pytest --cov --cov-report=xml --cov-report=term tests/

# -------- Policy / M2 demo helpers --------

.PHONY: policy-build
policy-build: ## Compile examples/example_agent/policy.yaml to a bundle under /tmp/m2-bundle
	$(UV) hexgate policy build examples/example_agent/policy.yaml --out /tmp/m2-bundle

.PHONY: policy-test-wasm
policy-test-wasm: ## Smoke a wasm-engine decision on the example policy
	$(UV) hexgate policy test examples/example_agent/policy.yaml \
	    --role default --tool web_search --args '{}' --engine wasm

.PHONY: demo-mcp
demo-mcp: ## Run the MCP-proxy demo (self-contained, no external services or LLM key)
	$(UV) python examples/mcp_demo.py

.PHONY: demo-gates
demo-gates: ## Open the gates showcase notebook (agent + MCP + policy; no LLM key). Local only — does NOT touch the Daytona snapshot.
	$(UV) --with marimo marimo edit deploy/gates-demo/notebook.py

.PHONY: demo-override
demo-override: ## Build a deny-everything bundle + chat with HEXGATE_LOCAL_POLICY set
	@echo "→ Writing a deny-everything override policy…"
	@printf 'version: 1\nroles:\n  default:\n    tools:\n      web_search: { mode: deny }\n      fetch: { mode: deny }\n' > /tmp/m2-deny-policy.yaml
	$(UV) hexgate policy build /tmp/m2-deny-policy.yaml --out /tmp/m2-deny-bundle
	@echo ""
	@echo "→ Starting chat with HEXGATE_LOCAL_POLICY=/tmp/m2-deny-bundle"
	@echo "  Try a prompt that would trigger web_search; expect a wasm-engine deny."
	@echo ""
	HEXGATE_LOCAL_POLICY=/tmp/m2-deny-bundle $(UV) hexgate chat --agent example_agent --approval-mode auto-deny

# -------- Platform infra (ClickHouse audit log) --------
#
# Docker Compose service definition lives in platform/docker-compose.yml.
# First `make clickhouse-up` on an empty volume runs the init scripts in
# platform/clickhouse/init/ and creates the policy_decision table.
# Subsequent schema changes don't auto-apply — use `make clickhouse-reset`
# (wipes data) or apply platform/clickhouse/migrations/*.sql by hand via
# `make clickhouse-cli`, in filename order.

COMPOSE := docker compose -f platform/docker-compose.yml

.PHONY: clickhouse-up
clickhouse-up: ## Start the local ClickHouse server (creates schema on first run)
	$(COMPOSE) up -d clickhouse

.PHONY: clickhouse-down
clickhouse-down: ## Stop ClickHouse (keeps the data volume)
	$(COMPOSE) stop clickhouse

.PHONY: clickhouse-logs
clickhouse-logs: ## Tail ClickHouse server logs
	$(COMPOSE) logs -f clickhouse

.PHONY: clickhouse-cli
clickhouse-cli: ## Open an interactive SQL shell against the local ClickHouse
	docker exec -it hexgate-clickhouse clickhouse-client \
	    --user hexgate --password hexgate-dev-password --database hexgate_audit

.PHONY: clickhouse-reset
clickhouse-reset: ## Wipe ONLY the ClickHouse data volume and re-run init scripts
	$(COMPOSE) rm -sf clickhouse
	-docker volume rm platform_clickhouse-data
	$(COMPOSE) up -d clickhouse

# -------- Platform infra (Postgres control-plane DB) --------
#
# Control-plane DB (service in platform/docker-compose.yml).

# DSN matching the postgres service (host port 5433, committed dev creds).
POSTGRES_DSN ?= postgresql+asyncpg://hexgate:hexgate-dev-password@localhost:5433/hexgate

.PHONY: postgres-up
postgres-up: ## Start local Postgres and wait until healthy
	$(COMPOSE) up -d --wait postgres

.PHONY: postgres-stop
postgres-stop: ## Stop Postgres (keeps the data volume)
	$(COMPOSE) stop postgres

.PHONY: postgres-psql
postgres-psql: ## Open a psql shell against local Postgres
	docker exec -it hexgate-postgres psql -U hexgate -d hexgate

.PHONY: postgres-reset
postgres-reset: ## Wipe ONLY the Postgres data volume and restart
	$(COMPOSE) rm -sf postgres
	-docker volume rm platform_postgres-data
	$(COMPOSE) up -d --wait postgres

# -------- Platform infra (Redpanda — OTLP ingestion buffer) --------
#
# Single-node dev broker, Kafka-wire-protocol-compatible. Topics aren't
# auto-created on first boot — run `make redpanda-topics` once after
# `make redpanda-up`.

.PHONY: redpanda-up
redpanda-up: ## Start local Redpanda and wait until healthy
	$(COMPOSE) up -d --wait redpanda

.PHONY: redpanda-stop
redpanda-stop: ## Stop Redpanda (keeps the data volume)
	$(COMPOSE) stop redpanda

.PHONY: redpanda-topics
redpanda-topics: redpanda-up ## Create the hexgate.otlp.raw / hexgate.otlp.dlq topics (idempotent)
	docker cp platform/redpanda/init/create-topics.sh hexgate-redpanda:/tmp/create-topics.sh
	docker exec hexgate-redpanda bash /tmp/create-topics.sh

.PHONY: redpanda-list-topics
redpanda-list-topics: ## List topics on the local Redpanda broker
	docker exec hexgate-redpanda rpk topic list --brokers localhost:9092

.PHONY: redpanda-reset
redpanda-reset: ## Wipe ONLY the Redpanda data volume, restart, and recreate topics
	$(COMPOSE) rm -sf redpanda
	-docker volume rm platform_redpanda-data
	$(COMPOSE) up -d --wait redpanda
	$(MAKE) redpanda-topics

# -------- OTLP ingestion Collector (Go) --------
#
# platform/collector/builder-config.yaml is an ocb (OpenTelemetry
# Collector Builder) manifest — collector-generate regenerates the Go
# source + go.mod/go.sum from it (and compiles by default; ocb doesn't
# separate those two steps). Runs natively on the host for local dev,
# same convention as `make platform-api` — see platform/collector/config.yaml
# for why it points at localhost, not the redpanda:29092 container listener.
#
# The Biscuit auth extension under platform/collector/extension/ is its own Go
# module, wired in by builder-config.yaml's `replaces`, and the integration
# suite under platform/collector/integration/ is another. Nested modules are
# invisible to `./...` from platform/collector, so both get their own steps
# below.

COLLECTOR_BUILDER_VERSION := v0.158.0
COLLECTOR_EXT_BISCUITAUTH := platform/collector/extension/hexgatebiscuitauth
COLLECTOR_EXT_INTEGRATION := platform/collector/integration

.PHONY: collector-install-builder
collector-install-builder: ## One-time: install the ocb builder tool ($GOBIN)
	go install go.opentelemetry.io/collector/cmd/builder@$(COLLECTOR_BUILDER_VERSION)

.PHONY: collector-generate
collector-generate: ## Regenerate + compile the collector from builder-config.yaml
	cd platform/collector && builder --config=builder-config.yaml

.PHONY: collector-run
# The authenticator makes boot fatal without Postgres, the devtoken schema,
# and the root public key, so this target now provides the first two and
# checks for the third — the pre-auth collector booted on Redpanda alone.
.PHONY: enricher-run
enricher-run: redpanda-topics clickhouse-up ## Run the span-enricher job (Redpanda → ClickHouse)
	cd platform/api && uv run python -m hexgate_api.jobs.enricher

collector-run: postgres-up redpanda-topics ## Run the collector binary against config.yaml
	cd platform/api && DATABASE_URL=$(POSTGRES_DSN) uv run python -c \
		"import asyncio; from hexgate_api.core.db import init_db; asyncio.run(init_db())"
	@test -f platform/api/data/hexgate.pub \
		|| { echo "platform/api/data/hexgate.pub is missing — run 'make platform-api' once to generate the root keypair, or set HEXGATE_COLLECTOR_PUBLIC_KEY_FILE"; exit 1; }
	cd platform/collector && ./hexgate-collector --config=config.yaml

.PHONY: collector-test
collector-test: ## Unit tests for the collector's own Go modules
	cd $(COLLECTOR_EXT_BISCUITAUTH) && go test -race ./...

# Opt-in, like the Python side's `pytest -m integration`: these drive the real
# binary against a real Postgres and Redpanda, so they are kept out of
# collector-check. The schema belongs to platform-api, so it is created here
# rather than by the Go tests.
.PHONY: collector-test-integration
collector-test-integration: postgres-up redpanda-topics ## Collector integration tests (real Postgres + Redpanda)
	cd platform/collector && go build -o hexgate-collector ./...
	cd platform/api && DATABASE_URL=$(POSTGRES_DSN) uv run python -c \
		"import asyncio; from hexgate_api.core.db import init_db; asyncio.run(init_db())"
	cd $(COLLECTOR_EXT_INTEGRATION) && go test -tags integration -count=1 ./...

.PHONY: collector-check
collector-check: ## Vet + test + build the collector, validate config.yaml (no ocb regeneration)
	cd $(COLLECTOR_EXT_BISCUITAUTH) && gofmt -l . | (! grep .)
	cd $(COLLECTOR_EXT_BISCUITAUTH) && go vet ./...
	cd $(COLLECTOR_EXT_BISCUITAUTH) && go test -race ./...
	cd $(COLLECTOR_EXT_INTEGRATION) && gofmt -l . | (! grep .)
	cd $(COLLECTOR_EXT_INTEGRATION) && go vet -tags integration ./...
	cd platform/collector && go vet ./...
	cd platform/collector && go build -o hexgate-collector ./...
	cd platform/collector && ./hexgate-collector validate --config=config.yaml

# -------- Platform API (FastAPI control plane) --------
#
# The platform API is a separate uv project under platform/api/ with its
# own pyproject.toml. We invoke uv from there directly so it uses the
# platform's venv, not the SDK's.

.PHONY: platform-api-install
platform-api-install: ## Install platform API deps (first time)
	cd platform/api && uv sync --group dev

.PHONY: platform-api
platform-api: ## Run the platform API dev server (FastAPI on :8000, SQLite)
	cd platform/api && uv run uvicorn hexgate_api.main:app --reload --port 8000

.PHONY: platform-api-pg
platform-api-pg: postgres-up ## Run the platform API against local Postgres (starts PG first)
	cd platform/api && DATABASE_URL=$(POSTGRES_DSN) uv run uvicorn hexgate_api.main:app --reload --port 8000

.PHONY: platform-api-test
platform-api-test: ## Run the platform API test suite
	cd platform/api && uv run pytest tests/

.PHONY: platform-api-test-integration
platform-api-test-integration: clickhouse-up ## Platform API integration tests (needs ClickHouse only, see .claude/skills/integration-tests)
	cd platform/api && uv run pytest -m integration

.PHONY: seed-audit
seed-audit: ## Seed ClickHouse with audit test data (anomaly detection)
	cd platform/api && uv run python ../scripts/seed_audit.py

.PHONY: seed-audit-clear
seed-audit-clear: ## Clear seeded audit test data
	cd platform/api && uv run python ../scripts/seed_audit.py --clear

# -------- Dashboard (Vite + React) --------
#
# Uses pnpm. `pnpm dev` runs Vite on :5173 and proxies /v1/* to :8000,
# so the dashboard needs the platform-api target running in another
# terminal.

.PHONY: dashboard-install
dashboard-install: ## Install dashboard JS deps (first time)
	cd platform/dashboard && pnpm install

.PHONY: dashboard
dashboard: ## Run the dashboard dev server (Vite on :5173)
	cd platform/dashboard && pnpm dev

.PHONY: dashboard-fmt
dashboard-fmt: ## Format dashboard TypeScript with prettier
	cd platform/dashboard && pnpm format

.PHONY: dashboard-fmt-check
dashboard-fmt-check: ## Check dashboard TypeScript formatting (prettier)
	cd platform/dashboard && pnpm format:check

.PHONY: dashboard-lint
dashboard-lint: ## Lint dashboard TypeScript with eslint
	cd platform/dashboard && pnpm lint

.PHONY: dashboard-typecheck
dashboard-typecheck: ## Typecheck dashboard TypeScript
	cd platform/dashboard && pnpm typecheck

# -------- Production deploy (build on target) --------
#
# STAGE selects the env: project hexgate-<stage> + platform/.env.<stage>, each an
# isolated stack. Defaults to staging so prod must be named explicitly. Ports come
# from HEXGATE_HTTP_PORT in the env file. Full runbook: platform/DEPLOY.md.
STAGE ?= staging
DEPLOY_COMPOSE = docker compose -p hexgate-$(STAGE) --env-file platform/.env.$(STAGE) -f platform/docker-compose.deploy.yml

# The env file is pulled from Scaleway (secret /hexgate/<stage>), not hand-copied.
.PHONY: platform-env-pull
platform-env-pull: ## Pull platform/.env.<stage> from Scaleway: make platform-env-pull STAGE=prod
	@bash platform/scripts/env-secret.sh $(STAGE)

# Auto-pull only a missing env file; an existing one is left untouched
# (`make platform-env-pull` to force a refresh).
.PHONY: _require-stage-env
_require-stage-env:
	@test -f platform/.env.$(STAGE) || $(MAKE) platform-env-pull STAGE=$(STAGE)

.PHONY: platform-up
platform-up: _require-stage-env ## Build + (re)start a deploy stack: make platform-up STAGE=prod (default staging)
	$(DEPLOY_COMPOSE) up -d --build

.PHONY: platform-down
platform-down: _require-stage-env ## Stop a deploy stack, keeps volumes: make platform-down STAGE=prod
	$(DEPLOY_COMPOSE) down

.PHONY: platform-logs
platform-logs: _require-stage-env ## Tail a deploy stack's logs: make platform-logs STAGE=prod
	$(DEPLOY_COMPOSE) logs -f

# -------- SDK → platform bridge --------

# Make's rule parser treats colons specially, so a positional
# `make serve examples.foo:bar` won't work — the colon makes Make
# read it as a target+prerequisite. Two clean ways to pick a
# different agent:
#
#   make serve AGENT_SPEC=examples.foo:bar        # variable form
#   uv run hexgate serve examples.foo:bar         # skip make entirely
#
# Bare `make serve` defaults to the customer_bot demo for the
# hexgate-canonical workflow.
AGENT_SPEC ?= examples.customer_bot:agent

.PHONY: serve
serve: ## Run `hexgate serve` on the customer_bot demo (override with AGENT_SPEC=)
# Reads HEXGATE_API_KEY from the repo-root .env at startup. Uvicorn-style spec —
# the agent name + tools come from the loaded object, no env vars to
# keep in sync.
	$(UV) hexgate serve $(AGENT_SPEC)

# -------- Full platform demo (multi-terminal) --------

.PHONY: demo-platform
demo-platform: ## Print 3-terminal instructions for the full platform demo
	@echo ""
	@echo "Platform demo — open three terminals at the repo root:"
	@echo ""
	@echo "  Terminal 1 — FastAPI backend (control plane):"
	@echo "      make platform-api"
	@echo ""
	@echo "  Terminal 2 — dashboard (Vite + React, http://localhost:5173):"
	@echo "      make dashboard"
	@echo ""
	@echo "  Terminal 3 — your local agent bridged to the platform:"
	@echo "      1. Open  http://localhost:5173/tokens  and mint a dev token"
	@echo "      2. Add to the repo-root .env:  HEXGATE_API_KEY=fty_live_..."
	@echo "      3. make serve  (or: hexgate serve <your.module:agent>)"
	@echo ""
	@echo "Then chat with the live agent at  http://localhost:5173/playground"
	@echo ""
	@echo "First-time setup (run once):"
	@echo "      make platform-api-install"
	@echo "      make dashboard-install"
	@echo ""

# -------- Bundled notebook demo (one process locally / per-container on Modal) --------
#
# Unlike `demo-platform` (3 terminals, manual login + token), this bundles the
# whole thing into one process: the API serves the built dashboard same-origin,
# auto-seeds + auto-logs-in, and a marimo notebook owns `hexgate serve`. The
# visitor brings their own OpenAI key (BYOK). This is also what runs per visitor
# in the public demo (a Daytona sandbox). See deploy/README.md.

.PHONY: demo-notebook-build
demo-notebook-build: platform-api-install dashboard-install ## One-time setup for `make demo-notebook` (deps + marimo + dashboard build)
	uv pip install --python platform/api/.venv marimo
	cd platform/dashboard && pnpm build

.PHONY: demo-notebook
demo-notebook: ## Run the bundled BYOK demo locally (one process). Open http://localhost:2718
	PATH="$(CURDIR)/platform/api/.venv/bin:$$PATH" \
	  HEXGATE_DEMO=1 HEXGATE_COOKIE_SECURE=0 \
	  python deploy/boot.py

.PHONY: demo-smoke
demo-smoke: ## Smoke-test the bundled demo with a mock LLM (no real key)
	cd platform/api && uv run python "$(CURDIR)/deploy/smoke_test.py"

# -------- Package --------

.PHONY: build
build: ## Build sdist + wheel into dist/
	uv build

.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
