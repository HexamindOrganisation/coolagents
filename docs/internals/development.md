# Development & testing

A `Makefile` at the repo root wraps the day-to-day commands so you don't have to
remember the `uv` incantations.

```bash
make help            # list every target with descriptions
make install-dev     # uv sync --extra dev (first time only)
make test            # full SDK test suite, quiet
make check           # lint + fmt-check + test (matches CI)
make test-one T=tests/security/test_bundle.py   # single file
```

## Targets at a glance

| Target | What it runs |
|---|---|
| **SDK dev loop** | |
| `test` / `test-verbose` / `test-failed` / `test-one` | `pytest tests/` with various flags |
| `lint` / `lint-fix` | `ruff check` (with `--fix` for autofixes) |
| `fmt` / `fmt-check` | `ruff format` |
| `check` | `lint` + `fmt-check` + `test` — pre-push gate |
| **Policy demo** | |
| `policy-build` | Compile the example policy.yaml to a bundle |
| `policy-test-wasm` | Smoke a WASM-engine decision |
| `demo-override` | Build a deny bundle + chat with `HEXGATE_LOCAL_POLICY` |
| **Platform** (multi-terminal — see below, or `make demo-platform`) | |
| `platform-api-pg` / `platform-api` | FastAPI control plane in `platform/api/`, on Postgres / on SQLite |
| `collector-run` | The OTLP collector (starts Redpanda, creates the topics) |
| `enricher-run` | The span-enricher, Redpanda → ClickHouse (starts ClickHouse) |
| `dashboard` / `dashboard-install` | Vite + React app in `platform/dashboard/` |
| `serve` | `hexgate serve` — bridge this SDK to the platform |
| `platform-api-install` / `platform-api-test` | Deps / unit tests for the API |
| `demo-platform` | Print the multi-terminal recipe |
| **Misc** | |
| `build` / `clean` | Package + tidy |

## Run the platform locally

The platform is five processes. Three of them make up the audit pipeline, and
an agent run without them looks fine while its audit trail silently 404s, so
start all of them. Each `make` target starts the Docker infrastructure it
needs (Postgres, Redpanda, ClickHouse) and then blocks, one terminal each:

```bash
make platform-api-pg      # 1. API on :8000, on Postgres — NOT `platform-api`: the collector
                          #    checks key revocation in Postgres, so keys minted by a SQLite
                          #    API are rejected with 401
make collector-run        # 2. OTLP receiver on :4318 (needs the keypair the API wrote on first boot)
make enricher-run         # 3. Redpanda → ClickHouse
make dashboard            # 4. http://localhost:5173
```

Then mint a key at <http://localhost:5173/tokens> and give it to the SDK. There
is no reverse proxy locally, so the SDK also needs to be told where the
collector is; on a deployed stage the proxy routes `/v1/traces` and this line
is unnecessary:

```bash
# repo-root .env (read by `make serve` and the SDK)
HEXGATE_API_KEY=fty_live_...
HEXGATE_API_URL=http://localhost:8000
HEXGATE_OTLP_ENDPOINT=http://localhost:4318/v1/traces
```

```bash
make serve                # 5. bridge the demo agent; chat at http://localhost:5173/playground
```

Every decision the agent makes shows up on the dashboard's audit page a few
seconds later (the collector batches for 5 s). To check the pipeline without an
agent, `HEXGATE_API_URL=http://localhost:8000 make platform-smoke` sends one of
every event type and reads them back. `deploy/provision.py` mints a key from the
command line when you don't want to go through the dashboard — the
`integration-tests` skill uses it.

First-time setup: `make platform-api-install`, `make dashboard-install`, and a
collector binary from `make collector-generate`.

Unset `HEXGATE_API_KEY` / `HEXGATE_API_URL` / `HEXGATE_OTLP_ENDPOINT` before
running the unit suite: some tests assert that no platform is configured.

## Using an existing virtualenv

By default `uv` manages its own `.venv` (created by `make install-dev`). If you
keep your dev environment elsewhere — e.g. a `micromamba` env — point `uv` at it
once and `make` picks it up:

```bash
export UV_PROJECT_ENVIRONMENT=/Users/<you>/micromamba/envs/<your-env>
uv sync --extra dev           # one-time: install dev deps into that env
make test                     # now runs against the micromamba env
```

Drop the `export` into your shell rc (or a `direnv` `.envrc`) and forget about it.
Without `--extra dev`, `pytest-asyncio` is missing and you'll see *"async
functions are not natively supported"* across every async test — same trap on a
fresh env.

## Platform-side test suite

The platform-side test suite is separate and lives at `platform/api/tests/`:

```bash
cd platform/api && uv run pytest tests/
```
