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
| **Platform demo** (multi-terminal — see `make demo-platform`) | |
| `platform-api` / `platform-api-install` / `platform-api-test` | FastAPI control plane in `platform/api/` |
| `dashboard` / `dashboard-install` | Vite + React app in `platform/dashboard/` |
| `serve` | `hexgate serve` — bridge this SDK to the platform |
| `demo-platform` | Print the 3-terminal recipe |
| **Misc** | |
| `build` / `clean` | Package + tidy |

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
