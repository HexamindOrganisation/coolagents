# API — Claude Code Instructions

After you make changes, run: `make fmt-check && make platform-api-check`  # fmt-check + lint + tests with coverage

## Layout (`hexgate_api/`)
- `main.py` — `create_app()` factory + router wiring only.
- `constants.py` — shared seed identity (`DEFAULT_*`) + role names (`ROLE_*`).
- `core/` — infra: `db`, `keystore` (holds the process-wide signing singleton), `biscuits`, `clickhouse`, `relay`, `mailer`, `spa`, `ids`.
- `deps/` — FastAPI dependency gates: `identity`, `tokens`, `org`, `project`, `ws`, `clickhouse`.
- `seeds/defaults.py` — first-boot triple-default seeding (agent seed data lives in `features/agents/seed_data.py`).
- `features/<x>/` — one vertical slice per context (`tokens`, `projects`, `members`, `orgs`, `invitations`, `agents`, `audit`, `chat`, `auth`), each a `router.py` + `service.py` (agents also `compiler.py`). Domain exceptions live in their `service.py`; exceptions shared across features live with the shared machinery that raises them (e.g. `AuditSchemaOutOfDate` in `core/clickhouse.py`, `EventOutOfWindow` in `query_scope.py`).
- `schemas.py` / `models.py` — shared Pydantic DTOs / SQLModel tables.
- `tests/` mirrors this: `tests/features/<x>/`, `tests/core/`.

## Fixed UUIDs (`constants.py`)
- Org: `00000000-0000-0000-0000-000000000001`
- User: `00000000-0000-0000-0000-000000000002`
- Project: `00000000-0000-0000-0000-000000000003`
