"""Opt-in Postgres smoke test — the only coverage of the asyncpg path.

The rest of the suite runs on SQLite, so this is the only test that points
the real engine at a live PG and round-trips a row. Skipped unless
``DATABASE_URL`` names a Postgres DSN (set by the ``platform-api-postgres``
CI job, or locally via ``make postgres-up``).
"""

from __future__ import annotations

import os

import pytest
from sqlmodel import select

pytestmark = pytest.mark.skipif(
    "postgres" not in os.environ.get("DATABASE_URL", ""),
    reason="set DATABASE_URL to a Postgres DSN to run (see `make postgres-up`)",
)


async def test_schema_builds_and_round_trips_on_postgres() -> None:
    # Lazy import so the module still collects (and skips) if a bad
    # DATABASE_URL made the app's engine fail to build.
    from hexgate_api import models
    from hexgate_api.core.db import async_session_factory, engine, init_db

    # Guard against a misconfigured DATABASE_URL silently using SQLite.
    assert engine.url.drivername == "postgresql+asyncpg"

    await init_db()  # create_all against Postgres

    async with async_session_factory() as session:
        # Self-heal a row leaked by a prior run that failed before cleanup.
        await _delete_smoke_org(session)

        org = models.Organization(slug="pg-smoke", name="PG Smoke")
        session.add(org)
        await session.commit()

        try:
            fetched = await session.get(models.Organization, org.id)
            assert fetched is not None and fetched.slug == "pg-smoke"

            # exec() path too — the dialect-sensitive query layer.
            by_slug = (
                await session.exec(
                    select(models.Organization).where(
                        models.Organization.slug == "pg-smoke"
                    )
                )
            ).first()
            assert by_slug is not None and by_slug.id == org.id
        finally:
            # Clean up even on assertion failure, so reruns against a
            # persistent volume don't collide on the unique slug.
            await _delete_smoke_org(session)


async def _delete_smoke_org(session) -> None:
    """Delete the pg-smoke org if present."""
    from hexgate_api import models

    existing = (
        await session.exec(
            select(models.Organization).where(models.Organization.slug == "pg-smoke")
        )
    ).first()
    if existing is not None:
        await session.delete(existing)
        await session.commit()
