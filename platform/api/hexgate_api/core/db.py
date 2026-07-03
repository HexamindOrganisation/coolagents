"""Async SQLAlchemy engine + session factory.

``DATABASE_URL`` selects Postgres (asyncpg) in deployment; unset falls back
to a local SQLite file so dev and tests stay zero-setup.
"""

import os
from urllib.parse import quote

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api import API_ROOT

# The engine is built at import, before main's load_dotenv(), so load .env
# here too. Non-overriding, so real env vars still win.
load_dotenv()

DB_PATH = API_ROOT / "hexgate.db"
_DEFAULT_URL = f"sqlite+aiosqlite:///{DB_PATH}"


def _url_from_components() -> str | None:
    """Assemble the Postgres URL from ``HEXGATE_POSTGRES_*`` parts, or None.

    This is the deployment path: the operator supplies only the password
    (the rest match the fixed compose topology), and we percent-encode the
    user + password here so a secret containing ``@ : / # ?`` can't corrupt
    the URL. That removes the old footgun where the password had to be
    URL-safe because compose embedded it verbatim into ``DATABASE_URL``.
    """
    password = os.environ.get("HEXGATE_POSTGRES_PASSWORD", "")
    if not password:
        return None
    user = os.environ.get("HEXGATE_POSTGRES_USER", "hexgate")
    host = os.environ.get("HEXGATE_POSTGRES_HOST", "postgres")
    port = os.environ.get("HEXGATE_POSTGRES_PORT", "5432")
    name = os.environ.get("HEXGATE_POSTGRES_DB", "hexgate")
    # safe="" so every reserved char in user/password is escaped.
    return (
        f"postgresql+asyncpg://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@{host}:{port}/{name}"
    )


def _database_url() -> str:
    """Resolve the async DB URL.

    Precedence: an explicit ``DATABASE_URL`` (bare ``postgres(ql)://`` is
    rewritten to the ``asyncpg`` driver the async engine requires) → the
    component-assembled Postgres URL (deploy path) → the local SQLite
    fallback that keeps dev and tests zero-setup.
    """
    url = os.environ.get("DATABASE_URL", "").strip()
    if url:
        for prefix in ("postgresql://", "postgres://"):
            if url.startswith(prefix):
                return "postgresql+asyncpg://" + url[len(prefix) :]
        return url
    return _url_from_components() or _DEFAULT_URL


_url = _database_url()
_engine_kwargs: dict = {"echo": False}
# pre_ping catches connections dropped by a managed Postgres; on SQLite
# (in-process, no server-side reaping) it's pure overhead, so PG-only.
if "postgresql" in _url:
    _engine_kwargs["pool_pre_ping"] = True
engine = create_async_engine(_url, **_engine_kwargs)

# Session factory — used by ``get_session()`` and one-off scripts (seeds,
# tests). ``expire_on_commit=False`` keeps ORM objects usable after a
# commit without a refetch — the sync default expires every attribute
# and forces a re-load, which is doubly expensive on async.
async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def init_db() -> None:
    """Create all tables defined on ``SQLModel.metadata``.

    Called once at app startup via the lifespan handler. Idempotent —
    ``create_all`` skips tables that already exist. Prototype-phase
    migration story is still ``rm hexgate.db && restart``; Alembic
    lands when there's production data to preserve.
    """
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)


async def get_session():
    """FastAPI dependency that yields a per-request async session.

    Lives in ``db.py`` (not ``main.py``) so the auth layer can depend
    on it without inducing a cycle through ``main``. Every route
    handler in ``main.py`` continues to import it from here.
    """
    async with async_session_factory() as session:
        yield session
