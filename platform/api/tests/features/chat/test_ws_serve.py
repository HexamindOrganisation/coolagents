"""Tests for ``WS /v1/serve`` — the token-implicit serve socket.

The Phase 6 design moves project context from the URL into the bearer
token. The CLI's ``hexgate serve`` connects via the
``bearer.<envelope>`` subprotocol; the server echoes ``hexgate.v1`` on
a successful handshake and resolves the project from the token row.

Five branches, one per test:

  1. No subprotocol header offered           → close 4401, no handshake
  2. Subprotocol present but no ``bearer.``  → close 4401
  3. ``bearer.`` malformed (bad signature)   → close 4401
  4. ``bearer.`` revoked / unknown secret    → close 4401
  5. Happy path                              → handshake completes,
                                                relay registers the
                                                serve socket under the
                                                token's project

The legacy ``/v1/projects/{id}/serve`` route was removed in Phase 6
step 3; this file is the sole coverage of the serve socket. The
legacy route never had its own tests — going away was a no-op for
the test suite.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette.websockets import WebSocketDisconnect

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.main import app
from hexgate_api.features.tokens.service import mint_api_key
from hexgate_api.seeds.defaults import ensure_default_project
from hexgate_api.constants import DEFAULT_PROJECT_ID


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory():
    """In-memory async SQLite with the schema + triple-default seed."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as bootstrap:
        await ensure_default_project(bootstrap)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def client(session_factory, tmp_path) -> TestClient:
    """TestClient with the test factory + fresh keystore."""
    from hexgate_api.core.db import get_session
    from hexgate_api.core.keystore import FileKeyStore

    async def override_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    original_keystore = keystore_mod.keystore
    keystore_mod.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    keystore_mod.keystore.ensure_keypair()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        keystore_mod.keystore = original_keystore


@pytest_asyncio.fixture
async def fresh_token(session_factory) -> str:
    """Mint a real biscuit-backed API key for the default project.

    Returns the full ``fty_<env>_<project>_<biscuit>`` envelope ready
    to drop into the ``bearer.<...>`` subprotocol.
    """
    async with session_factory() as session:
        _row, full = await mint_api_key(
            session,
            DEFAULT_PROJECT_ID,
            name="ws-test-key",
            scopes=["read"],
            env="live",
            # Pull the raw private bytes the same way mint_token in
            # main.py does. ``_private_key_bytes`` is internal but
            # tests are entitled to reach in.
            signing_key_bytes=keystore_mod.keystore._private_key_bytes(),
        )
        await session.commit()
    return full


# ---------------------------------------------------------------------------
# Reject paths
# ---------------------------------------------------------------------------


def test_ws_serve_rejects_when_no_subprotocol_offered(client: TestClient) -> None:
    """No subprotocols at all → close 4401 before accept.

    The legacy route would have happily accepted this with project_id
    from the URL; the new route refuses because there's no way to
    authenticate. The CLI must offer ``bearer.<key>`` to get in.
    """
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/v1/serve"):
            pass
    assert exc_info.value.code == 4401


def test_ws_serve_rejects_when_no_bearer_subprotocol(client: TestClient) -> None:
    """Subprotocols offered but none start with ``bearer.`` → 4401.

    Defensive against a client that offers ``hexgate.v1`` alone without
    actually authenticating — the marker subprotocol is a server-side
    echo, not a substitute for credentials.
    """
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/v1/serve", subprotocols=["hexgate.v1"]):
            pass
    assert exc_info.value.code == 4401


def test_ws_serve_rejects_when_bearer_is_garbage(client: TestClient) -> None:
    """``bearer.`` present but the value isn't a valid envelope → 4401.

    Covers the signature-gate path: parse_envelope/verify_token
    raise TokenError or TokenSignatureError, the handshake closes,
    no info leaked back to the client beyond the close code.
    """
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
            "/v1/serve",
            subprotocols=["bearer.fty_live_not_a_real_token", "hexgate.v1"],
        ):
            pass
    assert exc_info.value.code == 4401


def test_ws_serve_rejects_unknown_or_revoked_secret(
    client: TestClient, fresh_token: str, session_factory
) -> None:
    """Bearer parses cleanly but isn't in the ApiKey table → 4401.

    Synthesises this by minting a token, then deleting the row before
    the connection attempt — same shape as a revoke + reuse race.
    """
    import asyncio

    from hexgate_api.models import ApiKey
    from sqlmodel import select

    async def _delete_token():
        async with session_factory() as session:
            row = (
                await session.exec(select(ApiKey).where(ApiKey.secret == fresh_token))
            ).first()
            assert row is not None
            await session.delete(row)
            await session.commit()

    asyncio.get_event_loop().run_until_complete(_delete_token())

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
            "/v1/serve",
            subprotocols=[f"bearer.{fresh_token}", "hexgate.v1"],
        ):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_ws_serve_happy_path_registers_with_project_from_token(
    client: TestClient, fresh_token: str
) -> None:
    """A valid bearer in the subprotocol → handshake completes, the
    serve socket gets registered against the token's project."""
    from hexgate_api.core.relay import registry

    # Track the project the relay sees so we can assert post-hoc that
    # ws_require_project resolved to the right value.
    seen: dict[str, str] = {}
    original_attach = registry.attach_serve

    async def spy_attach(project_id, ws):
        seen["project_id"] = project_id
        return await original_attach(project_id, ws)

    registry.attach_serve = spy_attach  # type: ignore[assignment]

    try:
        with client.websocket_connect(
            "/v1/serve",
            subprotocols=[f"bearer.{fresh_token}", "hexgate.v1"],
        ) as ws:
            # Starlette's TestClient exposes the accepted subprotocol on
            # the WebSocket wrapper — confirm the server echoed the
            # marker and consumed the bearer (didn't echo it).
            assert ws.accepted_subprotocol == "hexgate.v1"
    finally:
        registry.attach_serve = original_attach  # type: ignore[assignment]

    assert seen.get("project_id") == DEFAULT_PROJECT_ID
