"""Tests for ``WS /v1/projects/{id}/chat`` — cookie-authed consumer socket.

The dashboard's Playground page drives this WebSocket from JavaScript.
Browsers can't set custom headers (e.g. ``Sec-WebSocket-Protocol`` from
``ws_serve``) on WS upgrades, so cookie auth is the only browser-
compatible option. The PR-#23 review caught that the route was wide
open: any client who could guess a ``project_id`` could connect,
eavesdrop on agent traffic, and relay arbitrary JSON back to the
serve process — bypassing every org-membership gate elsewhere.

Five branches, one per test:

  1. No cookie at all                       → close 4401, no handshake
  2. Cookie + non-member of project's org   → close 4401
  3. Cookie + unknown project_id            → close 4401
  4. Cookie + member of project's org       → handshake completes
  5. Garbage cookie (bad signature)         → close 4401
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
from hexgate_api.constants import DEFAULT_PROJECT_ID
from hexgate_api.seeds.defaults import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures (mirror test_ws_serve.py's shape)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory():
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


def _register_and_login(client: TestClient, email: str) -> str:
    """Register + log a user in. Leaves the session cookie on the
    client's cookie jar so subsequent requests carry it. Returns the
    user id."""
    client.post(
        "/v1/auth/register",
        json={"email": email, "password": "correcthorsebattery"},
    )
    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": email, "password": "correcthorsebattery"},
    )
    assert r.status_code == 204, r.text
    me = client.get("/v1/users/me").json()
    return me["id"]


# ---------------------------------------------------------------------------
# Reject paths
# ---------------------------------------------------------------------------


def test_ws_chat_rejects_without_cookie(client: TestClient) -> None:
    """Anonymous handshake → close 4401 before accept.

    Pre-fix this connected silently. Anyone with a project_id could
    relay arbitrary JSON into a running serve session and read every
    decision streaming back.
    """
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(f"/v1/projects/{DEFAULT_PROJECT_ID}/chat"):
            pass
    assert exc_info.value.code == 4401


def test_ws_chat_rejects_garbage_cookie(client: TestClient) -> None:
    """A cookie that doesn't decode as a valid session JWT → 4401.

    Forging a session cookie shouldn't be enough; the cookie has to
    chain to the platform's session secret.
    """
    client.cookies.set("hexgate_session", "not.a.real.jwt")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(f"/v1/projects/{DEFAULT_PROJECT_ID}/chat"):
            pass
    assert exc_info.value.code == 4401


def test_ws_chat_rejects_authenticated_non_member(
    client: TestClient,
) -> None:
    """A real cookie session, but the user isn't a member of the org
    that owns this project → 4401. Cookie proves identity, not access.
    """
    # Fresh signup auto-creates a personal org with its own project,
    # but the user is NOT a member of the seed default project's org.
    _register_and_login(client, "outsider@example.com")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(f"/v1/projects/{DEFAULT_PROJECT_ID}/chat"):
            pass
    assert exc_info.value.code == 4401


def test_ws_chat_rejects_unknown_project(client: TestClient) -> None:
    """A real cookie + a project_id that doesn't exist → 4401.
    Defensive: the relay must not silently route under a fake id.
    """
    _register_and_login(client, "ghost@example.com")
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
            "/v1/projects/00000000-0000-0000-0000-deadbeef0000/chat"
        ):
            pass
    assert exc_info.value.code == 4401


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_ws_chat_accepts_org_member(client: TestClient, session_factory) -> None:
    """Cookie session + the user IS a member of the project's org →
    handshake completes, the relay registers the chat socket."""
    import asyncio

    from hexgate_api.models import OrganizationMember, User
    from hexgate_api.constants import DEFAULT_ORG_ID, ROLE_MEMBER
    from sqlmodel import select

    _register_and_login(client, "insider@example.com")

    # Add the user to the seed org as a member so the gate passes.
    async def _add_to_default_org():
        async with session_factory() as s:
            user = (
                await s.exec(select(User).where(User.email == "insider@example.com"))
            ).one()
            s.add(
                OrganizationMember(
                    user_id=user.id, org_id=DEFAULT_ORG_ID, role=ROLE_MEMBER
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_add_to_default_org())

    # Spy on the relay so we can assert the registration fired.
    from hexgate_api.core.relay import registry

    seen: dict[str, str] = {}
    original_attach = registry.attach_chat

    async def spy_attach(project_id, ws):
        seen["project_id"] = project_id
        return await original_attach(project_id, ws)

    registry.attach_chat = spy_attach  # type: ignore[assignment]

    try:
        with client.websocket_connect(f"/v1/projects/{DEFAULT_PROJECT_ID}/chat") as _ws:
            # Connection completed — that's the contract. Close cleanly.
            pass
    finally:
        registry.attach_chat = original_attach  # type: ignore[assignment]

    assert seen.get("project_id") == DEFAULT_PROJECT_ID
