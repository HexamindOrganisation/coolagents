"""Tests for the kill-switch ban feature: dashboard CRUD, the SDK active-ban
feed (ETag/304), and tenant isolation. Fixtures mirror test_projects.py."""

from __future__ import annotations

import asyncio
import uuid

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import ROLE_MEMBER
from hexgate_api.core import keystore as keystore_mod
from hexgate_api.main import app
from hexgate_api.models import OrganizationMember, User
from hexgate_api.seeds.defaults import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures / helpers
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


def _signup_and_login(client: TestClient, email: str, password: str) -> None:
    r = client.post("/v1/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    r = client.post(
        "/v1/auth/cookie/login", data={"username": email, "password": password}
    )
    assert r.status_code == 204, r.text


def _make_project(
    client: TestClient,
    *,
    email: str = "owner@example.com",
    password: str = "correcthorsebattery",
    name: str = "proj",
) -> str:
    """Sign up (becomes owner of a personal org), create a project, return its id."""
    _signup_and_login(client, email, password)
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _add_member_to_org(
    session_factory, *, email: str, org_id: str, role: str
) -> str:
    async with session_factory() as s:
        existing = (await s.exec(select(User).where(User.email == email))).first()
        if existing is None:
            existing = User(email=email)
            s.add(existing)
            await s.commit()
            await s.refresh(existing)
        s.add(
            OrganizationMember(
                id=str(uuid.uuid4()), user_id=existing.id, org_id=org_id, role=role
            )
        )
        await s.commit()
        return existing.id


def _use_bearer_project(project_id: str) -> None:
    """Point the SDK feed's bearer auth at a project (biscuit path stubbed)."""
    from hexgate_api.deps.tokens import require_project

    app.dependency_overrides[require_project] = lambda: project_id


# ---------------------------------------------------------------------------
# POST /v1/projects/{id}/bans
# ---------------------------------------------------------------------------


def test_create_agent_ban_succeeds(client: TestClient) -> None:
    pid = _make_project(client)
    r = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "support-bot", "reason": "x"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ban_type"] == "agent"
    assert body["target_agent_name"] == "support-bot"
    assert body["target_user_id"] is None
    assert body["active"] is True
    assert body["revoked_at"] is None
    assert body["created_by_user_id"]  # audit trail recorded
    assert body["id"].startswith("ban_")


def test_create_user_ban_succeeds(client: TestClient) -> None:
    pid = _make_project(client)
    r = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "user", "target_user_id": "user-42"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["ban_type"] == "user"
    assert body["target_user_id"] == "user-42"
    assert body["target_agent_name"] is None


def test_create_ban_mismatched_target_rejected(client: TestClient) -> None:
    """ban_type/target mismatch is a 422 (schema-level) before the service."""
    pid = _make_project(client)
    # agent ban carrying a user target
    r = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_user_id": "u1"},
    )
    assert r.status_code == 422
    # user ban with no target at all
    r = client.post(f"/v1/projects/{pid}/bans", json={"ban_type": "user"})
    assert r.status_code == 422


def test_create_ban_duplicate_active_conflicts(client: TestClient) -> None:
    pid = _make_project(client)
    body = {"ban_type": "agent", "target_agent_name": "dupe"}
    assert client.post(f"/v1/projects/{pid}/bans", json=body).status_code == 201
    r = client.post(f"/v1/projects/{pid}/bans", json=body)
    assert r.status_code == 409
    assert "already exists" in r.json()["detail"].lower()


def test_create_ban_403_for_plain_member(client: TestClient, session_factory) -> None:
    """Plain members can't create bans — require_project_admin fires."""
    pid = _make_project(client)
    org_id = client.get("/v1/orgs").json()[0]["id"]
    member_id = asyncio.get_event_loop().run_until_complete(
        _add_member_to_org(
            session_factory, email="lowly@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )
    client.cookies.clear()
    r = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "x"},
        headers={"X-Dev-User": member_id},
    )
    assert r.status_code == 403
    assert "admin or owner" in r.json()["detail"].lower()


def test_create_ban_403_for_non_member(client: TestClient) -> None:
    """User B can't create bans in User A's project."""
    pid = _make_project(client, email="ownerA@example.com")
    client.cookies.clear()
    _signup_and_login(client, "strangerB@example.com", "correcthorsebattery")
    r = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "x"},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /v1/projects/{id}/bans
# ---------------------------------------------------------------------------


def test_list_bans_active_only_by_default(client: TestClient) -> None:
    pid = _make_project(client)
    a = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "keep"},
    ).json()
    b = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "user", "target_user_id": "gone"},
    ).json()
    client.delete(f"/v1/projects/{pid}/bans/{b['id']}")

    active = client.get(f"/v1/projects/{pid}/bans").json()
    assert {row["id"] for row in active} == {a["id"]}

    allrows = client.get(f"/v1/projects/{pid}/bans?include_revoked=true").json()
    assert {row["id"] for row in allrows} == {a["id"], b["id"]}
    revoked = next(row for row in allrows if row["id"] == b["id"])
    assert revoked["active"] is False
    assert revoked["revoked_at"] is not None


def test_list_bans_403_for_non_member(client: TestClient) -> None:
    pid = _make_project(client, email="ownerC@example.com")
    client.cookies.clear()
    _signup_and_login(client, "strangerC@example.com", "correcthorsebattery")
    assert client.get(f"/v1/projects/{pid}/bans").status_code == 403


# ---------------------------------------------------------------------------
# DELETE /v1/projects/{id}/bans/{ban_id}
# ---------------------------------------------------------------------------


def test_revoke_ban_returns_204_and_deactivates(client: TestClient) -> None:
    pid = _make_project(client)
    ban_id = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "revoke-me"},
    ).json()["id"]

    r = client.delete(f"/v1/projects/{pid}/bans/{ban_id}")
    assert r.status_code == 204
    assert client.get(f"/v1/projects/{pid}/bans").json() == []


def test_revoke_unknown_ban_404(client: TestClient) -> None:
    pid = _make_project(client)
    r = client.delete(f"/v1/projects/{pid}/bans/ban_deadbeef")
    assert r.status_code == 404


def test_revoke_ban_cross_project_404(client: TestClient) -> None:
    """A ban created in project A can't be revoked through project B's path."""
    p_a = _make_project(client, name="proj-a")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    p_b = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "proj-b"}).json()[
        "id"
    ]
    ban_id = client.post(
        f"/v1/projects/{p_a}/bans",
        json={"ban_type": "agent", "target_agent_name": "a"},
    ).json()["id"]

    r = client.delete(f"/v1/projects/{p_b}/bans/{ban_id}")
    assert r.status_code == 404
    # And it's still active under project A.
    assert len(client.get(f"/v1/projects/{p_a}/bans").json()) == 1


# ---------------------------------------------------------------------------
# GET /v1/bans — SDK active-ban feed (bearer)
# ---------------------------------------------------------------------------


def test_feed_returns_active_bans_only_minimal_shape(client: TestClient) -> None:
    pid = _make_project(client)
    active = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "a1", "reason": "why"},
    ).json()
    revoked = client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "user", "target_user_id": "u-gone"},
    ).json()
    client.delete(f"/v1/projects/{pid}/bans/{revoked['id']}")

    _use_bearer_project(pid)
    r = client.get("/v1/bans")
    assert r.status_code == 200
    entries = r.json()
    assert len(entries) == 1
    # Carries ban_id (so enforcement events link back); no created_by/timestamps.
    assert set(entries[0].keys()) == {
        "ban_id",
        "ban_type",
        "target_agent_name",
        "target_user_id",
        "reason",
    }
    assert entries[0]["target_agent_name"] == "a1"
    assert entries[0]["ban_id"] == active["id"]


def test_feed_etag_304_then_changes(client: TestClient) -> None:
    pid = _make_project(client)
    client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "agent", "target_agent_name": "a1"},
    )
    _use_bearer_project(pid)

    r1 = client.get("/v1/bans")
    assert r1.status_code == 200
    etag = r1.headers["ETag"]

    r2 = client.get("/v1/bans", headers={"If-None-Match": etag})
    assert r2.status_code == 304

    # Adding a ban changes the feed → new ETag, 200 again.
    client.post(
        f"/v1/projects/{pid}/bans",
        json={"ban_type": "user", "target_user_id": "u1"},
    )
    r3 = client.get("/v1/bans", headers={"If-None-Match": etag})
    assert r3.status_code == 200
    assert r3.headers["ETag"] != etag


def test_feed_empty_returns_stable_etag(client: TestClient) -> None:
    pid = _make_project(client)
    _use_bearer_project(pid)
    r = client.get("/v1/bans")
    assert r.status_code == 200
    assert r.json() == []
    assert "ETag" in r.headers
