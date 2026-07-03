"""Tests for the M3 Phase 4 step 5 project CRUD routes.

Covers create / list / read / rename across the org-scoped routes
(``POST/GET /orgs/{id}/projects``) and the project-id-scoped routes
(``GET/PATCH /projects/{id}``). The 409-on-duplicate-name rule is
pinned from both create and rename directions. Permission gates:

  * Create / list: any member (per the matrix; intent is to tighten later)
  * Read: any member
  * Rename: admin or owner only

Tenant isolation pinned by signing up two users in the same TestClient
and asserting Bob can't peek at Alice's project.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.main import app
from hexgate_api.models import OrganizationMember, User
from hexgate_api.constants import ROLE_ADMIN, ROLE_MEMBER
from hexgate_api.seeds.defaults import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures — mirror test_orgs.py / test_invites.py
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
    """Register + log in; cookie persists on the client for the next call."""
    r = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 201, r.text
    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": email, "password": password},
    )
    assert r.status_code == 204, r.text


async def _add_member_to_org(
    session_factory, *, email: str, org_id: str, role: str
) -> str:
    """Test helper: add (or create) a user as a member of an org.
    Returns the user id. The user lands without a password — sign-in
    via X-Dev-User (gated by the test conftest)."""
    async with session_factory() as s:
        existing = (await s.exec(select(User).where(User.email == email))).first()
        if existing is None:
            existing = User(email=email)
            s.add(existing)
            await s.commit()
            await s.refresh(existing)
        s.add(
            OrganizationMember(
                id=str(uuid.uuid4()),
                user_id=existing.id,
                org_id=org_id,
                role=role,
            )
        )
        await s.commit()
        return existing.id


# ---------------------------------------------------------------------------
# POST /v1/orgs/{id}/projects
# ---------------------------------------------------------------------------


def test_create_project_succeeds_for_member(client: TestClient) -> None:
    """The happy path: signed-in user creates a project in their own
    personal default org, gets back 201 + the row."""
    _signup_and_login(client, "founder@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r = client.post(
        f"/v1/orgs/{org_id}/projects",
        json={"name": "customer-bot"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "customer-bot"
    assert body["org_id"] == org_id
    assert body["id"]  # uuid issued


def test_create_project_403_for_non_member(client: TestClient) -> None:
    """User A creates an org; User B (different account) can't create
    projects in it. Same tenant-isolation rule as everywhere else."""
    _signup_and_login(client, "ownerA@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.cookies.clear()
    _signup_and_login(client, "strangerB@example.com", "correcthorsebattery")

    r = client.post(
        f"/v1/orgs/{org_id}/projects",
        json={"name": "sneaky"},
    )
    assert r.status_code == 403


def test_create_project_404_for_unknown_org(client: TestClient) -> None:
    """Unknown org id → 404. Don't leak existence by 403-only-on-known."""
    _signup_and_login(client, "scout@example.com", "correcthorsebattery")
    r = client.post(
        "/v1/orgs/00000000-0000-0000-0000-deadbeef0000/projects",
        json={"name": "void"},
    )
    assert r.status_code == 404


def test_create_project_409_on_duplicate_name(client: TestClient) -> None:
    """Second create with the same name in the same org → 409. The
    UI should prompt for a different name or offer to switch into
    the existing project."""
    _signup_and_login(client, "twice@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r1 = client.post(
        f"/v1/orgs/{org_id}/projects",
        json={"name": "shared-name"},
    )
    assert r1.status_code == 201
    r2 = client.post(
        f"/v1/orgs/{org_id}/projects",
        json={"name": "shared-name"},
    )
    assert r2.status_code == 409
    assert "already exists" in r2.json()["detail"].lower()


def test_create_project_with_same_name_in_different_orgs_allowed(
    client: TestClient,
) -> None:
    """The uniqueness is per-org. Two orgs each owning a "default"
    project is fine — the seeded support-bot is in one org, the
    user's personal default project (if they created one) is in another."""
    _signup_and_login(client, "multi@example.com", "correcthorsebattery")
    # Create a second org for the same user.
    r = client.post(
        "/v1/orgs",
        json={"name": "Second Org", "slug": "second-org"},
    )
    second_org_id = r.json()["id"]
    first_org_id = client.get("/v1/orgs").json()[0]["id"]
    # Same project name in both orgs — both succeed.
    r1 = client.post(
        f"/v1/orgs/{first_org_id}/projects",
        json={"name": "customer-bot"},
    )
    r2 = client.post(
        f"/v1/orgs/{second_org_id}/projects",
        json={"name": "customer-bot"},
    )
    assert r1.status_code == 201
    assert r2.status_code == 201


# ---------------------------------------------------------------------------
# GET /v1/orgs/{id}/projects
# ---------------------------------------------------------------------------


def test_list_projects_returns_org_projects(client: TestClient) -> None:
    """Lists projects from the requested org in creation order."""
    _signup_and_login(client, "lister@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(f"/v1/orgs/{org_id}/projects", json={"name": "p1"})
    client.post(f"/v1/orgs/{org_id}/projects", json={"name": "p2"})

    r = client.get(f"/v1/orgs/{org_id}/projects")
    assert r.status_code == 200
    names = [p["name"] for p in r.json()]
    assert names == ["p1", "p2"]


def test_list_projects_403_for_non_member(client: TestClient) -> None:
    _signup_and_login(client, "ownerC@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.cookies.clear()
    _signup_and_login(client, "strangerC@example.com", "correcthorsebattery")
    r = client.get(f"/v1/orgs/{org_id}/projects")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /v1/projects/{id}
# ---------------------------------------------------------------------------


def test_get_project_returns_detail_for_member(client: TestClient) -> None:
    _signup_and_login(client, "peek@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "reader"})
    pid = r.json()["id"]

    r = client.get(f"/v1/projects/{pid}")
    assert r.status_code == 200
    assert r.json()["id"] == pid
    assert r.json()["name"] == "reader"


def test_get_project_404_for_unknown(client: TestClient) -> None:
    """require_org_member returns 404 when the project id doesn't
    exist (doesn't leak via 403)."""
    _signup_and_login(client, "voider@example.com", "correcthorsebattery")
    r = client.get("/v1/projects/00000000-0000-0000-0000-deadbeef0000")
    assert r.status_code == 404


def test_get_project_403_for_non_member(client: TestClient) -> None:
    """User A's project isn't visible to User B."""
    _signup_and_login(client, "ownerD@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "private"})
    pid = r.json()["id"]
    client.cookies.clear()
    _signup_and_login(client, "strangerD@example.com", "correcthorsebattery")
    r = client.get(f"/v1/projects/{pid}")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# PATCH /v1/projects/{id}
# ---------------------------------------------------------------------------


def test_rename_project_succeeds_for_owner(client: TestClient) -> None:
    _signup_and_login(client, "renamer@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "old-name"})
    pid = r.json()["id"]

    r = client.patch(f"/v1/projects/{pid}", json={"name": "new-name"})
    assert r.status_code == 200
    assert r.json()["name"] == "new-name"


def test_rename_project_409_on_collision(client: TestClient) -> None:
    """Renaming to a name another project in the same org already has → 409."""
    _signup_and_login(client, "collider@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(f"/v1/orgs/{org_id}/projects", json={"name": "taken"})
    other = client.post(
        f"/v1/orgs/{org_id}/projects", json={"name": "rename-me"}
    ).json()["id"]

    r = client.patch(f"/v1/projects/{other}", json={"name": "taken"})
    assert r.status_code == 409


def test_rename_project_403_for_plain_member(
    client: TestClient, session_factory
) -> None:
    """Plain members can't rename. require_project_admin gate fires.

    Use X-Dev-User to assume the member identity (the helper-added
    member has no password)."""
    _signup_and_login(client, "ownerE@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    pid = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "no-touch"}).json()[
        "id"
    ]

    member_id = asyncio.get_event_loop().run_until_complete(
        _add_member_to_org(
            session_factory,
            email="lowly@example.com",
            org_id=org_id,
            role=ROLE_MEMBER,
        )
    )

    client.cookies.clear()
    r = client.patch(
        f"/v1/projects/{pid}",
        json={"name": "renamed-by-member"},
        headers={"X-Dev-User": member_id},
    )
    assert r.status_code == 403
    assert "admin or owner" in r.json()["detail"].lower()


def test_rename_project_succeeds_for_admin(client: TestClient, session_factory) -> None:
    """Admin (not just owner) can rename — matches the permission matrix."""
    _signup_and_login(client, "ownerF@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    pid = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "for-admin"}).json()[
        "id"
    ]

    admin_id = asyncio.get_event_loop().run_until_complete(
        _add_member_to_org(
            session_factory,
            email="adm@example.com",
            org_id=org_id,
            role=ROLE_ADMIN,
        )
    )

    client.cookies.clear()
    r = client.patch(
        f"/v1/projects/{pid}",
        json={"name": "renamed-by-admin"},
        headers={"X-Dev-User": admin_id},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "renamed-by-admin"


def test_rename_project_no_op_returns_200(client: TestClient) -> None:
    """Renaming to the same name is a 200, not a 409. Idempotent —
    a 'save' button that double-fires shouldn't error."""
    _signup_and_login(client, "idem@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    pid = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "same"}).json()["id"]

    r = client.patch(f"/v1/projects/{pid}", json={"name": "same"})
    assert r.status_code == 200


def test_rename_project_404_for_unknown(client: TestClient) -> None:
    _signup_and_login(client, "voider2@example.com", "correcthorsebattery")
    r = client.patch(
        "/v1/projects/00000000-0000-0000-0000-deadbeef0000",
        json={"name": "void"},
    )
    assert r.status_code == 404
