"""Tenant isolation tests for the M3 Phase 2 auth scaffolding.

These are the load-bearing safety net: every project-scoped route gates
on org membership, and a user from one org must never see another org's
data — even by guessing the UUID. The point of Phase 2 isn't real auth
(that's Phase 3); it's making the route surface tenant-aware so adding
real auth later is a swap-the-dependency change rather than a re-think.

The fixture provisions two complete tenants on a shared engine — Org A
and Org B, each with its own User + Project + agent — and asserts that
each tenant's user can reach only their own org. Cross-tenant requests
return 403; missing-auth requests return 401.
"""

from __future__ import annotations

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.main import app
from hexgate_api.models import Agent, Organization, OrganizationMember, Project, User
from hexgate_api.core.ids import new_id
from hexgate_api.bootstrap.seed import ensure_default_project
from hexgate_api.constants import DEFAULT_PROJECT_ID, DEFAULT_USER_ID


# ---------------------------------------------------------------------------
# Fixtures — two complete tenants on one engine
# ---------------------------------------------------------------------------


_ORG_A_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_USER_A_ID = "aaaaaaaa-0000-0000-0000-000000000002"
_PROJECT_A_ID = "aaaaaaaa-0000-0000-0000-000000000003"

_ORG_B_ID = "bbbbbbbb-0000-0000-0000-000000000001"
_USER_B_ID = "bbbbbbbb-0000-0000-0000-000000000002"
_PROJECT_B_ID = "bbbbbbbb-0000-0000-0000-000000000003"

_STRANGER_USER_ID = "cccccccc-0000-0000-0000-000000000002"


@pytest_asyncio.fixture
async def session_factory():
    """In-memory async SQLite + factory, with schema + triple-default seed."""
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
async def two_tenants(session_factory) -> dict:
    """Provision Org A + User A + Project A, and Org B + User B + Project B.

    Plus a stranger user that belongs to neither org — the third leg of
    the isolation test (logged-in but unauthorised). Returns a dict of
    the IDs for tests to reference.
    """
    async with session_factory() as s:
        # Org A
        s.add(Organization(id=_ORG_A_ID, slug="org-a", name="Org A"))
        s.add(User(id=_USER_A_ID, email="alice@a.local"))
        s.add(
            OrganizationMember(
                id=new_id_str("memA"),
                user_id=_USER_A_ID,
                org_id=_ORG_A_ID,
                role="owner",
            )
        )
        s.add(Project(id=_PROJECT_A_ID, org_id=_ORG_A_ID, name="project-a"))
        s.add(_seed_agent(_PROJECT_A_ID))

        # Org B
        s.add(Organization(id=_ORG_B_ID, slug="org-b", name="Org B"))
        s.add(User(id=_USER_B_ID, email="bob@b.local"))
        s.add(
            OrganizationMember(
                id=new_id_str("memB"),
                user_id=_USER_B_ID,
                org_id=_ORG_B_ID,
                role="owner",
            )
        )
        s.add(Project(id=_PROJECT_B_ID, org_id=_ORG_B_ID, name="project-b"))
        s.add(_seed_agent(_PROJECT_B_ID))

        # Stranger — exists, belongs to neither.
        s.add(User(id=_STRANGER_USER_ID, email="stranger@nowhere.local"))

        await s.commit()

    return {
        "org_a": _ORG_A_ID,
        "user_a": _USER_A_ID,
        "project_a": _PROJECT_A_ID,
        "org_b": _ORG_B_ID,
        "user_b": _USER_B_ID,
        "project_b": _PROJECT_B_ID,
        "stranger": _STRANGER_USER_ID,
    }


def new_id_str(prefix: str) -> str:
    """Local helper: deterministic-enough surrogate IDs for the fixture rows."""
    # Distinct from `services.new_id` so tests don't collide with real seed IDs.
    return f"{prefix}-{_id_counter()}"


def _seed_agent(project_id: str) -> Agent:
    """Minimal Agent row for the project — content doesn't matter; the
    isolation tests only care about reachability."""
    return Agent(
        id=new_id(Agent),
        project_id=project_id,
        name="default",
        agent_yaml="name: default\nmodel: gpt-5.4\nsystem_prompt: system.md\ntools: []\npolicy: policy.yaml\n",
        policy_yaml="version: 1\ndefault_policy:\n  mode: deny\ntools: {}\n",
        system_md="",
    )


_counter = {"n": 0}


def _id_counter() -> int:
    _counter["n"] += 1
    return _counter["n"]


@pytest_asyncio.fixture
async def client(session_factory) -> TestClient:
    """TestClient wired to the in-memory engine, no default header.

    Tests add the X-Dev-User header per-request so we can exercise the
    cross-tenant + missing-auth paths without re-instantiating the
    client three times.
    """

    async def override_session():
        async with session_factory() as session:
            yield session

    from hexgate_api.core.db import get_session

    app.dependency_overrides[get_session] = override_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Tests — the three paths that matter
# ---------------------------------------------------------------------------


def test_user_can_read_their_own_org(client: TestClient, two_tenants: dict) -> None:
    """The happy path: User A sends their UUID, asks for Org A's project → 200."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_a']}/agents",
        headers={"X-Dev-User": two_tenants["user_a"]},
    )
    assert r.status_code == 200


def test_user_cannot_read_other_org(client: TestClient, two_tenants: dict) -> None:
    """The load-bearing test: User A asks for Org B's project → 403.

    Even with a known project UUID, membership gates the read."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_b']}/agents",
        headers={"X-Dev-User": two_tenants["user_a"]},
    )
    assert r.status_code == 403


def test_user_without_membership_cannot_read(
    client: TestClient, two_tenants: dict
) -> None:
    """A real user (the stranger) who belongs to no org reaches no project."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_a']}/agents",
        headers={"X-Dev-User": two_tenants["stranger"]},
    )
    assert r.status_code == 403


def test_missing_header_returns_401(client: TestClient, two_tenants: dict) -> None:
    """No auth at all → 401, not 403. Distinguishes 'unknown caller' from
    'known caller, unauthorised'."""
    r = client.get(f"/v1/projects/{two_tenants['project_a']}/agents")
    assert r.status_code == 401


def test_unknown_user_returns_401(client: TestClient, two_tenants: dict) -> None:
    """A header pointing at a User that doesn't exist → 401."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_a']}/agents",
        headers={"X-Dev-User": "00000000-0000-0000-0000-deadbeef0000"},
    )
    assert r.status_code == 401


def test_nonexistent_project_returns_404(client: TestClient, two_tenants: dict) -> None:
    """A real user pointing at a project UUID that doesn't exist → 404,
    not 403. We don't leak project existence by 403'ing only on known IDs."""
    r = client.get(
        "/v1/projects/00000000-0000-0000-0000-000000000099/agents",
        headers={"X-Dev-User": two_tenants["user_a"]},
    )
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Dashboard get-agent route: GET /v1/projects/{p}/agents/{name}
# Cookie / X-Dev-User auth only; the SDK-facing bearer counterpart is at
# GET /v1/agents/{name} and tested in test_agents.py (Phase 6 step 1).
# ---------------------------------------------------------------------------


def test_get_agent_accepts_dashboard_user(
    client: TestClient, two_tenants: dict
) -> None:
    """A dashboard request with X-Dev-User goes through the membership gate."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_a']}/agents/default",
        headers={"X-Dev-User": two_tenants["user_a"]},
    )
    assert r.status_code == 200


def test_get_agent_rejects_cross_tenant_dashboard_user(
    client: TestClient, two_tenants: dict
) -> None:
    """User A can't peek into Org B even with a valid dashboard session."""
    r = client.get(
        f"/v1/projects/{two_tenants['project_b']}/agents/default",
        headers={"X-Dev-User": two_tenants["user_a"]},
    )
    assert r.status_code == 403


def test_get_agent_rejects_unauthenticated(
    client: TestClient, two_tenants: dict
) -> None:
    """No cookie AND no X-Dev-User → 401."""
    r = client.get(f"/v1/projects/{two_tenants['project_a']}/agents/default")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Seed sanity: the default user can reach the default project (the
# self-host path that `make platform-api` exercises out of the box).
# ---------------------------------------------------------------------------


def test_default_seed_user_reaches_default_project(client: TestClient) -> None:
    """No two_tenants fixture — just the bare engine + seed.

    Smokes the most common dev case: the dashboard sends DEFAULT_USER_ID,
    asks for the default project, and gets a 200 — no extra setup needed."""
    r = client.get(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents",
        headers={"X-Dev-User": DEFAULT_USER_ID},
    )
    assert r.status_code == 200
