"""Tests for the M3 Phase 4 organization service layer.

Covers the auto-personal-org-on-signup invariant + the helpers in
``services`` that the route layer (later in this phase) will hang
off: ``create_org``, ``list_orgs_for_user``, ``remove_member``,
``change_member_role``, ``_generate_unique_org_slug``.

The "always at least one owner" rule lives in services and surfaces
as ``LastOwnerError``; we pin it from both directions (removing the
last owner, demoting the last owner) so the route handlers in the
next step can wrap it confidently in HTTP 409.
"""

from __future__ import annotations

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api import main
from hexgate_api.main import app
from hexgate_api.models import Organization, OrganizationMember, User
from hexgate_api.constants import (
    DEFAULT_ORG_ID,
    ROLE_ADMIN,
    ROLE_MEMBER,
    ROLE_OWNER,
)
from hexgate_api.domains.members.service import (
    LastOwnerError,
    change_member_role,
    list_org_members,
    remove_member,
)
from hexgate_api.domains.orgs.service import (
    _email_to_slug_base,
    _generate_unique_org_slug,
    create_org,
    ensure_personal_default_org,
    list_orgs_for_user,
)
from hexgate_api.services import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures — mirror the test_auth pattern so the lifespan + seed are stable
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
    original_keystore = main.keystore
    main.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    main.keystore.ensure_keypair()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        main.keystore = original_keystore


# ---------------------------------------------------------------------------
# Pure helpers — no DB
# ---------------------------------------------------------------------------


def test_email_to_slug_base_strips_special_characters() -> None:
    """Dots, plus signs, and other non-alphanumerics collapse to dashes."""
    assert _email_to_slug_base("alice@example.com") == "alice"
    assert _email_to_slug_base("alice.smith@example.com") == "alice-smith"
    assert _email_to_slug_base("Alice.Smith+work@example.com") == "alice-smith-work"
    # Edge: empty/punct-only local part falls back to 'user'.
    assert _email_to_slug_base("__@x.com") == "user"


# ---------------------------------------------------------------------------
# Slug uniqueness — collision handling
# ---------------------------------------------------------------------------


async def test_generate_unique_slug_returns_base_when_free(session_factory) -> None:
    async with session_factory() as s:
        slug = await _generate_unique_org_slug(s, "alice")
        assert slug == "alice"


async def test_generate_unique_slug_appends_number_on_collision(
    session_factory,
) -> None:
    """Two users bidding for slug 'alice' → first gets 'alice', second
    gets 'alice-2'. Keeps the URL human-readable in the common case."""
    async with session_factory() as s:
        s.add(Organization(slug="alice", name="alice"))
        await s.commit()
    async with session_factory() as s:
        slug = await _generate_unique_org_slug(s, "alice")
        assert slug == "alice-2"


# ---------------------------------------------------------------------------
# create_org — atomic org + owner
# ---------------------------------------------------------------------------


async def test_create_org_inserts_owner_membership_atomically(
    session_factory,
) -> None:
    """The Organization and the OrganizationMember(owner) row land in
    the same commit. No transient state where an org exists with zero
    members — important because the route surface will reject
    actions on orgs the caller isn't a member of."""
    async with session_factory() as s:
        u = User(email="founder@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)

        org = await create_org(s, name="Acme", slug="acme-corp", owner_user_id=u.id)

        # Both rows committed.
        assert org.id
        members = (
            await s.exec(
                select(OrganizationMember).where(OrganizationMember.org_id == org.id)
            )
        ).all()
        assert len(members) == 1
        assert members[0].user_id == u.id
        assert members[0].role == ROLE_OWNER


# ---------------------------------------------------------------------------
# ensure_personal_default_org — the on-signup hook
# ---------------------------------------------------------------------------


async def test_personal_default_org_uses_email_prefix_as_slug(
    session_factory,
) -> None:
    """A fresh user → org named 'default' with slug derived from the
    email's local part. URL-friendly so Phase 5's
    /orgs/{slug}/... reads naturally."""
    async with session_factory() as s:
        u = User(email="alice@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)

        org = await ensure_personal_default_org(s, u)
        assert org.name == "default"
        assert org.slug == "alice"


async def test_personal_default_org_is_idempotent(session_factory) -> None:
    """Called twice with the same user → returns the existing org, no
    duplicate row. Defensive for retried registrations + future
    invite-merge flows."""
    async with session_factory() as s:
        u = User(email="bob@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)

        org1 = await ensure_personal_default_org(s, u)
        org2 = await ensure_personal_default_org(s, u)
        assert org1.id == org2.id

        # And the user only owns one org total.
        orgs = await list_orgs_for_user(s, u.id)
        owner_orgs = [(o, r) for o, r in orgs if r == ROLE_OWNER]
        assert len(owner_orgs) == 1


# ---------------------------------------------------------------------------
# Registration → personal org wired end-to-end via on_after_register
# ---------------------------------------------------------------------------


def test_register_creates_personal_default_org(
    client: TestClient, session_factory
) -> None:
    """The integration: POST /v1/auth/register triggers the
    UserManager.on_after_register hook which creates the user's
    default org + owner membership in the same transaction."""
    import asyncio

    r = client.post(
        "/v1/auth/register",
        json={"email": "founder@example.com", "password": "correcthorsebattery"},
    )
    assert r.status_code == 201, r.text

    async def _check() -> None:
        async with session_factory() as s:
            u = (
                await s.exec(select(User).where(User.email == "founder@example.com"))
            ).one()
            orgs = await list_orgs_for_user(s, u.id)
            # The new user belongs to exactly one org — their own — as owner.
            owner_orgs = [(o, r) for o, r in orgs if r == ROLE_OWNER]
            assert len(owner_orgs) == 1
            org = owner_orgs[0][0]
            assert org.name == "default"
            assert org.slug == "founder"

    asyncio.get_event_loop().run_until_complete(_check())


# ---------------------------------------------------------------------------
# list_orgs_for_user
# ---------------------------------------------------------------------------


async def test_list_orgs_returns_role_per_org(session_factory) -> None:
    """A user belonging to two orgs sees both, with the role on each."""
    async with session_factory() as s:
        u = User(email="multi@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)

        # Owner of orgA, member of orgB.
        org_a = await create_org(s, name="A", slug="org-a", owner_user_id=u.id)
        org_b = await create_org(s, name="B", slug="org-b", owner_user_id=u.id)
        # Demote u in org_b to member.
        member_b = (
            await s.exec(
                select(OrganizationMember).where(
                    OrganizationMember.org_id == org_b.id,
                    OrganizationMember.user_id == u.id,
                )
            )
        ).one()
        # Add a different user as owner so org_b still has at least one.
        other = User(email="other@example.com")
        s.add(other)
        await s.commit()
        await s.refresh(other)
        s.add(OrganizationMember(user_id=other.id, org_id=org_b.id, role=ROLE_OWNER))
        member_b.role = ROLE_MEMBER
        s.add(member_b)
        await s.commit()

        orgs = await list_orgs_for_user(s, u.id)
        by_id = {o.id: r for o, r in orgs}
        assert by_id[org_a.id] == ROLE_OWNER
        assert by_id[org_b.id] == ROLE_MEMBER


# ---------------------------------------------------------------------------
# remove_member — the last-owner guard
# ---------------------------------------------------------------------------


async def test_remove_member_returns_false_when_not_a_member(
    session_factory,
) -> None:
    async with session_factory() as s:
        ok = await remove_member(s, org_id=DEFAULT_ORG_ID, user_id="ghost-uuid")
        assert ok is False


async def test_remove_member_succeeds_for_existing_membership(
    session_factory,
) -> None:
    async with session_factory() as s:
        # Add a second member to support-bot's org (which has the default
        # admin as the only owner today).
        u = User(email="extra@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        s.add(OrganizationMember(user_id=u.id, org_id=DEFAULT_ORG_ID, role=ROLE_MEMBER))
        await s.commit()

        ok = await remove_member(s, org_id=DEFAULT_ORG_ID, user_id=u.id)
        assert ok is True
        # And the row really is gone.
        rows = (
            await s.exec(
                select(OrganizationMember).where(OrganizationMember.user_id == u.id)
            )
        ).all()
        assert rows == []


async def test_remove_member_refuses_last_owner(session_factory) -> None:
    """The default admin is the only owner of support-bot's org —
    removing them would leave the org unreachable. The guard fires
    here; the route layer translates it to HTTP 409."""
    import pytest

    from hexgate_api.constants import DEFAULT_USER_ID

    async with session_factory() as s:
        with pytest.raises(LastOwnerError):
            await remove_member(s, org_id=DEFAULT_ORG_ID, user_id=DEFAULT_USER_ID)


async def test_remove_member_allows_owner_when_others_exist(
    session_factory,
) -> None:
    """A second owner exists → either one is removable."""
    async with session_factory() as s:
        u = User(email="co-owner@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        s.add(OrganizationMember(user_id=u.id, org_id=DEFAULT_ORG_ID, role=ROLE_OWNER))
        await s.commit()

        # Now there are two owners. Removing the co-owner is fine.
        ok = await remove_member(s, org_id=DEFAULT_ORG_ID, user_id=u.id)
        assert ok is True


# ---------------------------------------------------------------------------
# change_member_role
# ---------------------------------------------------------------------------


async def test_change_member_role_updates_existing_row(session_factory) -> None:
    async with session_factory() as s:
        u = User(email="promote@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        s.add(OrganizationMember(user_id=u.id, org_id=DEFAULT_ORG_ID, role=ROLE_MEMBER))
        await s.commit()

        member = await change_member_role(
            s,
            org_id=DEFAULT_ORG_ID,
            user_id=u.id,
            new_role=ROLE_ADMIN,
            caller_role=ROLE_OWNER,
        )
        assert member is not None
        assert member.role == ROLE_ADMIN


async def test_change_member_role_refuses_demoting_last_owner(
    session_factory,
) -> None:
    """Demoting the only owner to member would orphan the org."""
    import pytest

    from hexgate_api.constants import DEFAULT_USER_ID

    async with session_factory() as s:
        with pytest.raises(LastOwnerError):
            await change_member_role(
                s,
                org_id=DEFAULT_ORG_ID,
                user_id=DEFAULT_USER_ID,
                new_role=ROLE_MEMBER,
                caller_role=ROLE_OWNER,
            )


async def test_change_member_role_allows_demoting_when_others_owners(
    session_factory,
) -> None:
    async with session_factory() as s:
        u = User(email="another-owner@example.com")
        s.add(u)
        await s.commit()
        await s.refresh(u)
        s.add(OrganizationMember(user_id=u.id, org_id=DEFAULT_ORG_ID, role=ROLE_OWNER))
        await s.commit()

        # Two owners → either one can be demoted.
        member = await change_member_role(
            s,
            org_id=DEFAULT_ORG_ID,
            user_id=u.id,
            new_role=ROLE_MEMBER,
            caller_role=ROLE_OWNER,
        )
        assert member is not None and member.role == ROLE_MEMBER


# ---------------------------------------------------------------------------
# list_org_members — for the dashboard member list (Phase 5)
# ---------------------------------------------------------------------------


async def test_list_org_members_returns_membership_and_user(
    session_factory,
) -> None:
    async with session_factory() as s:
        rows = await list_org_members(s, DEFAULT_ORG_ID)
        # At minimum the default admin is present.
        assert len(rows) >= 1
        emails = {u.email for _m, u in rows}
        assert "admin@hexgate.dev" in emails


# ---------------------------------------------------------------------------
# HTTP route tests — /v1/orgs CRUD
#
# Every test signs up a fresh user (gets a personal default org via the
# on_after_register hook), logs in, and uses the resulting cookie to
# exercise the routes. Cross-tenant isolation is pinned by signing up
# TWO users and asserting one can't read or update the other's org.
# ---------------------------------------------------------------------------


def _signup_and_login(client: TestClient, email: str, password: str) -> None:
    """Register a fresh user then exchange password for a session cookie.

    Leaves the cookie on the client's cookie jar for subsequent calls.
    The default `client` fixture's cookie jar persists across requests.
    """
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


# ---- GET /v1/orgs ---------------------------------------------------------


def test_list_orgs_returns_only_callers_orgs(client: TestClient) -> None:
    """A fresh user sees exactly one org (their personal default) with
    role=owner. They do NOT see other tenants' orgs."""
    _signup_and_login(client, "alice@example.com", "correcthorsebattery")

    r = client.get("/v1/orgs")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    only = body[0]
    assert only["name"] == "default"
    assert only["slug"] == "alice"
    assert only["role"] == ROLE_OWNER


def test_list_orgs_requires_authentication(client: TestClient) -> None:
    """No cookie → 401 (the global 401 handler in the dashboard
    redirects to /sign-in; here we just confirm the backend rejects)."""
    r = client.get("/v1/orgs")
    assert r.status_code == 401


def test_list_orgs_repairs_missing_personal_org(
    client: TestClient, session_factory
) -> None:
    """If a logged-in user somehow has zero org memberships, hitting
    ``GET /v1/orgs`` lazily creates their personal default org rather
    than returning the empty list that would render the dashboard's
    "no orgs yet" dead-end.

    Simulates the edge case where the ``on_after_register`` hook
    failed after FastAPI-Users committed the User row — the listing
    endpoint is the recovery net for that.
    """
    import asyncio

    _signup_and_login(client, "orphan@example.com", "correcthorsebattery")

    # Manually nuke the user's memberships to simulate a botched
    # registration. The User row stays; only the OrganizationMember
    # link (and the org itself, since it had a sole owner) disappear.
    async def _strip_org() -> None:
        async with session_factory() as s:
            u = (
                await s.exec(select(User).where(User.email == "orphan@example.com"))
            ).one()
            membership = (
                await s.exec(
                    select(OrganizationMember).where(OrganizationMember.user_id == u.id)
                )
            ).one()
            org_id = membership.org_id
            await s.delete(membership)
            org = (
                await s.exec(select(Organization).where(Organization.id == org_id))
            ).one()
            await s.delete(org)
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_strip_org())

    # First listing call repairs — caller sees their fresh personal org.
    r = client.get("/v1/orgs")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body) == 1
    repaired = body[0]
    assert repaired["name"] == "default"
    assert repaired["role"] == ROLE_OWNER

    # Second call is a no-op — idempotent, no extra org row.
    r2 = client.get("/v1/orgs")
    assert r2.status_code == 200
    assert len(r2.json()) == 1


def test_list_orgs_skips_repair_when_org_already_present(
    client: TestClient, session_factory
) -> None:
    """Healthy users (the common case) must NOT trigger the repair
    branch — the listing endpoint stays a pure GET on the happy path.
    Asserts a fresh signup ends with exactly one org and no duplicate
    after the first listing call.
    """
    import asyncio

    _signup_and_login(client, "healthy@example.com", "correcthorsebattery")

    # Hit the listing endpoint to give the repair path a chance to fire.
    r = client.get("/v1/orgs")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # Confirm via the DB that no second org was bootstrapped.
    async def _count_orgs() -> int:
        async with session_factory() as s:
            u = (
                await s.exec(select(User).where(User.email == "healthy@example.com"))
            ).one()
            return len(await list_orgs_for_user(s, u.id))

    assert asyncio.get_event_loop().run_until_complete(_count_orgs()) == 1


# ---- POST /v1/orgs --------------------------------------------------------


def test_create_org_makes_caller_owner(client: TestClient) -> None:
    """POST /v1/orgs → 201 with the new org; caller is owner."""
    _signup_and_login(client, "bob@example.com", "correcthorsebattery")

    r = client.post("/v1/orgs", json={"name": "Acme"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "Acme"
    # Server-derived slug from "Acme" → "acme".
    assert body["slug"] == "acme"

    # The caller now sees BOTH orgs in their list — personal + Acme.
    listed = client.get("/v1/orgs").json()
    names = {o["name"] for o in listed}
    assert names == {"default", "Acme"}
    # And they're owner of both.
    assert all(o["role"] == ROLE_OWNER for o in listed)


def test_create_org_accepts_explicit_slug(client: TestClient) -> None:
    """Client-supplied slug is used verbatim when valid + unique."""
    _signup_and_login(client, "carol@example.com", "correcthorsebattery")
    r = client.post("/v1/orgs", json={"name": "Carol Co", "slug": "carol-co"})
    assert r.status_code == 201
    assert r.json()["slug"] == "carol-co"


def test_create_org_rejects_collision_with_explicit_slug(
    client: TestClient,
) -> None:
    """Explicit slug that's already taken → 409. Server doesn't
    silently rewrite (would surprise the caller); UI prompts for a tweak."""
    _signup_and_login(client, "dave@example.com", "correcthorsebattery")

    # First create succeeds — slug "shared" is free.
    r = client.post("/v1/orgs", json={"name": "First", "slug": "shared"})
    assert r.status_code == 201
    # Second create with the same slug 409s.
    r = client.post("/v1/orgs", json={"name": "Second", "slug": "shared"})
    assert r.status_code == 409
    assert "taken" in r.json()["detail"].lower()


def test_create_org_rejects_malformed_slug(client: TestClient) -> None:
    """Slugs are DNS-label-shaped (lowercase letters / digits / hyphens,
    must start with a letter, can't end with hyphen). 422 on violation."""
    _signup_and_login(client, "eve@example.com", "correcthorsebattery")

    for bad in ("Foo", "-bad", "bad-", "foo!bar", ""):
        r = client.post("/v1/orgs", json={"name": "X", "slug": bad})
        assert r.status_code == 422, (
            f"expected 422 for slug={bad!r}, got {r.status_code}"
        )


# ---- GET /v1/orgs/{id} ---------------------------------------------------


def test_get_org_succeeds_for_member(client: TestClient) -> None:
    _signup_and_login(client, "frank@example.com", "correcthorsebattery")
    listed = client.get("/v1/orgs").json()
    org_id = listed[0]["id"]
    r = client.get(f"/v1/orgs/{org_id}")
    assert r.status_code == 200
    assert r.json()["id"] == org_id


def test_get_org_404_when_unknown(client: TestClient) -> None:
    """Unknown id → 404 (don't leak existence by 403'ing only on known
    ids)."""
    _signup_and_login(client, "grace@example.com", "correcthorsebattery")
    r = client.get("/v1/orgs/00000000-0000-0000-0000-deadbeef0000")
    assert r.status_code == 404


def test_get_org_403_for_non_member(client: TestClient) -> None:
    """User A creates an org; User B (different account) can't read it.

    This is the tenant-isolation guarantee for the org surface — same
    invariant we pin for projects."""
    # User A creates an org.
    _signup_and_login(client, "owner@example.com", "correcthorsebattery")
    r = client.post("/v1/orgs", json={"name": "Private", "slug": "private"})
    private_org_id = r.json()["id"]
    # Drop user A's cookie so the next sign-in is a clean session.
    client.cookies.clear()
    # User B signs in.
    _signup_and_login(client, "stranger@example.com", "correcthorsebattery")
    r = client.get(f"/v1/orgs/{private_org_id}")
    assert r.status_code == 403


# ---- PATCH /v1/orgs/{id} -------------------------------------------------


def test_patch_org_updates_name_for_owner(client: TestClient) -> None:
    _signup_and_login(client, "hank@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.patch(f"/v1/orgs/{org_id}", json={"name": "Hank Inc"})
    assert r.status_code == 200
    assert r.json()["name"] == "Hank Inc"


def test_patch_org_updates_slug_when_unique(client: TestClient) -> None:
    _signup_and_login(client, "ivy@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.patch(f"/v1/orgs/{org_id}", json={"slug": "ivy-renamed"})
    assert r.status_code == 200
    assert r.json()["slug"] == "ivy-renamed"


def test_patch_org_409_on_slug_collision(client: TestClient) -> None:
    """Trying to rename to a slug another org owns → 409. Same shape as
    POST /v1/orgs slug-collision handling."""
    # User A creates two orgs; tries to rename one to the other's slug.
    _signup_and_login(client, "jane@example.com", "correcthorsebattery")
    r = client.post("/v1/orgs", json={"name": "Y", "slug": "alpha"})
    alpha_id = r.json()["id"]
    client.post("/v1/orgs", json={"name": "Z", "slug": "beta"})
    r = client.patch(f"/v1/orgs/{alpha_id}", json={"slug": "beta"})
    assert r.status_code == 409


def test_patch_org_403_for_plain_member(client: TestClient, session_factory) -> None:
    """Members (not admin/owner) can't update the org. Pre-create a
    user as plain member of the default org and try."""
    import asyncio
    import uuid

    _signup_and_login(client, "memberonly@example.com", "correcthorsebattery")

    # Demote the seeded membership from owner→member by adding the
    # memberonly user as a member of DEFAULT_ORG_ID (which they don't
    # belong to by default). The user already has their own personal
    # org; we want to test the PATCH gate on an org they're a plain
    # member of.
    async def _join_default_as_member():
        async with session_factory() as s:
            from sqlmodel import select

            u = (
                await s.exec(select(User).where(User.email == "memberonly@example.com"))
            ).one()
            s.add(
                OrganizationMember(
                    id=str(uuid.uuid4()),
                    user_id=u.id,
                    org_id=DEFAULT_ORG_ID,
                    role=ROLE_MEMBER,
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_join_default_as_member())

    r = client.patch(f"/v1/orgs/{DEFAULT_ORG_ID}", json={"name": "Renamed"})
    assert r.status_code == 403
    assert "admin or owner" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Member management routes (Phase 4 step 3)
#
# Each test signs the caller into a fresh personal org (the on-signup
# default) and then either:
#   - operates inside that org (always a single owner — themselves)
#   - or directly adds a second member via the session_factory to set
#     up the "two members" / "two owners" scenarios.
# ---------------------------------------------------------------------------


async def _add_member(session_factory, *, email: str, org_id: str, role: str) -> str:
    """Test helper: add (or create) a user as a member of an org.

    Returns the user's id. If the email already exists, just adds the
    membership row — useful for the same TestClient handling multiple
    test scenarios.
    """
    import uuid

    async with session_factory() as s:
        from sqlmodel import select

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


# ---- GET /v1/orgs/{id}/members -------------------------------------------


def test_list_members_returns_self_for_fresh_user(client: TestClient) -> None:
    """A user with only their personal default org sees themselves in
    the members list."""
    _signup_and_login(client, "solo@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r = client.get(f"/v1/orgs/{org_id}/members")
    assert r.status_code == 200, r.text
    members = r.json()
    assert len(members) == 1
    assert members[0]["email"] == "solo@example.com"
    assert members[0]["role"] == ROLE_OWNER


def test_list_members_403_for_non_member(client: TestClient) -> None:
    """User A creates an org; User B (different account) can't list
    its members."""
    _signup_and_login(client, "ownerA@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.cookies.clear()
    _signup_and_login(client, "strangerB@example.com", "correcthorsebattery")

    r = client.get(f"/v1/orgs/{org_id}/members")
    assert r.status_code == 403


def test_list_members_404_for_unknown_org(client: TestClient) -> None:
    _signup_and_login(client, "wanderer@example.com", "correcthorsebattery")
    r = client.get("/v1/orgs/00000000-0000-0000-0000-deadbeef0000/members")
    assert r.status_code == 404


# ---- PATCH /v1/orgs/{id}/members/{uid} -----------------------------------


def test_promote_member_to_admin_as_owner(client: TestClient, session_factory) -> None:
    """Owner can promote a plain member to admin via PATCH."""
    import asyncio

    _signup_and_login(client, "boss@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    member_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="newbie@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )

    r = client.patch(
        f"/v1/orgs/{org_id}/members/{member_id}", json={"role": ROLE_ADMIN}
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == ROLE_ADMIN


def test_patch_member_role_403_for_plain_member(
    client: TestClient, session_factory
) -> None:
    """A plain member can't promote anyone — even themselves.

    The helper-created member has no password (added via direct DB
    write), so we impersonate them via the X-Dev-User header gated
    behind ``HEXGATE_ALLOW_DEV_USER_HEADER`` (enabled by the conftest
    for the test session). The dashboard never sends this header.
    """
    import asyncio

    _signup_and_login(client, "ownerX@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    member_user_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory,
            email="memberX@example.com",
            org_id=org_id,
            role=ROLE_MEMBER,
        )
    )

    # Drop the owner cookie + assume the member identity via X-Dev-User.
    client.cookies.clear()
    r = client.patch(
        f"/v1/orgs/{org_id}/members/{member_user_id}",
        json={"role": ROLE_ADMIN},
        headers={"X-Dev-User": member_user_id},
    )
    assert r.status_code == 403
    assert "admin or owner" in r.json()["detail"].lower()


def test_admin_cannot_promote_to_owner(client: TestClient, session_factory) -> None:
    """Privilege escalation guard — an admin PATCHing themselves (or
    anyone else) to owner is refused with 403.

    The invitation path enforces this via :func:`_can_invite_role`;
    the PATCH-member-role path now does too. Before the fix, any admin
    could seize an org by promoting themselves.
    """
    import asyncio

    _signup_and_login(client, "ownerY@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    admin_user_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="adminY@example.com", org_id=org_id, role=ROLE_ADMIN
        )
    )

    # Drop the owner cookie + impersonate the admin via X-Dev-User.
    client.cookies.clear()
    r = client.patch(
        f"/v1/orgs/{org_id}/members/{admin_user_id}",
        json={"role": ROLE_OWNER},
        headers={"X-Dev-User": admin_user_id},
    )
    assert r.status_code == 403
    # Defensive: the message names the offending role transition so
    # the dashboard can surface it sensibly.
    assert "owner" in r.json()["detail"].lower()


def test_owner_can_promote_admin_to_owner(client: TestClient, session_factory) -> None:
    """Sanity-check the other side of the rank check — owners can still
    set any role. The fix shouldn't restrict the owner path."""
    import asyncio

    _signup_and_login(client, "ownerZ@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    admin_user_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="adminZ@example.com", org_id=org_id, role=ROLE_ADMIN
        )
    )

    r = client.patch(
        f"/v1/orgs/{org_id}/members/{admin_user_id}",
        json={"role": ROLE_OWNER},
    )
    assert r.status_code == 200, r.text
    assert r.json()["role"] == ROLE_OWNER


def test_demote_last_owner_returns_409(client: TestClient) -> None:
    """Owner tries to demote themselves while sole owner → 409. The
    last-owner guard fires in services.change_member_role; the route
    translates LastOwnerError to HTTP 409 with the same message."""
    _signup_and_login(client, "lone@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    me_id = client.get("/v1/users/me").json()["id"]

    r = client.patch(f"/v1/orgs/{org_id}/members/{me_id}", json={"role": ROLE_MEMBER})
    assert r.status_code == 409
    assert "last owner" in r.json()["detail"].lower()


def test_demote_owner_succeeds_when_other_owners_exist(
    client: TestClient, session_factory
) -> None:
    """With a second owner around, either one can be demoted."""
    import asyncio

    _signup_and_login(client, "co1@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    co_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="co2@example.com", org_id=org_id, role=ROLE_OWNER
        )
    )

    r = client.patch(f"/v1/orgs/{org_id}/members/{co_id}", json={"role": ROLE_MEMBER})
    assert r.status_code == 200
    assert r.json()["role"] == ROLE_MEMBER


def test_patch_member_404_for_unknown_user(client: TestClient) -> None:
    """User isn't in the org → 404 (matches services contract)."""
    _signup_and_login(client, "looker@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r = client.patch(
        f"/v1/orgs/{org_id}/members/00000000-0000-0000-0000-deadbeef0000",
        json={"role": ROLE_MEMBER},
    )
    assert r.status_code == 404


def test_patch_member_422_for_invalid_role(client: TestClient) -> None:
    """Role outside the allowed set → 422 (pydantic body validation)."""
    _signup_and_login(client, "validator@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    me_id = client.get("/v1/users/me").json()["id"]

    r = client.patch(f"/v1/orgs/{org_id}/members/{me_id}", json={"role": "superadmin"})
    assert r.status_code == 422


# ---- DELETE /v1/orgs/{id}/members/{uid} ---------------------------------


def test_owner_removes_member(client: TestClient, session_factory) -> None:
    """Owner removes a plain member → 204, member is gone from list."""
    import asyncio

    _signup_and_login(client, "remover@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    victim_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="victim@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )

    r = client.delete(f"/v1/orgs/{org_id}/members/{victim_id}")
    assert r.status_code == 204, r.text
    # And the member list no longer includes them.
    members = client.get(f"/v1/orgs/{org_id}/members").json()
    assert victim_id not in {m["user_id"] for m in members}


def test_member_can_remove_self(client: TestClient, session_factory) -> None:
    """A plain member can leave the org by DELETEing their own row.

    We exercise self-removal via X-Dev-User since the manually-added
    member doesn't have a password. The dashboard's "Leave org" button
    will hit the same endpoint with a cookie session in production.
    """
    import asyncio

    _signup_and_login(client, "stayer@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    leaver_id = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="leaver@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )

    client.cookies.clear()
    r = client.delete(
        f"/v1/orgs/{org_id}/members/{leaver_id}",
        headers={"X-Dev-User": leaver_id},
    )
    assert r.status_code == 204


def test_member_cannot_remove_someone_else(client: TestClient, session_factory) -> None:
    """Plain member tries to remove a third party → 403. The
    require_org_admin_or_self gate fires."""
    import asyncio

    _signup_and_login(client, "obs@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    mem_a = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="ma@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )
    mem_b = asyncio.get_event_loop().run_until_complete(
        _add_member(
            session_factory, email="mb@example.com", org_id=org_id, role=ROLE_MEMBER
        )
    )

    client.cookies.clear()
    r = client.delete(
        f"/v1/orgs/{org_id}/members/{mem_b}",
        headers={"X-Dev-User": mem_a},
    )
    assert r.status_code == 403


def test_remove_last_owner_returns_409(client: TestClient) -> None:
    """Owner tries to remove themselves while sole owner → 409."""
    _signup_and_login(client, "alone@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    me_id = client.get("/v1/users/me").json()["id"]

    r = client.delete(f"/v1/orgs/{org_id}/members/{me_id}")
    assert r.status_code == 409
    assert "last owner" in r.json()["detail"].lower()


def test_delete_member_404_for_unknown_user(client: TestClient) -> None:
    _signup_and_login(client, "explorer@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r = client.delete(f"/v1/orgs/{org_id}/members/00000000-0000-0000-0000-deadbeef0000")
    assert r.status_code == 404
