"""Tests for the M3 Phase 4 step 4 invitation flow.

Five routes (POST/GET/GET preview/POST accept/DELETE), three terminal
states (accepted, revoked, expired), one role-escalation guard, one
strict email-match guard. The tests below cover each gate from both
directions + the happy path end-to-end.

Mailer is swapped for the capturing fake from test_auth.py's outbox
pattern so we can assert that the invitation email actually went out
without needing real SMTP.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api import main
from hexgate_api.core import mailer
from hexgate_api.main import app
from hexgate_api.models import (
    Invitation,
    OrganizationMember,
    User,
)
from hexgate_api.models import utcnow
from hexgate_api.constants import ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER
from hexgate_api.services import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures
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


class _CapturingSender:
    """Mailer fake — records every send so tests can assert on
    recipient + subject + body."""

    def __init__(self) -> None:
        self.outbox: list[dict] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})


@pytest_asyncio.fixture
async def outbox():
    original = mailer.get_email_sender()
    capturing = _CapturingSender()
    mailer.set_email_sender(capturing)
    yield capturing.outbox
    mailer.set_email_sender(original)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signup_and_login(client: TestClient, email: str, password: str) -> str:
    """Register + log in; return the new user's id."""
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
    return client.get("/v1/users/me").json()["id"]


async def _add_user_only(session_factory, *, email: str) -> str:
    """Create a User row without an org membership. Used to set up
    "invitee already has an account elsewhere" scenarios."""
    async with session_factory() as s:
        u = User(email=email)
        s.add(u)
        await s.commit()
        await s.refresh(u)
        return u.id


# ---------------------------------------------------------------------------
# POST /v1/orgs/{id}/invites
# ---------------------------------------------------------------------------


def test_owner_creates_invitation_and_email_is_sent(
    client: TestClient, outbox: list[dict]
) -> None:
    """Happy path: owner mints invite → 201, response carries the
    invitee email + role + inviter, and one email lands in the outbox
    with a clickable link."""
    _signup_and_login(client, "boss@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    r = client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "guest@example.com", "role": ROLE_MEMBER},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "guest@example.com"
    assert body["role"] == ROLE_MEMBER
    assert body["invited_by_email"] == "boss@example.com"

    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["to"] == "guest@example.com"
    assert "/invites/" in msg["body"]
    assert "/accept" in msg["body"]


def test_create_invitation_403_for_plain_member(
    client: TestClient, session_factory
) -> None:
    """Plain members can't invite. Sign in as the owner first, add a
    plain member, then assume the member identity via X-Dev-User."""
    _signup_and_login(client, "boss2@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    member_id = asyncio.get_event_loop().run_until_complete(
        _add_user_only(session_factory, email="plain@example.com")
    )

    async def _join():
        async with session_factory() as s:
            s.add(
                OrganizationMember(
                    id=str(uuid.uuid4()),
                    user_id=member_id,
                    org_id=org_id,
                    role=ROLE_MEMBER,
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_join())

    client.cookies.clear()
    r = client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "x@example.com", "role": ROLE_MEMBER},
        headers={"X-Dev-User": member_id},
    )
    assert r.status_code == 403


def test_admin_cannot_invite_owner(client: TestClient, session_factory) -> None:
    """Role escalation guard: admin can invite admin/member but not
    owner. Service-layer InvitationError → HTTP 400."""
    _signup_and_login(client, "head@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    # Add a second user as admin in the same org.
    admin_id = asyncio.get_event_loop().run_until_complete(
        _add_user_only(session_factory, email="admin@example.com")
    )

    async def _join():
        async with session_factory() as s:
            s.add(
                OrganizationMember(
                    id=str(uuid.uuid4()),
                    user_id=admin_id,
                    org_id=org_id,
                    role=ROLE_ADMIN,
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_join())

    client.cookies.clear()
    # Admin tries to mint an owner-level invite → 400.
    r = client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "outsider@example.com", "role": ROLE_OWNER},
        headers={"X-Dev-User": admin_id},
    )
    assert r.status_code == 400
    assert "cannot invite" in r.json()["detail"].lower()


def test_owner_can_invite_owner(client: TestClient, outbox: list[dict]) -> None:
    """Owners CAN mint owner-level invites — the rank rule says
    inviter >= target."""
    _signup_and_login(client, "boss3@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "co-owner@example.com", "role": ROLE_OWNER},
    )
    assert r.status_code == 201
    assert r.json()["role"] == ROLE_OWNER


# ---------------------------------------------------------------------------
# Re-invite cancels the previous pending invite
# ---------------------------------------------------------------------------


def test_re_invite_cancels_previous_pending_invitation(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Inviting the same email twice → first invite revoked, second
    pending. The dashboard's Members tab shows one pending row, not
    two — and only the latest link is acceptable."""
    _signup_and_login(client, "boss4@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    # First invite.
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "twice@example.com", "role": ROLE_MEMBER},
    )
    # Second invite to the same email.
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "twice@example.com", "role": ROLE_ADMIN},
    )

    listed = client.get(f"/v1/orgs/{org_id}/invites").json()
    matching = [i for i in listed if i["email"] == "twice@example.com"]
    assert len(matching) == 1, f"expected 1 pending, saw {len(matching)}"
    # And it's the latest role (admin), not the cancelled member-level one.
    assert matching[0]["role"] == ROLE_ADMIN


# ---------------------------------------------------------------------------
# GET /v1/orgs/{id}/invites
# ---------------------------------------------------------------------------


def test_list_invitations_returns_pending_only(
    client: TestClient, outbox: list[dict]
) -> None:
    _signup_and_login(client, "boss5@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "p1@example.com", "role": ROLE_MEMBER},
    )
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "p2@example.com", "role": ROLE_ADMIN},
    )
    listed = client.get(f"/v1/orgs/{org_id}/invites").json()
    assert {i["email"] for i in listed} == {"p1@example.com", "p2@example.com"}
    # Each pending invite carries its id so the dashboard's "Cancel"
    # button has a row to address. The strict email-match guard on
    # accept is the load-bearing protection — id exposure isn't an
    # impersonation vector (only the invited user can accept).
    assert all("id" in i and i["id"] for i in listed)


def test_list_invitations_403_for_plain_member(
    client: TestClient, session_factory
) -> None:
    _signup_and_login(client, "boss6@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    member_id = asyncio.get_event_loop().run_until_complete(
        _add_user_only(session_factory, email="member6@example.com")
    )

    async def _join():
        async with session_factory() as s:
            s.add(
                OrganizationMember(
                    id=str(uuid.uuid4()),
                    user_id=member_id,
                    org_id=org_id,
                    role=ROLE_MEMBER,
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_join())

    client.cookies.clear()
    r = client.get(
        f"/v1/orgs/{org_id}/invites",
        headers={"X-Dev-User": member_id},
    )
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /v1/invites/{id} — public-readable preview
# ---------------------------------------------------------------------------


def test_invitation_preview_works_without_auth(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Anyone with the link can preview — no cookie required. Powers
    the dashboard's accept landing page."""
    _signup_and_login(client, "boss7@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "preview@example.com", "role": ROLE_MEMBER},
    )

    # Pull the invite id from the DB (the list endpoint hides it).
    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "preview@example.com")
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    # Drop the cookie — preview is public.
    client.cookies.clear()
    r = client.get(f"/v1/invites/{invite_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "preview@example.com"
    assert body["org_id"] == org_id
    assert body["org_name"] == "default"
    assert body["invited_by_email"] == "boss7@example.com"


def test_invitation_preview_404_for_unknown(client: TestClient) -> None:
    r = client.get("/v1/invites/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


def test_invitation_preview_410_for_expired(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Expired invite → 410 Gone (the dashboard renders an
    "expired" card instead of the accept button)."""
    _signup_and_login(client, "boss8@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "stale@example.com", "role": ROLE_MEMBER},
    )

    async def _expire_it() -> str:
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "stale@example.com")
                )
            ).one()
            inv.expires_at = utcnow() - timedelta(hours=1)
            s.add(inv)
            await s.commit()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_expire_it())

    client.cookies.clear()
    r = client.get(f"/v1/invites/{invite_id}")
    assert r.status_code == 410


# ---------------------------------------------------------------------------
# POST /v1/invites/{id}/accept
# ---------------------------------------------------------------------------


def test_accept_invitation_happy_path(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """End-to-end: invite alice → alice signs up → alice accepts →
    alice is a member of the org with the invited role."""
    # Owner mints the invitation.
    _signup_and_login(client, "boss9@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "alice@example.com", "role": ROLE_ADMIN},
    )

    # Pull the invite id (the list view hides it, but it's the DB column).
    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "alice@example.com")
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    # Switch sessions: alice signs up and accepts.
    client.cookies.clear()
    _signup_and_login(client, "alice@example.com", "correcthorsebattery")
    r = client.post(f"/v1/invites/{invite_id}/accept")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == ROLE_ADMIN

    # Alice now sees TWO orgs in her list — her personal default plus
    # the one she was invited into.
    listed = client.get("/v1/orgs").json()
    org_ids = {o["id"] for o in listed}
    assert org_id in org_ids
    # And in the invited org, her role is admin.
    invited_org = next(o for o in listed if o["id"] == org_id)
    assert invited_org["role"] == ROLE_ADMIN


def test_accept_invitation_403_when_email_mismatches(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Invitation is for bob@example.com but eve@example.com tries
    to accept → 403. Strict email match stops 'anyone with the link'
    from joining."""
    _signup_and_login(client, "boss10@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "bob@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "bob@example.com")
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    client.cookies.clear()
    _signup_and_login(client, "eve@example.com", "correcthorsebattery")
    r = client.post(f"/v1/invites/{invite_id}/accept")
    assert r.status_code == 403
    assert (
        "different" in r.json()["detail"].lower() or "not" in r.json()["detail"].lower()
    )


def test_accept_email_mismatch_response_does_not_echo_invitee_email(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """A logged-in attacker who got hold of an invite id (link leaked,
    URL pasted in a chat, etc.) must not be able to learn who the
    invite was addressed to by hitting accept and reading the error.

    The route forwards ``str(InvitationEmailMismatch)`` as the HTTP
    detail; assert the detail contains neither the invited email nor
    the accepting user's email."""
    _signup_and_login(client, "boss-leak@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    invited = "secret-target@example.com"
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": invited, "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(select(Invitation).where(Invitation.email == invited))
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    client.cookies.clear()
    attacker_email = "snoop@example.com"
    _signup_and_login(client, attacker_email, "correcthorsebattery")
    r = client.post(f"/v1/invites/{invite_id}/accept")
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert invited not in detail
    assert attacker_email not in detail


def test_accept_invitation_410_when_expired(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    _signup_and_login(client, "boss11@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "late@example.com", "role": ROLE_MEMBER},
    )

    async def _expire():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "late@example.com")
                )
            ).one()
            inv.expires_at = utcnow() - timedelta(hours=1)
            s.add(inv)
            await s.commit()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_expire())

    client.cookies.clear()
    _signup_and_login(client, "late@example.com", "correcthorsebattery")
    r = client.post(f"/v1/invites/{invite_id}/accept")
    assert r.status_code == 410


def test_accept_invitation_409_when_already_accepted(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Double-click guard. First accept succeeds; second returns 409
    so the UI knows to refresh."""
    _signup_and_login(client, "boss12@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "double@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "double@example.com")
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    client.cookies.clear()
    _signup_and_login(client, "double@example.com", "correcthorsebattery")
    r1 = client.post(f"/v1/invites/{invite_id}/accept")
    assert r1.status_code == 200
    r2 = client.post(f"/v1/invites/{invite_id}/accept")
    assert r2.status_code == 409


def test_accept_invitation_404_for_unknown(client: TestClient) -> None:
    _signup_and_login(client, "wanderer2@example.com", "correcthorsebattery")
    r = client.post("/v1/invites/00000000-0000-0000-0000-000000000000/accept")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /v1/invites/{id} — cancel + decline
# ---------------------------------------------------------------------------


def test_admin_cancels_invitation(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    _signup_and_login(client, "boss13@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "cancelme@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(Invitation.email == "cancelme@example.com")
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())
    r = client.delete(f"/v1/invites/{invite_id}")
    assert r.status_code == 204
    # Pending list no longer shows it.
    pending = client.get(f"/v1/orgs/{org_id}/invites").json()
    assert all(i["email"] != "cancelme@example.com" for i in pending)


def test_invitee_declines_invitation(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """The invited user can DELETE the invite (decline) themselves
    without needing org-admin permissions."""
    _signup_and_login(client, "boss14@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "declineme@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(
                        Invitation.email == "declineme@example.com"
                    )
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    client.cookies.clear()
    _signup_and_login(client, "declineme@example.com", "correcthorsebattery")
    r = client.delete(f"/v1/invites/{invite_id}")
    assert r.status_code == 204


def test_accept_upgrades_existing_member_role(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """Re-inviting an existing teammate at a higher role promotes them.

    Pre-fix the existing-member branch silently kept the original role,
    so an owner clicking "make admin" via re-invite would see no
    change. Now: invite alice as member → alice joins → owner re-invites
    her as admin → alice accepts → her role is admin."""
    _signup_and_login(client, "boss-upgrade@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    # First invite — joins as member.
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "alice-up@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id_for(email: str) -> str:
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation)
                    .where(Invitation.email == email)
                    .where(Invitation.accepted_at.is_(None))
                    .where(Invitation.revoked_at.is_(None))
                )
            ).one()
            return inv.id

    first_invite = asyncio.get_event_loop().run_until_complete(
        _get_id_for("alice-up@example.com")
    )

    client.cookies.clear()
    _signup_and_login(client, "alice-up@example.com", "correcthorsebattery")
    r = client.post(f"/v1/invites/{first_invite}/accept")
    assert r.status_code == 200, r.text
    assert r.json()["role"] == ROLE_MEMBER

    # Owner mints a second invite — promotes to admin. (Login-only
    # call, not re-register; the owner account already exists.)
    client.cookies.clear()
    r_login = client.post(
        "/v1/auth/cookie/login",
        data={
            "username": "boss-upgrade@example.com",
            "password": "correcthorsebattery",
        },
    )
    assert r_login.status_code == 204, r_login.text
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "alice-up@example.com", "role": ROLE_ADMIN},
    )
    second_invite = asyncio.get_event_loop().run_until_complete(
        _get_id_for("alice-up@example.com")
    )

    client.cookies.clear()
    r_login = client.post(
        "/v1/auth/cookie/login",
        data={
            "username": "alice-up@example.com",
            "password": "correcthorsebattery",
        },
    )
    assert r_login.status_code == 204, r_login.text
    r = client.post(f"/v1/invites/{second_invite}/accept")
    assert r.status_code == 200, r.text
    assert r.json()["role"] == ROLE_ADMIN

    # Confirm via the org listing too.
    listed = client.get("/v1/orgs").json()
    invited_org = next(o for o in listed if o["id"] == org_id)
    assert invited_org["role"] == ROLE_ADMIN


def test_accept_does_not_downgrade_existing_owner(
    client: TestClient, outbox: list[dict], session_factory
) -> None:
    """A re-invite at a lower role must NOT silently demote.

    Edge case: owner re-invites themselves as member (sloppy UI, copy-
    paste, whatever). The role on their existing OrganizationMember
    row must stay ``owner`` — anything else would let a fat-fingered
    invite locked out the only owner of an org.
    """
    _signup_and_login(client, "self-invite@example.com", "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]

    # Owner mints an invite for themselves at the lowest role.
    client.post(
        f"/v1/orgs/{org_id}/invites",
        json={"email": "self-invite@example.com", "role": ROLE_MEMBER},
    )

    async def _get_id():
        async with session_factory() as s:
            inv = (
                await s.exec(
                    select(Invitation).where(
                        Invitation.email == "self-invite@example.com"
                    )
                )
            ).one()
            return inv.id

    invite_id = asyncio.get_event_loop().run_until_complete(_get_id())

    r = client.post(f"/v1/invites/{invite_id}/accept")
    assert r.status_code == 200, r.text
    # Critical: role stays OWNER, even though the invite said MEMBER.
    assert r.json()["role"] == ROLE_OWNER

    listed = client.get("/v1/orgs").json()
    own = next(o for o in listed if o["id"] == org_id)
    assert own["role"] == ROLE_OWNER
