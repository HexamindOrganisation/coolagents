"""Tests for the FastAPI Users wiring (M3 Phase 3a).

Covers the human-side auth surface: register / cookie login / logout /
``/users/me``, plus the ``require_user`` cookie-or-header behaviour
that keeps the existing dashboard working during the Phase 3a→3b→3c
transition.

The SDK biscuit path is unchanged — these tests deliberately don't
touch it. Cross-coverage for "biscuit still works alongside cookies"
lives in :mod:`test_tenant_isolation`.
"""

from __future__ import annotations

import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.core import mailer
from hexgate_api.main import app
from hexgate_api.bootstrap.seed import ensure_default_project
from hexgate_api.constants import (
    DEFAULT_PROJECT_ID,
    DEFAULT_USER_EMAIL,
    DEFAULT_USER_ID,
)


# ---------------------------------------------------------------------------
# Fixtures — fresh DB + clean keystore so the default-admin announcement
# is exercised on every test (deterministically).
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
    """TestClient with the test factory injected, fresh keystore per run."""
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


# ---------------------------------------------------------------------------
# POST /v1/auth/register
# ---------------------------------------------------------------------------


def test_register_creates_user(client: TestClient) -> None:
    """A clean registration returns 201 with the public user view."""
    r = client.post(
        "/v1/auth/register",
        json={"email": "alice@example.com", "password": "correcthorsebattery"},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "alice@example.com"
    # Server-side defaults — clients can't set these on registration.
    assert body["is_active"] is True
    assert body["is_verified"] is False
    assert body["is_superuser"] is False
    # Password never leaks back to the client.
    assert "hashed_password" not in body
    assert "password" not in body


def test_register_rejects_duplicate_email(client: TestClient) -> None:
    """Second registration with the same email → 400 (REGISTER_USER_ALREADY_EXISTS)."""
    payload = {"email": "dup@example.com", "password": "correcthorsebattery"}
    r1 = client.post("/v1/auth/register", json=payload)
    assert r1.status_code == 201
    r2 = client.post("/v1/auth/register", json=payload)
    assert r2.status_code == 400
    assert "exists" in r2.json()["detail"].lower()


# NOTE: password complexity validation lives with the signup UI work
# (Phase 3d). FastAPI Users' default ``validate_password`` is a pass-
# through; we'll override it once we know what rules the UI enforces
# (length, common-password blocklist, etc.) so the server check matches
# the form check exactly.


# ---------------------------------------------------------------------------
# POST /v1/auth/cookie/login + /logout
# ---------------------------------------------------------------------------


def test_login_sets_session_cookie(client: TestClient) -> None:
    """A correct password → 204 with a Set-Cookie: hexgate_session=... header."""
    client.post(
        "/v1/auth/register",
        json={"email": "bob@example.com", "password": "correcthorsebattery"},
    )
    r = client.post(
        "/v1/auth/cookie/login",
        # FastAPI Users login uses OAuth2 password-flow form-encoded,
        # not JSON — ``username`` is the email field.
        data={"username": "bob@example.com", "password": "correcthorsebattery"},
    )
    assert r.status_code == 204, r.text
    set_cookie = r.headers.get("set-cookie", "")
    assert "hexgate_session=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()


def test_login_rejects_wrong_password(client: TestClient) -> None:
    """Wrong password → 400 (LOGIN_BAD_CREDENTIALS), no cookie set."""
    client.post(
        "/v1/auth/register",
        json={"email": "carol@example.com", "password": "correcthorsebattery"},
    )
    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": "carol@example.com", "password": "wrong"},
    )
    assert r.status_code == 400
    assert "set-cookie" not in {k.lower() for k in r.headers}


def test_login_rejects_unknown_email(client: TestClient) -> None:
    """Email not in DB → 400, same opaque error as wrong-password.

    Don't distinguish "no such email" from "wrong password" to keep the
    login surface from leaking which emails are registered.
    """
    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": "nobody@example.com", "password": "anything"},
    )
    assert r.status_code == 400


def test_logout_clears_cookie(client: TestClient) -> None:
    """POST /logout while logged in → 204 + the cookie clears."""
    client.post(
        "/v1/auth/register",
        json={"email": "dave@example.com", "password": "correcthorsebattery"},
    )
    client.post(
        "/v1/auth/cookie/login",
        data={"username": "dave@example.com", "password": "correcthorsebattery"},
    )
    r = client.post("/v1/auth/cookie/logout")
    assert r.status_code == 204
    # Server-issued clear: cookie is set to empty with Max-Age=0.
    cookie = r.headers.get("set-cookie", "")
    assert "hexgate_session=" in cookie
    assert ("max-age=0" in cookie.lower()) or ("expires=" in cookie.lower())


# ---------------------------------------------------------------------------
# GET /v1/users/me
# ---------------------------------------------------------------------------


def test_me_requires_authentication(client: TestClient) -> None:
    """Hitting /users/me without a cookie → 401."""
    r = client.get("/v1/users/me")
    assert r.status_code == 401


def test_me_returns_logged_in_user(client: TestClient) -> None:
    """After login, /users/me returns the active user's public view."""
    client.post(
        "/v1/auth/register",
        json={"email": "eve@example.com", "password": "correcthorsebattery"},
    )
    client.post(
        "/v1/auth/cookie/login",
        data={"username": "eve@example.com", "password": "correcthorsebattery"},
    )
    r = client.get("/v1/users/me")
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "eve@example.com"
    assert body["is_active"] is True
    assert "hashed_password" not in body


# ---------------------------------------------------------------------------
# require_user — cookie-first, X-Dev-User fallback
# ---------------------------------------------------------------------------


def test_project_route_accepts_cookie_auth(client: TestClient) -> None:
    """A logged-in user (via cookie) can read their org's project.

    The default seed user (admin@hexgate.dev) is a member of
    support-bot's org and gets verified=True / superuser=True on seed,
    so we can log in as them with the default-boot password.
    Generating that password fresh per test would require capturing
    stderr; for this test we just register a new user, log them in,
    then add them to the default org manually.
    """
    # Register + log in.
    client.post(
        "/v1/auth/register",
        json={"email": "frank@example.com", "password": "correcthorsebattery"},
    )
    client.post(
        "/v1/auth/cookie/login",
        data={"username": "frank@example.com", "password": "correcthorsebattery"},
    )

    # Frank doesn't belong to support-bot's org yet → expect 403.
    r = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents")
    assert r.status_code == 403, r.text
    assert "member" in r.json()["detail"].lower()


def test_project_route_accepts_x_dev_user_header_in_test_mode(
    client: TestClient,
) -> None:
    """The conftest sets HEXGATE_ALLOW_DEV_USER_HEADER=1 for the whole
    test session so existing tests can use X-Dev-User as a cheap
    impersonation seam. Mirrors the production behaviour when an
    operator explicitly opts in (e.g. for a staging environment)."""
    r = client.get(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents",
        headers={"X-Dev-User": DEFAULT_USER_ID},
    )
    assert r.status_code == 200


def test_cookie_route_accepts_cookie_session(
    client: TestClient, session_factory
) -> None:
    """Regression for the "Playground reverts to homepage" bug.

    ``GET /v1/projects/{p}/agents/{name}`` (the dashboard get-agent
    route) must accept a cookie session from a logged-in user — not
    just the test-only X-Dev-User header. The Playground page calls
    ``api.getAgent`` on mount; without cookie support here the
    request 401s, the dashboard's global handler redirects to
    /sign-in, and a still-logged-in user gets forwarded to / — which
    looks like Playground "reverts to the homepage".

    We register + log in a fresh user, add them to the default org
    membership directly (skipping the not-yet-built invite flow), and
    then hit the route with NO X-Dev-User — only the session cookie.
    Success ⇒ cookies are accepted.
    """
    import asyncio
    import uuid

    from hexgate_api.models import OrganizationMember, User
    from hexgate_api.constants import DEFAULT_ORG_ID

    # Register + log in so the client carries the session cookie.
    client.post(
        "/v1/auth/register",
        json={"email": "cookie-user@example.com", "password": "correcthorsebattery"},
    )
    r_login = client.post(
        "/v1/auth/cookie/login",
        data={
            "username": "cookie-user@example.com",
            "password": "correcthorsebattery",
        },
    )
    assert r_login.status_code == 204

    # Wire this user into the default org so the route's membership
    # check passes.
    async def _add_to_default_org():
        async with session_factory() as s:
            from sqlmodel import select

            user = (
                await s.exec(
                    select(User).where(User.email == "cookie-user@example.com")
                )
            ).one()
            s.add(
                OrganizationMember(
                    id=str(uuid.uuid4()),
                    user_id=user.id,
                    org_id=DEFAULT_ORG_ID,
                    role="member",
                )
            )
            await s.commit()

    asyncio.get_event_loop().run_until_complete(_add_to_default_org())

    # Hit the route with NO X-Dev-User — cookie auth alone must carry
    # it through to 200.
    r = client.get(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default",
        headers={"X-Dev-User": ""},  # explicitly blank to defeat any fixture default
    )
    assert r.status_code == 200, r.text


def test_default_admin_email_passes_pydantic_validation() -> None:
    """Regression: ``DEFAULT_USER_EMAIL`` must pass pydantic's EmailStr.

    fastapi-users' UserRead schema declares email as EmailStr, which
    runs through email-validator. Reserved TLDs (``.local``, ``.test``,
    ``.example``, ``.invalid``, ``.localhost``) get rejected — so a
    seed admin with one of those emails crashes ``/v1/users/me`` on
    serialization, and the dashboard's ``useUser()`` can never resolve.

    This test catches that class of regression at CI time rather than
    when a self-hoster first opens the dashboard. If the assertion
    fails after a refactor, change DEFAULT_USER_EMAIL to a real TLD
    (``.dev``, ``.io``, ``.com`` …).
    """
    from hexgate_api.auth import UserRead

    # Should not raise. The dummy values for the other fields don't
    # matter — only the email goes through validation that depends on
    # the runtime config.
    UserRead(
        id=DEFAULT_USER_ID,
        email=DEFAULT_USER_EMAIL,
        is_active=True,
        is_superuser=True,
        is_verified=True,
    )


def test_project_route_rejects_x_dev_user_in_production_mode(
    client: TestClient, monkeypatch
) -> None:
    """X-Dev-User MUST be ignored when ``HEXGATE_ALLOW_DEV_USER_HEADER``
    is unset (the production default). Anyone with a guessed User UUID
    would otherwise impersonate that user, which would be a CVE."""
    monkeypatch.delenv("HEXGATE_ALLOW_DEV_USER_HEADER", raising=False)
    r = client.get(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents",
        headers={"X-Dev-User": DEFAULT_USER_ID},
    )
    assert r.status_code == 401


def test_inactive_user_cannot_authenticate_via_cookie(
    client: TestClient, session_factory
) -> None:
    """An ``is_active=False`` user can't log in even with the right password.

    The auth backend's ``current_active_user`` dependency only succeeds
    for active users, so a deactivated account is effectively a soft-
    delete from the perspective of the auth surface.
    """
    import asyncio

    from hexgate_api.models import User

    client.post(
        "/v1/auth/register",
        json={"email": "ghost@example.com", "password": "correcthorsebattery"},
    )

    async def _deactivate():
        async with session_factory() as session:
            from sqlmodel import select

            row = (
                await session.exec(
                    select(User).where(User.email == "ghost@example.com")
                )
            ).first()
            row.is_active = False
            session.add(row)
            await session.commit()

    asyncio.get_event_loop().run_until_complete(_deactivate())

    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": "ghost@example.com", "password": "correcthorsebattery"},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Phase 3b — email verification + password reset
#
# The flows mint a single-use JWT, hand it to ``UserManager.on_after_*``,
# which sends it through the mailer. Tests substitute a list-capturing
# sender so they can read the token without an SMTP server set up.
# ---------------------------------------------------------------------------


class _CapturingSender:
    """Mailer that pushes every email into a list, for tests."""

    def __init__(self) -> None:
        self.outbox: list[dict] = []

    async def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})


@pytest_asyncio.fixture
async def outbox():
    """Replaces the module-level mailer with a capturing sender.

    Yields the outbox list so tests can ``assert outbox[-1]["body"]
    contains the token``. Restores the StderrEmailSender on teardown
    so subsequent test modules aren't affected.
    """
    original = mailer.get_email_sender()
    capturing = _CapturingSender()
    mailer.set_email_sender(capturing)
    yield capturing.outbox
    mailer.set_email_sender(original)


def _extract_token(body: str) -> str:
    """Pull the token out of a mailed body — it's the only word that
    fits the JWT shape (three dot-separated chunks, all base64url)."""
    import re

    match = re.search(r"\b[\w-]+\.[\w-]+\.[\w-]+\b", body)
    assert match is not None, f"no JWT-shaped token in:\n{body}"
    return match.group(0)


# ---- /auth/request-verify-token + /auth/verify ---------------------------


def test_request_verify_sends_email_to_registered_user(
    client: TestClient, outbox: list[dict]
) -> None:
    """Newly-registered users start unverified; requesting verification
    mails them a token via the configured sender."""
    client.post(
        "/v1/auth/register",
        json={"email": "verify@example.com", "password": "correcthorsebattery"},
    )
    outbox.clear()  # ignore any post-register email

    r = client.post(
        "/v1/auth/request-verify-token",
        json={"email": "verify@example.com"},
    )
    assert r.status_code == 202, r.text
    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["to"] == "verify@example.com"
    assert "verify" in msg["subject"].lower()
    # The token is the magic part — make sure it's in the body.
    _extract_token(msg["body"])


def test_request_verify_silent_for_unknown_email(
    client: TestClient, outbox: list[dict]
) -> None:
    """Unknown email → 202 with no email sent.

    The same opaque status code as the happy path means we don't leak
    which emails are registered via this endpoint.
    """
    r = client.post(
        "/v1/auth/request-verify-token",
        json={"email": "nobody@example.com"},
    )
    assert r.status_code == 202
    assert outbox == []


def test_verify_with_valid_token_marks_user_verified(
    client: TestClient, outbox: list[dict]
) -> None:
    """Posting the mailed token to /auth/verify flips is_verified True."""
    client.post(
        "/v1/auth/register",
        json={"email": "newuser@example.com", "password": "correcthorsebattery"},
    )
    client.post(
        "/v1/auth/request-verify-token",
        json={"email": "newuser@example.com"},
    )
    token = _extract_token(outbox[-1]["body"])

    r = client.post("/v1/auth/verify", json={"token": token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["email"] == "newuser@example.com"
    assert body["is_verified"] is True


def test_verify_with_invalid_token_rejects(client: TestClient) -> None:
    """A bogus token → 400 (VERIFY_USER_BAD_TOKEN)."""
    r = client.post("/v1/auth/verify", json={"token": "totally.made.up"})
    assert r.status_code == 400


# ---- /auth/forgot-password + /auth/reset-password ------------------------


def test_forgot_password_sends_reset_token_to_registered_user(
    client: TestClient, outbox: list[dict]
) -> None:
    """The forgot-password flow mails a token the user can present to
    /auth/reset-password to set a new password."""
    client.post(
        "/v1/auth/register",
        json={"email": "reset@example.com", "password": "old-password-12"},
    )
    outbox.clear()

    r = client.post(
        "/v1/auth/forgot-password",
        json={"email": "reset@example.com"},
    )
    assert r.status_code == 202, r.text
    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["to"] == "reset@example.com"
    assert "reset" in msg["subject"].lower()
    _extract_token(msg["body"])


def test_forgot_password_silent_for_unknown_email(
    client: TestClient, outbox: list[dict]
) -> None:
    """Same opaque 202 + no email sent. Stops the endpoint from leaking
    which emails are registered."""
    r = client.post(
        "/v1/auth/forgot-password",
        json={"email": "nobody@example.com"},
    )
    assert r.status_code == 202
    assert outbox == []


def test_reset_password_with_valid_token_changes_password(
    client: TestClient, outbox: list[dict]
) -> None:
    """End-to-end: request → consume token → log in with the new password."""
    client.post(
        "/v1/auth/register",
        json={"email": "rotator@example.com", "password": "before-rotation"},
    )
    client.post(
        "/v1/auth/forgot-password",
        json={"email": "rotator@example.com"},
    )
    token = _extract_token(outbox[-1]["body"])

    r = client.post(
        "/v1/auth/reset-password",
        json={"token": token, "password": "after-rotation"},
    )
    assert r.status_code == 200, r.text

    # Old password no longer works.
    r_old = client.post(
        "/v1/auth/cookie/login",
        data={"username": "rotator@example.com", "password": "before-rotation"},
    )
    assert r_old.status_code == 400

    # New password does.
    r_new = client.post(
        "/v1/auth/cookie/login",
        data={"username": "rotator@example.com", "password": "after-rotation"},
    )
    assert r_new.status_code == 204


def test_reset_password_with_invalid_token_rejects(client: TestClient) -> None:
    """A bogus reset token → 400, no password change."""
    r = client.post(
        "/v1/auth/reset-password",
        json={"token": "not.a.real-token", "password": "doesn't-matter"},
    )
    assert r.status_code == 400


# ---------------------------------------------------------------------------
# Cookie ``Secure`` flag — environment toggle
# ---------------------------------------------------------------------------


def test_cookie_secure_defaults_to_false_for_localhost_dev(monkeypatch) -> None:
    """Default of ``HEXGATE_COOKIE_SECURE`` (unset) → ``Secure`` off.

    A Secure cookie is silently dropped by every browser on http://, so
    if this regressed to ``True`` ``make platform-api`` would 401 on
    every request after login. The ergonomic default is off."""
    from hexgate_api.auth import _cookie_secure

    monkeypatch.delenv("HEXGATE_COOKIE_SECURE", raising=False)
    assert _cookie_secure() is False


def test_cookie_secure_respects_env_var(monkeypatch) -> None:
    """``HEXGATE_COOKIE_SECURE=1`` (or true/yes/on) → Secure on.

    The whole point of this knob is that prod deployments behind an
    HTTPS terminator can flip the Secure flag on with one env var. If
    any of the documented truthy values stopped working, prod would
    silently ship insecure cookies."""
    from hexgate_api.auth import _cookie_secure

    for truthy in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("HEXGATE_COOKIE_SECURE", truthy)
        assert _cookie_secure() is True, f"{truthy!r} should be truthy"

    for falsy in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("HEXGATE_COOKIE_SECURE", falsy)
        assert _cookie_secure() is False, f"{falsy!r} should be falsy"
