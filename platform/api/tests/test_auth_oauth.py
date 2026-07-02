"""Tests for Google OAuth wiring (M3 Phase 3c).

The actual round-trip to Google's auth servers is mocked — we patch
``GoogleOAuth2.get_access_token`` + ``GoogleOAuth2.get_id_email`` so
the callback flow runs end-to-end inside the test process. What's
proven:

  * Router builder returns ``None`` when env vars are absent and an
    ``APIRouter`` when both are set.
  * The ``/authorize`` endpoint returns a Google consent URL carrying
    our signed state token.
  * The ``/callback`` endpoint creates a User + OAuthAccount row on
    first sign-in.
  * Same Google email signing in a second time after an email/password
    User already exists → the OAuth account links to that existing
    User (not a duplicate).

Real-world OAuth correctness (state signature validation, code
exchange, scope handling) is the library's responsibility; these tests
focus on our wiring around it.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx_oauth.clients.google import GoogleOAuth2
from httpx_oauth.oauth2 import OAuth2Token
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api import main
from hexgate_api.main import app
from hexgate_api.models import OAuthAccount, User
from hexgate_api.bootstrap.seed import ensure_default_project


# ---------------------------------------------------------------------------
# Builder-level tests — env switching, no app needed
# ---------------------------------------------------------------------------


def test_build_router_returns_none_without_env(monkeypatch) -> None:
    """No env vars → no router. ``make platform-api`` works out of the box."""
    monkeypatch.delenv("HEXGATE_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("HEXGATE_GOOGLE_CLIENT_SECRET", raising=False)
    # build_google_oauth_router calls into the keystore for the state
    # secret — ensure it's initialised so the call doesn't blow up
    # before it hits the env-var check we actually care about.
    main.keystore.ensure_keypair()
    from hexgate_api.auth import build_google_oauth_router

    assert build_google_oauth_router() is None


def test_build_router_returns_router_with_env(monkeypatch) -> None:
    """With both env vars set → APIRouter with /authorize + /callback."""
    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_SECRET", "test-secret")
    main.keystore.ensure_keypair()
    from hexgate_api.auth import build_google_oauth_router

    router = build_google_oauth_router()
    assert router is not None
    paths = {route.path for route in router.routes}
    assert "/authorize" in paths
    assert "/callback" in paths


# ---------------------------------------------------------------------------
# Registration-order guard — the SPA catch-all must not shadow OAuth routes
# ---------------------------------------------------------------------------


def test_spa_catchall_does_not_shadow_oauth_routes(monkeypatch, tmp_path) -> None:
    """Pin the lifespan's registration order: OAuth router first, SPA last.

    The ``oauth_client`` fixture below sidesteps the lifespan (it touches the
    real DB), so without this the moved ``mount_spa`` catch-all is registered
    in no test — a future reorder that mounts the SPA before the OAuth router
    would silently shadow ``/v1/auth/google/*`` and break Google sign-in while
    the suite stayed green. Here we rebuild the exact production wiring on a
    throwaway app (v1 router → OAuth router → ``mount_spa``) and assert the
    OAuth route still wins over the ``/{full_path:path}`` catch-all.
    """
    from hexgate_api.auth import build_google_oauth_router
    from hexgate_api.core.spa import mount_spa

    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_SECRET", "test-secret")
    main.keystore.ensure_keypair()

    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>app</title>")
    monkeypatch.setenv("HEXGATE_DASHBOARD_DIST", str(dist))

    # Same order as main.lifespan: v1 routes, then the OAuth router, then the
    # SPA catch-all LAST.
    app = FastAPI()
    app.include_router(main.v1)
    google_router = build_google_oauth_router()
    assert google_router is not None
    app.include_router(google_router, prefix="/v1/auth/google", tags=["auth"])
    mount_spa(app)

    client = TestClient(app)

    # OAuth authorize resolves — not shadowed by the catch-all.
    r = client.get("/v1/auth/google/authorize", params={"scopes": ["openid", "email"]})
    assert r.status_code == 200, r.text
    assert r.json()["authorization_url"].startswith("https://accounts.google.com")

    # The catch-all IS present (a real SPA route returns index.html)...
    assert "text/html" in client.get("/some/client/route").headers["content-type"]
    # ...but never swallows an unknown API path as the SPA.
    nf = client.get("/v1/does-not-exist")
    assert nf.status_code == 404
    assert nf.json() == {"detail": "Not Found"}


# ---------------------------------------------------------------------------
# End-to-end callback flow — requires the lifespan to have run with env set.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory():
    """Fresh in-memory async DB with the schema + the triple-default seed."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        await ensure_default_project(s)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def oauth_client(monkeypatch, session_factory, tmp_path) -> TestClient:
    """TestClient with Google OAuth env vars set + mocked HTTP calls.

    Patches ``GoogleOAuth2.get_access_token`` and ``.get_id_email`` so
    the callback never actually reaches Google — tests control the
    canned response that "Google" would have returned.

    The OAuth router normally mounts inside ``main._maybe_mount_oauth_routers``
    during lifespan startup. Tests sidestep the lifespan (which would
    touch the real hexgate.db + run backfill) and mount the router
    directly here once the keystore is initialised. The mounted route
    persists on ``app`` across tests in this file — fine because each
    test rebuilds the in-memory DB and the OAuth wiring doesn't carry
    cross-test state.
    """
    from hexgate_api.auth import build_google_oauth_router
    from hexgate_api.core.db import get_session
    from hexgate_api.core.keystore import FileKeyStore

    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("HEXGATE_GOOGLE_CLIENT_SECRET", "test-secret")

    # Fake the Google round-trip. Both methods get awaited by httpx-oauth
    # / fastapi-users; we return canned values that tests can mutate
    # via the ``fake`` dict exposed on the returned client.
    fake = {"account_id": "google-sub-12345", "email": "gauser@example.com"}

    async def fake_get_access_token(self, code, redirect_uri, code_verifier=None):
        return OAuth2Token(
            {"access_token": "fake-access-token", "token_type": "bearer"}
        )

    async def fake_get_id_email(self, token):
        return fake["account_id"], fake["email"]

    monkeypatch.setattr(GoogleOAuth2, "get_access_token", fake_get_access_token)
    monkeypatch.setattr(GoogleOAuth2, "get_id_email", fake_get_id_email)

    async def override_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    original_keystore = main.keystore
    main.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    main.keystore.ensure_keypair()

    # Mount the OAuth router now (lifespan would have done this in
    # production). Safe to call multiple times — FastAPI appends; the
    # first match still wins on duplicate routes.
    google_router = build_google_oauth_router()
    assert google_router is not None  # env vars were set above
    app.include_router(google_router, prefix="/v1/auth/google", tags=["auth"])
    # Rebuild OpenAPI so the new routes are findable in the dispatcher.
    app.openapi_schema = None

    try:
        client = TestClient(app)
        client.fake = fake  # type: ignore[attr-defined]
        yield client
    finally:
        app.dependency_overrides.clear()
        main.keystore = original_keystore


def _state_from_authorize_url(authorize_url: str) -> str:
    """Pull the signed state JWT out of the Google consent URL."""
    qs = parse_qs(urlparse(authorize_url).query)
    assert "state" in qs, f"no state in URL: {authorize_url}"
    return qs["state"][0]


def test_authorize_returns_google_consent_url(oauth_client: TestClient) -> None:
    """GET /authorize returns the Google URL with our signed state."""
    r = oauth_client.get(
        "/v1/auth/google/authorize",
        params={"scopes": ["openid", "email"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "authorization_url" in body
    url = body["authorization_url"]
    parsed = urlparse(url)
    assert parsed.netloc == "accounts.google.com"
    qs = parse_qs(parsed.query)
    assert qs["client_id"] == ["test-client-id"]
    assert "state" in qs
    # Scopes we asked for show up on the URL.
    scope = qs["scope"][0]
    assert "openid" in scope and "email" in scope


def test_callback_creates_new_user_and_oauth_link(
    oauth_client: TestClient, session_factory
) -> None:
    """First Google sign-in → new User + new OAuthAccount + session cookie."""
    import asyncio

    # Get a real state from /authorize so the callback's signature check passes.
    r_auth = oauth_client.get(
        "/v1/auth/google/authorize",
        params={"scopes": ["openid", "email"]},
    )
    state = _state_from_authorize_url(r_auth.json()["authorization_url"])

    oauth_client.fake["email"] = "newgoogle@example.com"  # type: ignore[attr-defined]
    oauth_client.fake["account_id"] = "google-sub-new"  # type: ignore[attr-defined]

    # The library's /callback is GET (Google redirects with code + state).
    # ``follow_redirects=False`` so we can inspect the Set-Cookie header
    # that fastapi-users would send before any redirect.
    r_cb = oauth_client.get(
        "/v1/auth/google/callback",
        params={"code": "fake-code", "state": state},
        follow_redirects=False,
    )
    assert r_cb.status_code in (200, 204, 302, 307), r_cb.text
    assert "hexgate_session=" in r_cb.headers.get("set-cookie", "")

    # Verify the DB state — one User, one OAuthAccount linking them.
    async def _check():
        async with session_factory() as s:
            users = (
                await s.exec(select(User).where(User.email == "newgoogle@example.com"))
            ).all()
            assert len(users) == 1, f"expected 1 user, got {len(users)}"
            user = users[0]
            # Google sign-in implies verified email.
            assert user.is_verified is True
            # FastAPI Users seeds hashed_password with a hash of a
            # random secret for OAuth-only users (the column is
            # non-null, but the user can't actually log in with a
            # password — they'd need to use forgot-password to set one).
            # The test just confirms a hash got persisted.
            assert user.hashed_password.startswith("$")

            links = (
                await s.exec(
                    select(OAuthAccount).where(OAuthAccount.user_id == user.id)
                )
            ).all()
            assert len(links) == 1
            link = links[0]
            assert link.oauth_name == "google"
            assert link.account_id == "google-sub-new"
            assert link.account_email == "newgoogle@example.com"

    asyncio.get_event_loop().run_until_complete(_check())


def test_callback_returning_user_reuses_existing_row(
    oauth_client: TestClient, session_factory
) -> None:
    """A second sign-in by the same Google account → no duplicate.

    fastapi-users looks up the existing User via
    (oauth_name, account_id) and reissues a session for it. Without
    this guarantee, the unique constraint on
    ``(oauth_name, account_id)`` in OAuthAccount would raise on the
    second callback, OR a duplicate User row would slip in if the
    lookup were wrong. We pin both invariants explicitly.
    """
    import asyncio

    oauth_client.fake["email"] = "returning@example.com"  # type: ignore[attr-defined]
    oauth_client.fake["account_id"] = "google-sub-returning"  # type: ignore[attr-defined]

    def _do_one_signin() -> dict:
        """Run a full /authorize → /callback dance, return the cookie set."""
        r_auth = oauth_client.get(
            "/v1/auth/google/authorize",
            params={"scopes": ["openid", "email"]},
        )
        state = _state_from_authorize_url(r_auth.json()["authorization_url"])
        r_cb = oauth_client.get(
            "/v1/auth/google/callback",
            params={"code": "fake-code", "state": state},
            follow_redirects=False,
        )
        assert r_cb.status_code in (200, 204, 302, 307), r_cb.text
        return r_cb.headers

    # First sign-in — creates the rows.
    headers1 = _do_one_signin()
    assert "hexgate_session=" in headers1.get("set-cookie", "")

    # Second sign-in by the same Google account — must succeed without
    # tripping the unique constraint, and must NOT create duplicates.
    headers2 = _do_one_signin()
    assert "hexgate_session=" in headers2.get("set-cookie", "")

    async def _check_no_duplicates():
        async with session_factory() as s:
            users = (
                await s.exec(select(User).where(User.email == "returning@example.com"))
            ).all()
            assert len(users) == 1, (
                f"duplicate Users after returning sign-in: {len(users)}"
            )
            links = (
                await s.exec(
                    select(OAuthAccount).where(
                        OAuthAccount.account_id == "google-sub-returning"
                    )
                )
            ).all()
            assert len(links) == 1, (
                f"duplicate OAuthAccounts after returning sign-in: {len(links)}"
            )

    asyncio.get_event_loop().run_until_complete(_check_no_duplicates())


def test_callback_links_to_existing_email_user(
    oauth_client: TestClient, session_factory
) -> None:
    """A Google sign-in whose email matches an existing User → that
    User gets the OAuthAccount linked, no duplicate User row.

    Stops the "you already have an account" deadend when a user
    registered with email/password earlier and now wants to sign in
    via Google."""
    import asyncio

    # Pre-register via email/password.
    r_reg = oauth_client.post(
        "/v1/auth/register",
        json={"email": "linked@example.com", "password": "before-google-12"},
    )
    assert r_reg.status_code == 201

    # Now OAuth with the same email.
    r_auth = oauth_client.get(
        "/v1/auth/google/authorize",
        params={"scopes": ["openid", "email"]},
    )
    state = _state_from_authorize_url(r_auth.json()["authorization_url"])

    oauth_client.fake["email"] = "linked@example.com"  # type: ignore[attr-defined]
    oauth_client.fake["account_id"] = "google-sub-linked"  # type: ignore[attr-defined]

    r_cb = oauth_client.get(
        "/v1/auth/google/callback",
        params={"code": "fake-code", "state": state},
        follow_redirects=False,
    )
    assert r_cb.status_code in (200, 204, 302, 307), r_cb.text

    async def _check():
        async with session_factory() as s:
            # Still exactly one User for this email.
            users = (
                await s.exec(select(User).where(User.email == "linked@example.com"))
            ).all()
            assert len(users) == 1, f"duplicate Users: {len(users)}"
            user = users[0]
            # The password they set during email/password registration is
            # preserved — they can still log in with it.
            assert user.hashed_password != ""

            # OAuthAccount links to the same User row.
            links = (
                await s.exec(
                    select(OAuthAccount).where(OAuthAccount.user_id == user.id)
                )
            ).all()
            assert len(links) == 1
            assert links[0].account_id == "google-sub-linked"

    asyncio.get_event_loop().run_until_complete(_check())


# A no-op reference to httpx so the import isn't flagged as unused — the
# library is imported here as a hint to test maintainers about where the
# OAuth client gets its HTTP transport from.
_ = httpx
