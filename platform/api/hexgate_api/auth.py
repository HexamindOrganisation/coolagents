"""FastAPI Users wiring — registration, login, cookie sessions.

This module owns the human-side auth surface: ``POST /v1/auth/register``,
cookie login/logout, password reset (Phase 3b later), and the
``current_active_user`` / ``current_active_user_optional`` dependencies
the rest of the route table consumes.

The two auth surfaces (humans via cookie, machines via biscuit) stay
separate by design — biscuits live in ``main._validate_sdk_token`` and
``require_project``; this module never touches them. See
``m3-platform-auth.md`` for the dual-surface rationale.

ID type is ``str`` (UUID-formatted) rather than ``uuid.UUID`` so the
column types stay aligned with the rest of our str-keyed SQLModel
tables. FastAPI Users is generic over the ID type — both
``SQLAlchemyUserDatabase`` and ``FastAPIUsers`` accept the parametrised
form ``[User, str]`` without any extra adapter code.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers, schemas
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from httpx_oauth.clients.google import GoogleOAuth2
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.core.mailer import _redact_email, get_email_sender
from hexgate_api.models import OAuthAccount, User

logger = logging.getLogger("hexgate.platform.auth")


# ---------------------------------------------------------------------------
# Pydantic schemas — wire shapes for register / read / update
# ---------------------------------------------------------------------------


class UserRead(schemas.BaseUser[str]):
    """What clients see on ``GET /v1/users/me`` and the register response.

    Inherits ``id`` / ``email`` / ``is_active`` / ``is_superuser`` /
    ``is_verified`` from the FastAPI Users base. ``hashed_password`` is
    intentionally NOT exposed — schemas.BaseUser excludes it.
    """


class UserCreate(schemas.BaseUserCreate):
    """Body of ``POST /v1/auth/register`` — just ``email`` + ``password``.

    Extra fields the model carries (``is_active``, ``is_superuser``) are
    server-controlled and ignored if a client tries to send them.
    """


class UserUpdate(schemas.BaseUserUpdate):
    """Body of ``PATCH /v1/users/me`` — limited self-service updates."""


# ---------------------------------------------------------------------------
# Database adapter + user manager
# ---------------------------------------------------------------------------


async def get_user_db(
    session: AsyncSession = Depends(get_session),
) -> AsyncGenerator[SQLAlchemyUserDatabase, None]:
    """Yield the FastAPI Users SQLAlchemy adapter bound to a per-request session.

    Same ``get_session`` every other route handler uses — one async
    session per request, scoped to the dependency-injection lifecycle.
    Passes ``oauth_account_table=OAuthAccount`` so the adapter can write
    OAuth links (Phase 3c) into the same DB transaction as the User
    upsert during the OAuth callback flow.
    """
    yield SQLAlchemyUserDatabase(session, User, OAuthAccount)


def _session_secret() -> str:
    """Derive a stable session-JWT secret from the platform's signing key.

    Lazy import of the ``core.keystore`` singleton (read at call time) so a
    test swap of ``core.keystore.keystore`` is picked up. Domain-separation
    prefix keeps this distinct from any other key derivation off the same
    root. Rotating the keystore invalidates every session — that's the right
    blast radius.
    """
    from hexgate_api.core.keystore import keystore

    return hashlib.sha256(
        b"hexagate-session-v1:" + keystore._private_key_bytes()
    ).hexdigest()


_SESSION_TTL_SECONDS = 7 * 24 * 3600  # 7 days; rolling refresh comes later


def _dashboard_url() -> str:
    """Base URL the verify/reset emails render their magic links against.

    Env-overridable so production deployments can point at their hosted
    dashboard while dev defaults to the Vite server on localhost:5173.
    Trailing slash is stripped so f"{url}/path" always renders cleanly.
    """
    return os.environ.get("HEXGATE_DASHBOARD_URL", "http://localhost:5173").rstrip("/")


def _cookie_secure() -> bool:
    """Whether to set the ``Secure`` flag on session + CSRF cookies.

    Default is ``False`` so ``make platform-api`` works over plain HTTP
    on localhost (a Secure cookie is silently dropped by every browser
    on http://). Production deployments behind an HTTPS terminator MUST
    set ``HEXGATE_COOKIE_SECURE=1`` (or ``true``/``yes``/``on``) — without
    it, a hostile network can sniff or strip the session cookie on the
    first request that drops back to HTTP.

    Truthy values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).
    Everything else, including unset, evaluates to ``False``.
    """
    return os.environ.get("HEXGATE_COOKIE_SECURE", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


class UserManager(BaseUserManager[User, str]):
    """User lifecycle hooks (register / login / password reset).

    Phase 3a wires the structural pieces but leaves the email-sending
    hooks as info-level logs — Phase 3b plugs Resend in. ``parse_id``
    is the only protocol method we MUST override for str IDs (the
    default expects uuid.UUID).
    """

    # The token secrets sign reset / verify links. Lazy via @property
    # so the keystore can be patched in tests without restamping these
    # at module import time.
    @property
    def reset_password_token_secret(self) -> str:  # type: ignore[override]
        return _session_secret()

    @property
    def verification_token_secret(self) -> str:  # type: ignore[override]
        return _session_secret()

    def parse_id(self, value: Any) -> str:
        """ID is a str. FastAPI Users calls this on path-string IDs."""
        return str(value)

    async def on_after_register(
        self, user: User, request: Request | None = None
    ) -> None:
        """Hook after a successful ``POST /v1/auth/register``.

        Two things happen on first registration:

          1. Log it. Operators tail stderr for "user registered" lines
             during demos; later this becomes a webhook.
          2. **Create a personal "default" Org** owned by the new
             user so the dashboard never lands on an empty
             "no orgs yet" state. The org's slug is derived from the
             email prefix with collision fallback (see
             :func:`services._generate_unique_org_slug`).

        Caveat: FastAPI-Users commits the User row BEFORE calling this
        hook. The two writes are therefore NOT in one transaction — if
        the org-create fails here the user row stays committed and the
        account lands without an org. The repair path in
        ``GET /v1/orgs`` (``api_list_orgs``) covers that case by
        invoking :func:`ensure_personal_default_org` lazily for any
        orgless user, so the hook is best-effort eager bootstrap and
        the listing endpoint is the recovery net.

        Verification stays separate — registering and verifying are
        decoupled so the dashboard can gate destructive actions on
        ``is_verified`` at its own moment and call
        ``POST /auth/request-verify-token`` independently.
        """
        from hexgate_api.domains.orgs.service import ensure_personal_default_org

        # Redact the email — same PII rule the mailer error path uses
        # (al***@domain). User id is the durable handle for support.
        logger.info("user registered: %s (id=%s)", _redact_email(user.email), user.id)
        # ``self.user_db.session`` is the same async session the User
        # insert used — but FastAPI-Users has already committed it by
        # the time we get here. Idempotency guarantees of the helper
        # mean a retried registration after a transient error still
        # doesn't create duplicate default orgs.
        session = self.user_db.session  # SQLAlchemyUserDatabase exposes this
        await ensure_personal_default_org(session, user)

    async def on_after_forgot_password(
        self, user: User, token: str, request: Request | None = None
    ) -> None:
        """Hook when a password reset is requested.

        Sends a magic-link email containing ``token`` so the recipient
        can land on the dashboard's reset form pre-loaded with it. The
        link URL is rendered from ``HEXGATE_DASHBOARD_URL`` (defaults
        to localhost:5173 for dev). Dev mode prints the email to stderr
        via :class:`StderrEmailSender`; production swaps in a real
        provider via :func:`mailer.set_email_sender`.
        """
        link = f"{_dashboard_url()}/reset-password/{token}"
        body = (
            f"Hi {user.email},\n\n"
            f"Someone requested a password reset for your Hexgate account.\n"
            f"If that was you, use this link within the next hour:\n\n"
            f"    {link}\n\n"
            f"If it wasn't you, ignore this email — your password stays put.\n"
        )
        try:
            await get_email_sender().send(
                to=user.email,
                subject="Reset your Hexgate password",
                body=body,
            )
        except Exception:
            # Mailer logs with the recipient redacted; we just need to
            # stop the exception from 5xx-ing /v1/auth/forgot-password.
            # User can request a new link; operator sees the mailer log.
            logger.exception("password-reset email could not be sent")

    async def on_after_request_verify(
        self, user: User, token: str, request: Request | None = None
    ) -> None:
        """Hook when a verification email is requested.

        Same shape as the reset flow: mints a token, mails a dashboard
        link that consumes it. ``HEXGATE_DASHBOARD_URL`` controls the
        host.
        """
        link = f"{_dashboard_url()}/verify-email/{token}"
        body = (
            f"Hi {user.email},\n\n"
            f"Welcome to Hexgate. Click this link to verify your email:\n\n"
            f"    {link}\n\n"
            f"Unverified accounts can sign in but won't be able to invite\n"
            f"teammates or mint API tokens until verification completes.\n"
        )
        try:
            await get_email_sender().send(
                to=user.email,
                subject="Verify your Hexgate account",
                body=body,
            )
        except Exception:
            # Don't 5xx /v1/auth/request-verify-token over a Resend
            # outage — the user can retry from the dashboard banner.
            logger.exception("verification email could not be sent")


async def get_user_manager(
    user_db: SQLAlchemyUserDatabase = Depends(get_user_db),
) -> AsyncGenerator[UserManager, None]:
    yield UserManager(user_db)


# ---------------------------------------------------------------------------
# Authentication backend — cookie transport + JWT strategy
# ---------------------------------------------------------------------------


cookie_transport = CookieTransport(
    cookie_name="hexgate_session",
    cookie_max_age=_SESSION_TTL_SECONDS,
    # ``Secure`` would refuse the cookie over plain HTTP — fine in prod
    # (HTTPS terminator in front), wrong for ``make platform-api`` which
    # serves on localhost over HTTP. ``HEXGATE_COOKIE_SECURE=1`` flips
    # the flag on for production; default is off for dev ergonomics.
    cookie_secure=_cookie_secure(),
    cookie_httponly=True,
    # ``lax`` — strict breaks OAuth redirects when we add Google sign-in
    # (Phase 3c). The OWASP recommendation for general use is lax.
    cookie_samesite="lax",
)


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=_session_secret(), lifetime_seconds=_SESSION_TTL_SECONDS)


auth_backend = AuthenticationBackend(
    name="cookie",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)


# ---------------------------------------------------------------------------
# FastAPIUsers instance + the dependencies the rest of the API consumes
# ---------------------------------------------------------------------------


fastapi_users = FastAPIUsers[User, str](
    get_user_manager,
    [auth_backend],
)


# Returns the current ``User`` row or raises 401. Used by ``GET /v1/users/me``
# and (Phase 3a) consulted by ``require_user`` before the X-Dev-User fallback.
current_active_user = fastapi_users.current_user(active=True)

# Returns the current ``User`` or ``None`` (no raise) — the variant
# ``require_user`` actually uses, so it can fall back to X-Dev-User
# during the transition without a try/except.
current_active_user_optional = fastapi_users.current_user(active=True, optional=True)


# ---------------------------------------------------------------------------
# Phase 3c — Google OAuth
#
# The OAuth router is mounted conditionally — only when the operator has
# set HEXGATE_GOOGLE_CLIENT_ID + HEXGATE_GOOGLE_CLIENT_SECRET. That keeps
# `make platform-api` working out of the box without any Google Cloud
# Console setup, and turns OAuth on as a single env flip when ready.
# ---------------------------------------------------------------------------


def _oauth_state_secret() -> str:
    """Derive the OAuth state-token signing secret from the keystore.

    Same domain-separated SHA-256 trick as :func:`_session_secret`, with
    a distinct prefix so the same keystore can't be exploited via
    cross-purpose tokens. State tokens are short-lived (the lifetime of
    one authorize/callback round trip) so rotation cost is essentially
    zero — a key rotation invalidates any pending OAuth flows, which is
    exactly what you'd want.
    """
    from hexgate_api.core.keystore import keystore

    return hashlib.sha256(
        b"hexagate-oauth-state-v1:" + keystore._private_key_bytes()
    ).hexdigest()


def build_google_oauth_router() -> APIRouter | None:
    """Return the Google OAuth router if env-configured, else ``None``.

    Two endpoints get mounted:
      * ``GET /authorize`` → returns the Google consent URL with a
        state token the SDK / dashboard then redirects the user to.
      * ``GET /callback``  → handles Google's redirect back, exchanges
        the code for tokens, upserts the User + OAuthAccount, and
        issues the same ``hexgate_session`` cookie a password login
        would have set.

    ``associate_by_email=True``: if a Google account's email matches an
    existing User (from email/password registration), link the OAuth
    account onto that user instead of creating a duplicate row. Stops
    "you already have an account" deadends on first Google sign-in for
    users who used email/password earlier.

    ``is_verified_by_default=True``: a user that successfully completed
    Google OAuth has, by definition, a verified email — Google verified
    it for us. Skip the platform's own verify-email step in that case.

    Env vars are read at call time (not module import) so tests can
    monkeypatch them before the lifespan triggers this builder.
    """
    client_id = os.environ.get("HEXGATE_GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("HEXGATE_GOOGLE_CLIENT_SECRET")
    if not (client_id and client_secret):
        return None
    google_client = GoogleOAuth2(client_id, client_secret)
    return fastapi_users.get_oauth_router(
        google_client,
        auth_backend,
        _oauth_state_secret(),
        associate_by_email=True,
        is_verified_by_default=True,
        # FastAPI Users defaults the CSRF cookie to ``secure=True`` (HTTPS
        # only). That breaks ``make platform-api`` over localhost HTTP +
        # tests over http://testserver — the browser sets the cookie but
        # never sends it back on /callback, so state verification fails.
        # Track the session cookie's flag: ``HEXGATE_COOKIE_SECURE=1``
        # flips both on in production, neither in dev.
        csrf_token_cookie_secure=_cookie_secure(),
    )
