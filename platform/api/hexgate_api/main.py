import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import (
    APIRouter,
    FastAPI,
)
from fastapi.middleware.cors import CORSMiddleware

from hexgate_api.core.clickhouse import ping as clickhouse_ping
from hexgate_api.core.db import async_session_factory, init_db
from hexgate_api.core.keystore import FileKeyStore
from hexgate_api import health
from hexgate_api.domains.agents.service import backfill_bundles
from hexgate_api.bootstrap.seed import ensure_default_project


# Load .env into os.environ before any HEXGATE_* read (CORS + keystore
# resolve at import time). Real env vars still take precedence.
load_dotenv()

keystore = FileKeyStore()
_log = logging.getLogger(__name__)


def _demo_enabled() -> bool:
    """Whether single-tenant demo mode is on (see platform/api/demo.py).

    Off by default. When on, the API exposes a *passwordless* ``/v1/demo-login``
    for the seeded admin — safe only in an ephemeral throwaway container. (The
    same-origin dashboard serving is no longer demo-specific; see
    :func:`spa.mount_spa`, wired in both modes.)
    """
    return os.environ.get("HEXGATE_DEMO", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _configure_email_sender() -> None:
    """Swap the dev stderr sender for Resend if both env vars are set.

    Three cases, three log levels:
      * both set → INFO "Resend wired" — production happy path.
      * neither set → INFO "dev stderr sender" — clean dev mode.
      * exactly one set → WARNING naming the missing var — operator
        misconfig; falls back to stderr rather than half-broken Resend.
    """
    from hexgate_api.core.mailer import (
        ResendEmailSender,
        StderrEmailSender,
        set_email_sender,
    )

    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    from_addr = os.environ.get("HEXGATE_EMAIL_FROM", "").strip()
    if api_key and from_addr:
        set_email_sender(ResendEmailSender(api_key=api_key, from_addr=from_addr))
        _log.info("email: Resend sender wired (from=%s)", from_addr)
        return
    # Reset to stderr explicitly so a re-config (test, lifespan-restart)
    # that clears env vars doesn't leave a stale Resend sender wired.
    set_email_sender(StderrEmailSender())
    if api_key or from_addr:
        missing = "HEXGATE_EMAIL_FROM" if api_key else "RESEND_API_KEY"
        present = "RESEND_API_KEY" if api_key else "HEXGATE_EMAIL_FROM"
        _log.warning(
            "email: partial Resend config — %s is set but %s is not. "
            "Falling back to dev stderr sender; real mail will NOT be sent.",
            present,
            missing,
        )
    else:
        _log.info(
            "email: dev stderr sender — set RESEND_API_KEY and HEXGATE_EMAIL_FROM "
            "to deliver real mail (verification + password reset)."
        )


@asynccontextmanager
async def lifespan(app_: FastAPI):
    await init_db()
    keystore.ensure_keypair()
    # OAuth router mounting waits on the keystore — its state-token
    # secret is derived from the keystore's private key (see
    # auth._oauth_state_secret). Doing this at module load would race
    # the lifespan; the include here runs once at startup, before any
    # request reaches the app.
    _maybe_mount_oauth_routers()
    # SPA catch-all goes on LAST — after the OAuth router just mounted — so
    # /{path} never shadows /v1/auth/google/*. (Static /v1 routes are already
    # registered at import; only the OAuth router mounts here at startup, so the
    # SPA must follow it.) Demo mode mounts the same SPA + a passwordless login.
    if _demo_enabled():
        from hexgate_api.demo import enable_demo

        enable_demo(app)
    else:
        from hexgate_api.core.spa import mount_spa

        mount_spa(app)
    async with async_session_factory() as session:
        await ensure_default_project(session)
        # Backfill signed bundles for seeded agents so they're served via
        # WASM on the first request, not just after their first edit.
        await backfill_bundles(session, keystore.sign)
    # Don't fail startup on unreachable ClickHouse — /ready surfaces it.
    if not clickhouse_ping():
        _log.warning(
            "ClickHouse unreachable at startup; audit endpoints will 503 until reachable"
        )
    # Surface deployment config at startup so a misconfig shows in logs
    # rather than as a silent browser CORS/cookie failure.
    from hexgate_api.auth import _cookie_secure, _dashboard_url

    _log.info(
        "hexgate-api startup config: cors_origins=%s cookie_secure=%s dashboard_url=%s",
        _cors_origins(),
        _cookie_secure(),
        _dashboard_url(),
    )
    _configure_email_sender()
    if _demo_enabled():
        _log.warning(
            "⚠ HEXGATE_DEMO is ON — /v1/demo-login grants a PASSWORDLESS session "
            "for the seeded admin. Use ONLY in an ephemeral throwaway container, "
            "NEVER on a persistent/real deployment."
        )
    yield


app = FastAPI(title="Hexgate API", version="0.1.0", lifespan=lifespan)


_DEFAULT_CORS_ORIGINS = ["http://localhost:5173"]


def _cors_origins() -> list[str]:
    """Allowed browser origins from comma-separated ``HEXGATE_CORS_ORIGINS``.

    Entries are trailing-slash/whitespace-stripped to match the ``Origin``
    header. Unset or unparseable falls back to the dev default. No wildcard:
    credentialed CORS forbids it, so production must list explicit origins.
    """
    raw = os.environ.get("HEXGATE_CORS_ORIGINS", "").strip()
    if not raw:
        return _DEFAULT_CORS_ORIGINS
    parsed = [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]
    return parsed or _DEFAULT_CORS_ORIGINS


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Domain routers. Imported here (not in the top import block) so they land
# after the keystore is defined: the routers/deps pull in auth.py, whose
# _session_secret() lazy-imports the keystore singleton from this module. The
# two auth surfaces (dashboard humans vs SDK machines) stay separate by design
# — see m3-platform-auth.md, "the dual-auth-surface insight".
from hexgate_api.domains.agents.router import router as agents_router  # noqa: E402
from hexgate_api.domains.audit.router import router as audit_router  # noqa: E402
from hexgate_api.domains.chat.router import router as chat_router  # noqa: E402
from hexgate_api.domains.invitations.router import (  # noqa: E402
    router as invitations_router,
)
from hexgate_api.domains.members.router import router as members_router  # noqa: E402
from hexgate_api.domains.orgs.router import router as orgs_router  # noqa: E402
from hexgate_api.domains.projects.router import router as projects_router  # noqa: E402
from hexgate_api.domains.tokens.router import router as tokens_router  # noqa: E402

v1 = APIRouter(prefix="/v1")
app.include_router(health.router)
v1.include_router(health.v1_router)
v1.include_router(tokens_router)
v1.include_router(audit_router)
v1.include_router(agents_router)
v1.include_router(chat_router)
v1.include_router(orgs_router)
v1.include_router(members_router)
v1.include_router(invitations_router)
v1.include_router(projects_router)


# ---------------------------------------------------------------------------
# M3 Phase 3a — FastAPI Users routers
#
# Mounted under /v1/auth/* and /v1/users/* so they ride the same versioned
# prefix as the rest of the API. The library provides one router per
# concern; we include the cookie auth + register routers now and the
# verify / reset-password / oauth routers in 3b / 3c.
# ---------------------------------------------------------------------------

from hexgate_api.auth import (  # noqa: E402 — placed late so keystore is initialised
    UserCreate,
    UserRead,
    UserUpdate,
    auth_backend,
    build_google_oauth_router,
    fastapi_users,
)

v1.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/cookie",
    tags=["auth"],
)
v1.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)
# Phase 3b — email verification (POST /auth/request-verify-token + /auth/verify)
# and password reset (POST /auth/forgot-password + /auth/reset-password). Both
# routers use the UserManager email hooks (on_after_request_verify +
# on_after_forgot_password) to send the magic-link tokens through the mailer.
v1.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
)
v1.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
)
v1.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"],
)


# ---------------------------------------------------------------------------
# M3 Phase 4 — Organization CRUD
#
# Read-your-own / create-new / read-by-id / update-name. Member
# management + invitations land in subsequent steps but share these
# dependencies and schemas.
# ---------------------------------------------------------------------------


def _maybe_mount_oauth_routers() -> None:
    """Mount the Phase 3c OAuth router(s) iff env-configured.

    Called from the lifespan once the keystore is initialised — its
    private key derives the OAuth state-token secret. With no Google
    credentials in env, this is a no-op and ``make platform-api``
    works out of the box; flipping the two env vars and restarting
    the server turns Google sign-in on. The router goes onto ``app``
    directly (not ``v1``) so we don't double-include the rest of v1
    that ``app.include_router(v1)`` below already mounted.
    """
    import sys

    google_router = build_google_oauth_router()
    if google_router is not None:
        app.include_router(
            google_router,
            prefix="/v1/auth/google",
            tags=["auth"],
        )
        print(
            "[hexgate] Google OAuth enabled (HEXGATE_GOOGLE_CLIENT_ID set)",
            file=sys.stderr,
        )
    else:
        print(
            "[hexgate] Google OAuth disabled — set HEXGATE_GOOGLE_CLIENT_ID "
            "+ HEXGATE_GOOGLE_CLIENT_SECRET to enable",
            file=sys.stderr,
        )


app.include_router(v1)

# The SPA catch-all is mounted in the lifespan (after the OAuth router), NOT
# here — registering it at import would shadow the lifespan-mounted
# /v1/auth/google/* routes, since Starlette matches in registration order.
