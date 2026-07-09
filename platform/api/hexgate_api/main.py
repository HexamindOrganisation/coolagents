import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hexgate_api import health
from hexgate_api.seeds.defaults import ensure_default_project
from hexgate_api.core.clickhouse import ping as clickhouse_ping
from hexgate_api.core.db import async_session_factory, init_db
from hexgate_api.core.keystore import keystore
from hexgate_api.features.agents.router import router as agents_router
from hexgate_api.features.agents.service import backfill_bundles
from hexgate_api.features.audit.router import router as audit_router
from hexgate_api.features.auth.router import include_auth_routers, mount_oauth_routers
from hexgate_api.features.bans.router import router as bans_router
from hexgate_api.features.chat.router import router as chat_router
from hexgate_api.features.invitations.router import router as invitations_router
from hexgate_api.features.llm_invocations.router import router as llm_invocations_router
from hexgate_api.features.members.router import router as members_router
from hexgate_api.features.orgs.router import router as orgs_router
from hexgate_api.features.projects.router import router as projects_router
from hexgate_api.features.tokens.router import router as tokens_router

# Load .env into os.environ before any HEXGATE_* read (CORS resolves at import
# time). Real env vars still take precedence.
load_dotenv()

_log = logging.getLogger(__name__)

_DEFAULT_CORS_ORIGINS = ["http://localhost:5173"]


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


def _build_v1_router() -> APIRouter:
    """Assemble the versioned ``/v1`` router from every domain + auth wiring."""
    v1 = APIRouter(prefix="/v1")
    v1.include_router(health.v1_router)
    v1.include_router(tokens_router)
    v1.include_router(audit_router)
    v1.include_router(llm_invocations_router)
    v1.include_router(agents_router)
    v1.include_router(chat_router)
    v1.include_router(orgs_router)
    v1.include_router(members_router)
    v1.include_router(invitations_router)
    v1.include_router(projects_router)
    v1.include_router(bans_router)
    include_auth_routers(v1)
    return v1


@asynccontextmanager
async def lifespan(app_: FastAPI):
    await init_db()
    keystore.ensure_keypair()
    # OAuth router mounting waits on the keystore — its state-token secret is
    # derived from the keystore's private key (see auth._oauth_state_secret).
    # Doing this at import would race the lifespan; it runs once at startup,
    # before any request reaches the app.
    mount_oauth_routers(app_)
    # SPA catch-all goes on LAST — after the OAuth router just mounted — so
    # /{path} never shadows /v1/auth/google/*. (Static /v1 routes are already
    # registered at import; only the OAuth router mounts here at startup, so the
    # SPA must follow it.) Demo mode mounts the same SPA + a passwordless login.
    if _demo_enabled():
        from hexgate_api.demo import enable_demo

        enable_demo(app_)
    else:
        from hexgate_api.core.spa import mount_spa

        mount_spa(app_)
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
    from hexgate_api.features.auth.service import _cookie_secure, _dashboard_url

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


def create_app() -> FastAPI:
    """Build the FastAPI app: middleware + health + the versioned ``/v1`` router.

    The SPA catch-all and the OAuth router are mounted in :func:`lifespan`
    (after startup) so they don't shadow the static routes registered here.
    """
    app_ = FastAPI(title="Hexgate API", version="0.1.0", lifespan=lifespan)
    app_.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app_.include_router(health.router)
    app_.include_router(_build_v1_router())
    return app_


app = create_app()
