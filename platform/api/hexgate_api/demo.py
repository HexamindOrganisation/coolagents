"""Single-tenant demo bundle: serve the built dashboard same-origin + auto-login.

Wired into :mod:`main` only when ``HEXGATE_DEMO`` is truthy, so normal
``make platform-api`` / production runs are completely unaffected. The goal
is a throwaway, per-visitor container where:

  * the FastAPI app *also* serves the built React dashboard (``dist/``) from
    the same origin — so the ``hexgate_session`` cookie and the ``/v1`` WebSocket
    resolve without any CORS / cross-origin cookie config, behind a single
    public URL (e.g. one ``modal.forward(8000)`` tunnel); and

  * ``GET /v1/demo-login`` logs the seeded default user in (sets the session
    cookie) and redirects to the playground, so the visitor lands signed-in
    with no login wall. There is exactly one org / user / project in the
    container's fresh SQLite (created by ``ensure_default_seed`` at startup),
    so "log in as the default user" is unambiguous.

Container dies → SQLite + the ephemeral org/project evaporate. Nothing to
garbage-collect in a shared database.

⚠️  SECURITY: when enabled, ``/v1/demo-login`` grants a passwordless session for
the seeded admin (superuser). This is intentional for a *throwaway, single-user
container* but would be an account-takeover hole on any persistent/real
deployment that ran the default seed. Only ever set ``HEXGATE_DEMO`` on an
ephemeral demo container — never on the real platform. The lifespan logs a loud
warning when it's on.
"""

from __future__ import annotations

from fastapi import FastAPI, Response
from fastapi.responses import RedirectResponse

from hexgate_api.core.spa import mount_spa


def enable_demo(app: FastAPI) -> None:
    """Attach the demo-login route + SPA static serving to ``app``.

    MUST be called *after* ``app.include_router(v1)`` so the ``/v1`` API and
    WebSocket routes are matched before the catch-all SPA fallback. Starlette
    matches routes in registration order, so registering this last is what
    keeps ``/v1/*`` from being shadowed by ``index.html``.

    The same-origin SPA serving is shared with production via
    :func:`spa.mount_spa`; the only demo-specific addition is the passwordless
    ``/v1/demo-login`` below.
    """

    # ----- auto-login -----------------------------------------------------
    @app.get("/v1/demo-login", include_in_schema=False)
    async def demo_login() -> Response:
        """Mint a session cookie for the seeded default user and land on /playground.

        Reuses the platform's real auth backend (JWT strategy + the exact
        cookie attributes from ``auth.cookie_transport``) so the issued cookie
        is indistinguishable from a normal password login — the dashboard's
        ``ws_require_org_member`` accepts it unchanged.
        """
        from hexgate_api.features.auth.service import cookie_transport, get_jwt_strategy
        from hexgate_api.core.db import async_session_factory
        from hexgate_api.models import User
        from hexgate_api.constants import DEFAULT_USER_ID

        async with async_session_factory() as session:
            user = await session.get(User, DEFAULT_USER_ID)
            if user is None:  # seed disabled (HEXGATE_SEED=skip) — nothing to log into
                return RedirectResponse(url="/", status_code=303)
            token = await get_jwt_strategy().write_token(user)

        # Set the cookie from the platform's real CookieTransport config
        # (name / ttl / secure / samesite / …) so it never drifts from how a
        # normal password login sets it.
        resp = RedirectResponse(url="/playground", status_code=303)
        resp.set_cookie(
            key=cookie_transport.cookie_name,
            value=token,
            max_age=cookie_transport.cookie_max_age,
            path=cookie_transport.cookie_path,
            domain=cookie_transport.cookie_domain,
            secure=cookie_transport.cookie_secure,
            httponly=cookie_transport.cookie_httponly,
            samesite=cookie_transport.cookie_samesite,
        )
        return resp

    # ----- static SPA -----------------------------------------------------
    # Same-origin dashboard serving, shared with the production path.
    mount_spa(app)
