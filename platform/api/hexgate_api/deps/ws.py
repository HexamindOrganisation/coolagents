"""WebSocket handshake auth gates.

Called manually inside the WS route handlers (not via ``Depends``) because
Starlette resolves dependencies differently on the WS path. Both close with
``4401`` before ``accept()`` on any failure and return ``None`` so the handler
can bail cleanly.
"""

from urllib.parse import unquote

from fastapi import WebSocket
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.biscuits import (
    TokenError,
    TokenSignatureError,
    parse_envelope,
    verify_token,
)
from hexgate_api.models import OrganizationMember, Project, User
from hexgate_api.domains.tokens.service import find_token_by_secret

# Marker subprotocol the server echoes on a successful WS handshake. The
# CLI client asserts it back so it knows the platform understands the
# bearer-in-subprotocol contract (i.e., we're talking to a Phase-6+
# server, not an older deployment that ignored unknown subprotocols).
_WS_PROTOCOL_MARKER = "hexgate.v1"

# WS close code for "auth failed at handshake". 4000-4999 is the
# application-private range per RFC 6455; 4401 is chosen to mirror the
# HTTP 401 mnemonic so logs read consistently across the two layers.
_WS_CLOSE_UNAUTHENTICATED = 4401


async def ws_require_project(
    websocket: WebSocket,
    session: AsyncSession,
) -> str | None:
    """Authenticate a WebSocket via a bearer token in the subprotocol header.

    Browsers can't set custom headers on WS handshakes; the standard
    workaround is to overload ``Sec-WebSocket-Protocol``. The CLI client
    offers two subprotocols on ``connect``:

      * ``bearer.<envelope>`` — the actual hexgate key, consumed by the
        server and never echoed back (kept out of any proxy mirror logs).
      * ``hexgate.v1`` — protocol marker; the server echoes this so the
        client knows the handshake bound a real auth context.

    On any reject path we ``close(code=4401)`` before ``accept()`` — the
    handshake never completes, the client sees a clean rejection
    instead of an immediate disconnect after an accepted upgrade. The
    handler that consumes this dependency must ``return`` when the
    result is ``None``.

    Reuses :func:`require_project`'s signature + revocation gates so
    HTTP and WS paths can't drift on what counts as a valid token.
    """
    from hexgate_api.main import keystore

    subprotocols = websocket.scope.get("subprotocols") or []
    bearer: str | None = None
    for sp in subprotocols:
        if sp.startswith("bearer."):
            # The CLI percent-encodes the envelope before placing it
            # in the subprotocol — biscuit base64 has '=' padding,
            # which RFC 7230 token grammar forbids. ``unquote`` is a
            # no-op on un-encoded input, so tests that pass raw
            # envelopes (TestClient doesn't enforce the grammar) keep
            # working unchanged.
            bearer = unquote(sp.removeprefix("bearer."))
            break

    if not bearer:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    # Signature gate — same parse_envelope + verify_token the HTTP path
    # runs. Any failure here is a 4401, no detail leaked.
    try:
        _, _, biscuit_b64 = parse_envelope(bearer)
        verify_token(biscuit_b64, keystore.public_key_bytes())
    except (TokenError, TokenSignatureError):
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    # Revocation gate. ``find_token_by_secret`` also bumps last_used_at,
    # which is what makes the dashboard's "last used" column work for
    # serve sessions.
    token = await find_token_by_secret(session, bearer)
    if token is None:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    # Echo only the marker — the bearer subprotocol is consumed
    # internally so it doesn't end up in any access log that captures
    # Sec-WebSocket-Protocol response headers.
    await websocket.accept(subprotocol=_WS_PROTOCOL_MARKER)
    return token.project_id


async def ws_require_org_member(
    websocket: WebSocket,
    project_id: str,
    session: AsyncSession,
) -> User | None:
    """Authenticate a dashboard-driven WebSocket via the session cookie.

    Counterpart of :func:`ws_require_project` for the cookie-auth side.
    Browsers can't set custom headers on WS upgrades — fine for
    ``ws_serve`` (the CLI sends a bearer subprotocol) but the dashboard
    drives ``ws_chat`` from JavaScript and can't reach for an
    Authorization header. We extract the ``hexgate_session`` cookie
    directly from the handshake.

    Three gates run in order:

      1. Cookie present → decode the JWT via the same strategy the
         HTTP cookie path uses.
      2. Decoded user exists + is active.
      3. User is a member of the project's org (any role).

    Any failure → ``close(code=4401)`` before ``accept()`` and return
    ``None``. On success → ``accept()`` and return the ``User``.

    Before this gate landed, ``ws_chat`` was a wide-open eavesdrop /
    inject surface: anyone who could guess or enumerate a ``project_id``
    could relay arbitrary JSON to a running serve process and read its
    replies. The bearer-subprotocol pattern from ``ws_require_project``
    doesn't work here because JS WebSocket can't set
    ``Sec-WebSocket-Protocol`` cookies — cookie auth is the only
    browser-compatible option.
    """
    # Cookie extraction. ``websocket.cookies`` is Starlette's parsed
    # mapping; absent cookies show up as missing keys, not empty
    # strings.
    cookie_token = websocket.cookies.get("hexgate_session")
    if not cookie_token:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    # JWT decode via the same strategy + user_manager wiring the HTTP
    # cookie path uses. Importing locally so this module can be
    # imported without forcing the auth package to load — keeps
    # require_user_or_sdk_token (gone) and friends out of the cycle.
    from fastapi_users.db import SQLAlchemyUserDatabase

    from hexgate_api.auth import OAuthAccount, UserManager, get_jwt_strategy

    user_db = SQLAlchemyUserDatabase(session, User, OAuthAccount)
    user_manager = UserManager(user_db)
    strategy = get_jwt_strategy()
    try:
        user = await strategy.read_token(cookie_token, user_manager)
    except Exception:  # noqa: BLE001 — any decode failure is auth failure
        user = None
    if user is None or not user.is_active:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    # Org-membership check. ``ws_chat`` is project-scoped; the cookie
    # only proves identity, not access to this particular project.
    project = await session.get(Project, project_id)
    if project is None:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None
    membership = (
        await session.exec(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.org_id == project.org_id,
            )
        )
    ).first()
    if membership is None:
        await websocket.close(code=_WS_CLOSE_UNAUTHENTICATED)
        return None

    await websocket.accept()
    return user
