"""Bearer/SDK-token dependencies — machine auth via ``Authorization: Bearer``.

The signing keystore is read lazily from :mod:`hexgate_api.main` at call time
(the same pattern :func:`hexgate_api.auth._session_secret` uses) so the singleton
stays in one place and test swaps of ``main.keystore`` are picked up.
"""

from fastapi import Depends, Header, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.biscuits import (
    TokenError,
    TokenSignatureError,
    parse_envelope,
    verify_token,
)
from hexgate_api.core.db import get_session
from hexgate_api.domains.tokens.service import find_token_by_secret


async def _validate_sdk_token(authorization: str, session: AsyncSession) -> None:
    """Validate an ``Authorization: Bearer <hexgate_key>`` biscuit envelope.

    Used by :func:`optional_dev_token` (allows a missing header) and
    indirectly by :func:`require_project` / :func:`ws_require_project`
    (the bearer-implicit SDK routes). Raises 401 on signature or
    revocation failure; returns None on success.
    """
    from hexgate_api.core.keystore import keystore

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="malformed authorization header")
    secret = authorization.removeprefix("Bearer ").strip()

    # Signature gate
    try:
        _, _, biscuit_b64 = parse_envelope(secret)
    except TokenError:
        raise HTTPException(status_code=401, detail="malformed hexgate key") from None
    try:
        verify_token(biscuit_b64, keystore.public_key_bytes())
    except TokenSignatureError:
        raise HTTPException(
            status_code=401, detail="invalid hexgate key signature"
        ) from None

    # Revocation gate
    if await find_token_by_secret(session, secret) is None:
        raise HTTPException(status_code=401, detail="unknown or revoked hexgate key")


async def optional_dev_token(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Validate Authorization: Bearer <hexgate_key> when present.

    Two gates run when a header is supplied:

    1. **Signature verification** — parse the envelope, decode the Biscuit,
       check it chains to the platform's root public key.
    2. **Revocation lookup** — confirm the exact secret is still in the
       ``DevToken`` table and update ``last_used_at``.

    POC behaviour: the header itself remains optional so the dashboard
    (no user-session concept yet) can keep calling these endpoints
    unauthenticated. Routes that DO require some auth pick the
    appropriate dep:

      * cookie/dashboard humans → :func:`require_org_member`
      * bearer/SDK machines → :func:`require_project` (HTTP) or
        :func:`ws_require_project` (WebSocket)
    """
    if authorization is None:
        return
    await _validate_sdk_token(authorization, session)


async def require_project(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> str:
    """Resolve `Authorization: Bearer <hexgate_key>` to a project_id.

    Used by SDK-facing endpoints (e.g. POST /v1/agents) where the caller
    has only an API key, not a project id in the URL.

    Two gates run in order, matching :func:`ws_require_project` and
    :func:`optional_dev_token` so all three bearer-auth surfaces agree
    on what counts as a valid token:

      1. **Signature verification** via :func:`_validate_sdk_token` —
         parse the envelope, verify the biscuit chains to the platform's
         root public key. A revocation lookup runs inside the helper.
      2. **Project resolution** — read ``DevToken.project_id`` for the
         already-validated secret.

    The signature gate was missing before — a forged biscuit whose
    secret string happened to match a stored ``DevToken.secret`` would
    have been accepted. Defense-in-depth + consistency with the WS
    bearer path.
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="missing or malformed authorization header"
        )
    # Signature + revocation gate. Raises HTTPException(401) on any
    # failure (malformed envelope, bad signature, unknown/revoked
    # secret) so the project lookup below only fires on a verified
    # token.
    await _validate_sdk_token(authorization, session)
    secret = authorization.removeprefix("Bearer ").strip()
    token = await find_token_by_secret(session, secret)
    # ``_validate_sdk_token`` already confirmed find_token_by_secret
    # returns a row; the second lookup is to read .project_id, not
    # to re-gate access. assert guards against a logic regression.
    assert token is not None, "find_token_by_secret returned None after signature gate"
    return token.project_id
