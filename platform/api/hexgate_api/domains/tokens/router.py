"""Dev-token CRUD, key introspection, and the signing-key JWKS endpoint.

The signing keystore is read lazily from :mod:`hexgate_api.main` at call time
(the platform's shared singleton; see :mod:`hexgate_api.deps.tokens`).
"""

import base64

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.org import require_org_member
from hexgate_api.schemas import (
    KeyIntrospection,
    TokenListItem,
    TokenMintRequest,
    TokenMintResponse,
)
from hexgate_api.domains.tokens.service import (
    delete_dev_token,
    find_token_by_secret,
    list_dev_tokens,
    mask_secret,
    mint_dev_token,
)
from hexgate_api.bootstrap.seed import ensure_default_project

router = APIRouter()


@router.get("/.well-known/keys")
async def well_known_keys() -> dict[str, object]:
    """Publish the platform's signing public key + fingerprint.

    JWKS-shaped so we can grow into multi-key publishing later without
    breaking clients. Lets dashboards and CLIs sanity-check that what
    their SDK has embedded matches what this platform is signing with.
    """
    from hexgate_api.main import keystore

    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "x": base64.urlsafe_b64encode(keystore.public_key_bytes())
                .rstrip(b"=")
                .decode("ascii"),
                "fingerprint": keystore.fingerprint(),
            }
        ]
    }


@router.get(
    "/projects/{project_id}/tokens",
    response_model=list[TokenListItem],
    dependencies=[Depends(require_org_member)],
)
async def list_tokens(
    project_id: str, session: AsyncSession = Depends(get_session)
) -> list[TokenListItem]:
    tokens = await list_dev_tokens(session, project_id)
    return [
        TokenListItem(
            id=t.id,
            name=t.name,
            masked=mask_secret(t.secret),
            scopes=t.scopes_csv.split(",") if t.scopes_csv else [],
            created_at=t.created_at,
            last_used_at=t.last_used_at,
        )
        for t in tokens
    ]


@router.post(
    "/projects/{project_id}/tokens",
    response_model=TokenMintResponse,
    status_code=201,
    dependencies=[Depends(require_org_member)],
)
async def mint_token(
    project_id: str,
    body: TokenMintRequest,
    session: AsyncSession = Depends(get_session),
) -> TokenMintResponse:
    from hexgate_api.main import keystore

    await ensure_default_project(
        session
    )  # POC: lazy-create so single project works out of the box
    token, full = await mint_dev_token(
        session,
        project_id=project_id,
        name=body.name,
        scopes=body.scopes,
        env=body.env,
        signing_key_bytes=keystore._private_key_bytes(),
    )
    return TokenMintResponse(
        id=token.id,
        name=token.name,
        full=full,
        masked=mask_secret(full),
        scopes=token.scopes_csv.split(",") if token.scopes_csv else [],
        created_at=token.created_at,
    )


@router.delete(
    "/projects/{project_id}/tokens/{token_id}",
    status_code=204,
    dependencies=[Depends(require_org_member)],
)
async def revoke_token(
    project_id: str,
    token_id: str,
    session: AsyncSession = Depends(get_session),
) -> None:
    ok = await delete_dev_token(session, project_id, token_id)
    if not ok:
        raise HTTPException(status_code=404, detail="token not found")


@router.get("/me/key", response_model=KeyIntrospection)
async def api_introspect_key(
    authorization: str | None = Header(default=None),
    session: AsyncSession = Depends(get_session),
) -> KeyIntrospection:
    """Describe the bearer token (project + env + scopes).

    Useful for the CLI's startup log line — ``hexgate serve`` can show
    ``project=acme-prod env=live`` without parsing the envelope itself,
    and we keep the parse-envelope contract on one side (the server).

    Authentication is the bearer; possessing the key proves the right
    to read its own description. ``find_token_by_secret`` already bumps
    ``last_used_at`` so this call counts as activity (visible in the
    dashboard's "last used" column).
    """
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="missing or malformed authorization header"
        )
    secret = authorization.removeprefix("Bearer ").strip()
    token = await find_token_by_secret(session, secret)
    if token is None:
        raise HTTPException(status_code=401, detail="invalid hexgate key")

    # ``prefix`` on the row is ``fty_test`` or ``fty_live``; strip the
    # leading ``fty_`` to expose just the env value the CLI cares about.
    env = token.prefix.removeprefix("fty_")
    scopes = [s for s in token.scopes_csv.split(",") if s] if token.scopes_csv else []
    return KeyIntrospection(
        token_id=token.id,
        name=token.name,
        project_id=token.project_id,
        env=env,
        scopes=scopes,
    )
