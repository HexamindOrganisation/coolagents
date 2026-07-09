"""Ban endpoints — dashboard CRUD (cookie, project-admin) + SDK active feed (bearer)."""

import hashlib
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.project import require_project_admin
from hexgate_api.deps.tokens import require_project
from hexgate_api.features.bans.service import (
    BanConflictError,
    BanNotFoundError,
    active_bans_for_project,
    create_ban,
    list_bans,
    revoke_ban,
)
from hexgate_api.models import Ban, OrganizationMember, User
from hexgate_api.schemas import BanCreate, BanFeedEntry, BanRead

router = APIRouter()


def _ban_read(ban: Ban) -> BanRead:
    return BanRead(
        id=ban.id,
        project_id=ban.project_id,
        ban_type=ban.ban_type,
        target_agent_name=ban.target_agent_name,
        target_user_id=ban.target_user_id,
        reason=ban.reason,
        created_by_user_id=ban.created_by_user_id,
        created_at=ban.created_at,
        revoked_at=ban.revoked_at,
        active=ban.revoked_at is None,
    )


def _feed_entry(ban: Ban) -> BanFeedEntry:
    return BanFeedEntry(
        ban_id=ban.id,
        ban_type=ban.ban_type,
        target_agent_name=ban.target_agent_name,
        target_user_id=ban.target_user_id,
        reason=ban.reason,
    )


@router.post("/projects/{project_id}/bans", status_code=201, tags=["bans"])
async def api_create_ban(
    project_id: str,
    body: BanCreate,
    membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> BanRead:
    """Create a ban (admin/owner); 409 if one already targets this agent/user."""
    caller, _member = membership
    try:
        ban = await create_ban(
            session,
            project_id=project_id,
            created_by_user_id=caller.id,
            ban_type=body.ban_type,
            target_agent_name=body.target_agent_name,
            target_user_id=body.target_user_id,
            reason=body.reason,
        )
    except BanConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _ban_read(ban)


@router.get("/projects/{project_id}/bans", tags=["bans"])
async def api_list_bans(
    project_id: str,
    include_revoked: bool = False,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> list[BanRead]:
    """List a project's bans (admin/owner); active-only unless ``include_revoked``."""
    rows = await list_bans(
        session, project_id=project_id, include_revoked=include_revoked
    )
    return [_ban_read(b) for b in rows]


@router.delete("/projects/{project_id}/bans/{ban_id}", status_code=204, tags=["bans"])
async def api_revoke_ban(
    project_id: str,
    ban_id: str,
    membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Revoke a ban (admin/owner) → 204; 404 if not in this project."""
    caller, _member = membership
    try:
        await revoke_ban(
            session,
            project_id=project_id,
            ban_id=ban_id,
            revoked_by_user_id=caller.id,
        )
    except BanNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=204)


@router.get("/bans", response_model=list[BanFeedEntry], tags=["bans"])
async def api_list_active_bans_by_token(
    response: Response,
    project_id: str = Depends(require_project),
    session: AsyncSession = Depends(get_session),
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
) -> list[BanFeedEntry] | Response:
    """SDK active-ban feed for the token's project; ETag → 304 when unchanged."""
    rows = await active_bans_for_project(session, project_id=project_id)
    entries = [_feed_entry(b) for b in rows]
    body = json.dumps([e.model_dump() for e in entries], sort_keys=True).encode()
    etag = f'"{hashlib.sha256(body).hexdigest()}"'

    if if_none_match and if_none_match.strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})

    response.headers["ETag"] = etag
    return entries
