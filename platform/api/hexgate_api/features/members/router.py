"""Org member management — list, promote/demote, remove. Cookie-authed."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.org import (
    require_org_admin,
    require_org_admin_or_self,
    require_org_membership,
)
from hexgate_api.models import OrganizationMember, User
from hexgate_api.schemas import MemberRead, MemberUpdate

router = APIRouter()


def _member_read(member: OrganizationMember, user: User) -> MemberRead:
    """Shape the (membership, user) join into the wire row."""
    return MemberRead(
        user_id=user.id,
        email=user.email,
        role=member.role,
        joined_at=member.created_at,
    )


@router.get("/orgs/{org_id}/members", tags=["orgs"])
async def api_list_members(
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
    session: AsyncSession = Depends(get_session),
) -> list[MemberRead]:
    """List all members of an org. Any member can read.

    The role gating intentionally stops at "any member" rather than
    "admin/owner" — every member has a legitimate need to know who
    else is in the org (e.g., to know who to ask for promotion).
    """
    from hexgate_api.features.members.service import list_org_members

    _, member = membership
    rows = await list_org_members(session, member.org_id)
    return [_member_read(m, u) for m, u in rows]


@router.patch("/orgs/{org_id}/members/{user_id}", tags=["orgs"])
async def api_update_member_role(
    user_id: str,
    body: MemberUpdate,
    membership: tuple[User, OrganizationMember] = Depends(require_org_admin),
    session: AsyncSession = Depends(get_session),
) -> MemberRead:
    """Promote / demote a member. Admin or owner role required.

    Two service-layer refusals surface here as HTTP errors:

      * ``RoleEscalationError`` → 403 — the caller (admin or owner)
        tried to assign a role above their own rank. Admins can't
        mint owners by going through PATCH any more than they can
        through the invitation path; the rank check is centralised
        on :func:`_can_invite_role`.
      * ``LastOwnerError`` → 409 — demoting the only owner would
        orphan the org. Catches self-demotion too via the owner count.

    Returns the updated row so the dashboard can re-render the badge
    without a follow-up GET.
    """
    from hexgate_api.features.members.service import (
        LastOwnerError,
        RoleEscalationError,
        change_member_role,
    )

    _, caller_member = membership
    try:
        updated = await change_member_role(
            session,
            org_id=caller_member.org_id,
            user_id=user_id,
            new_role=body.role,
            caller_role=caller_member.role,
        )
    except RoleEscalationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LastOwnerError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="member not found")

    # Look up the user so we can return MemberRead's email field.
    user = await session.get(User, user_id)
    assert user is not None  # FK guarantee
    return _member_read(updated, user)


@router.delete("/orgs/{org_id}/members/{user_id}", status_code=204, tags=["orgs"])
async def api_remove_member(
    user_id: str,
    membership: tuple[User, OrganizationMember] = Depends(require_org_admin_or_self),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Remove a member. Admin/owner can remove anyone; plain members
    can only remove themselves (the "leave organization" flow).

    Refuses with 409 when the removal would leave the org with zero
    owners — promote another member to owner first, then leave.

    Returns 204 No Content on success (REST norm for DELETE).
    """
    from hexgate_api.features.members.service import LastOwnerError, remove_member

    _, caller_member = membership
    try:
        removed = await remove_member(
            session, org_id=caller_member.org_id, user_id=user_id
        )
    except LastOwnerError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(status_code=404, detail="member not found")
    return Response(status_code=204)
