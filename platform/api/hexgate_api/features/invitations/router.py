"""Org invitations — mint/list/preview/accept/revoke.

Preview is public-readable; accept/revoke are cookie-authed and email-matched.
"""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.identity import require_user
from hexgate_api.deps.org import require_org_admin
from hexgate_api.features.members.router import _member_read
from hexgate_api.models import Invitation, Organization, OrganizationMember, User
from hexgate_api.schemas import (
    InvitationCreate,
    InvitationPreview,
    InvitationRead,
    MemberRead,
)

router = APIRouter()


def _invitation_read(invitation: Invitation, inviter: User) -> InvitationRead:
    """Shape the (Invitation, inviter User) join into the dashboard
    list row. Includes the invitation id so the dashboard's Cancel
    button has a row to address; the strict email-match guard on
    ``POST /invites/{id}/accept`` keeps id exposure from being an
    impersonation vector — see InvitationRead's docstring."""
    return InvitationRead(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        invited_by_email=inviter.email,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
    )


@router.post("/orgs/{org_id}/invites", status_code=201, tags=["orgs"])
async def api_create_invitation(
    body: InvitationCreate,
    membership: tuple[User, OrganizationMember] = Depends(require_org_admin),
    session: AsyncSession = Depends(get_session),
) -> InvitationRead:
    """Mint a pending invitation + email it. Admin or owner required.

    Role escalation guard fires in :func:`services.create_invitation` —
    admins can only invite at-or-below their level (no minting owner
    invites then accepting them yourself to promote). Surfaced as
    400 with a specific detail message.

    The route also looks up the org name + inviter email for the email
    body (one extra query each; cheap).
    """
    from hexgate_api.features.invitations.service import (
        InvitationError,
        create_invitation,
        send_invitation_email,
    )

    caller, caller_member = membership
    try:
        invitation = await create_invitation(
            session,
            org_id=caller_member.org_id,
            email=body.email,
            role=body.role,
            invited_by=caller_member,
        )
    except InvitationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Email the invitee. Failures here are logged but don't fail the
    # API call — the invite row exists; a re-send can happen via a
    # follow-up POST to the same email (which cancels this one and
    # mints a fresh link).
    org = await session.get(Organization, caller_member.org_id)
    assert org is not None
    try:
        await send_invitation_email(
            invitation=invitation, org_name=org.name, inviter_email=caller.email
        )
    except Exception:
        # Mailer failure — log via the auth logger so it shows up in
        # the same stderr block operators are already watching. Invitee
        # address is PII-redacted (same rule as mailer.py); the org slug
        # stays so support can grep by tenant.
        from hexgate_api.features.auth.service import logger as auth_logger
        from hexgate_api.core.mailer import _redact_email

        auth_logger.exception(
            "failed to send invitation email to %s for org %s",
            _redact_email(invitation.email),
            org.slug,
        )

    return _invitation_read(invitation, caller)


@router.get("/orgs/{org_id}/invites", tags=["orgs"])
async def api_list_invitations(
    membership: tuple[User, OrganizationMember] = Depends(require_org_admin),
    session: AsyncSession = Depends(get_session),
) -> list[InvitationRead]:
    """List pending invitations for the org. Admin or owner required.

    Only non-terminal invites (no ``accepted_at``, no ``revoked_at``)
    show up. Already-accepted invites surface implicitly as new
    OrganizationMember rows via ``GET /members``.
    """
    from hexgate_api.features.invitations.service import list_pending_invitations

    _, caller_member = membership
    rows = await list_pending_invitations(session, caller_member.org_id)
    return [_invitation_read(inv, inv_user) for inv, inv_user in rows]


@router.get("/invites/{invitation_id}", tags=["invitations"])
async def api_get_invitation_preview(
    invitation_id: str,
    session: AsyncSession = Depends(get_session),
) -> InvitationPreview:
    """Public-readable preview of an invitation.

    Returns 404 for unknown ids; 410 Gone for terminal invites
    (already accepted/revoked/expired). Lets the invitee land on the
    accept page and see what they're being invited to BEFORE
    authenticating. The invite id is UUID v4 (unguessable enough);
    the accept POST is what requires auth + strict email match.
    """
    from hexgate_api.features.invitations.service import (
        _is_invitation_terminal,
        find_invitation,
    )

    invitation = await find_invitation(session, invitation_id)
    if invitation is None:
        raise HTTPException(status_code=404, detail="invitation not found")
    if _is_invitation_terminal(invitation):
        raise HTTPException(
            status_code=410, detail="invitation expired or already used"
        )

    org = await session.get(Organization, invitation.org_id)
    inviter = await session.get(User, invitation.invited_by_user_id)
    assert org is not None and inviter is not None  # FK guarantee
    return InvitationPreview(
        email=invitation.email,
        role=invitation.role,
        invited_by_email=inviter.email,
        org_id=org.id,
        org_name=org.name,
        org_slug=org.slug,
        expires_at=invitation.expires_at,
    )


@router.post("/invites/{invitation_id}/accept", tags=["invitations"])
async def api_accept_invitation(
    invitation_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> MemberRead:
    """Consume an invitation. Cookie-authenticated; email must match.

    Returns the newly-created (or already-existing) ``OrganizationMember``
    row so the dashboard can immediately drop the user into the org's
    view without a follow-up ``/orgs`` round-trip.

    HTTP codes mirror the service-layer exception hierarchy:
      * 404 — unknown invitation id
      * 410 — expired
      * 409 — already accepted or revoked
      * 403 — email mismatch ("this invite isn't for you")
    """
    from hexgate_api.features.invitations.service import (
        InvitationAlreadyConsumed,
        InvitationEmailMismatch,
        InvitationExpired,
        accept_invitation,
        find_invitation,
    )

    invitation = await find_invitation(session, invitation_id)
    if invitation is None:
        raise HTTPException(status_code=404, detail="invitation not found")

    try:
        member = await accept_invitation(
            session, invitation=invitation, accepting_user=user
        )
    except InvitationExpired as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc
    except InvitationAlreadyConsumed as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except InvitationEmailMismatch as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    return _member_read(member, user)


@router.delete("/invites/{invitation_id}", status_code=204, tags=["invitations"])
async def api_revoke_invitation(
    invitation_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> Response:
    """Cancel a pending invitation. Two callers are authorised:

      * admin / owner of the inviting org — the "cancel" use case
      * the invited user themselves (by email match) — the "decline" use
        case, so the invitee can close out an unwanted invite without
        joining

    404 for unknown; 409 for already-terminal invites. Idempotent on
    success — calling DELETE on an already-revoked invite is a no-op
    that still returns 204.
    """
    from hexgate_api.constants import ROLE_ADMIN, ROLE_OWNER
    from hexgate_api.features.members.service import find_member
    from hexgate_api.features.invitations.service import (
        find_invitation,
        revoke_invitation,
    )

    invitation = await find_invitation(session, invitation_id)
    if invitation is None:
        raise HTTPException(status_code=404, detail="invitation not found")

    if invitation.email.lower() == user.email.lower():
        # Invitee declining their own invite.
        await revoke_invitation(session, invitation)
        return Response(status_code=204)

    # Otherwise check whether the caller is an admin or owner of the org.
    caller_member = await find_member(
        session, org_id=invitation.org_id, user_id=user.id
    )
    if caller_member is None or caller_member.role not in {
        ROLE_OWNER,
        ROLE_ADMIN,
    }:
        raise HTTPException(
            status_code=403,
            detail="only admins/owners or the invitee can cancel an invitation",
        )

    await revoke_invitation(session, invitation)
    return Response(status_code=204)
