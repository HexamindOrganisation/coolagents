"""Invitation lifecycle: mint, look up, accept (→ membership), revoke, email.

Role-rank checks + membership creation reuse the members domain
(:mod:`hexgate_api.domains.members.service`).
"""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import ALL_ROLES
from hexgate_api.domains.members.service import (
    _ROLE_RANK,
    _can_invite_role,
    find_member,
)
from hexgate_api.models import Invitation, OrganizationMember, User, utcnow

# Default lifetime — a week is enough for "I'll get to it on Monday" but
# short enough that an exfiltrated email link 6 months later is dead.
_DEFAULT_INVITE_TTL_HOURS = 168


class InvitationError(Exception):
    """Base class for invitation-validation failures.

    Routes translate the subclasses to specific HTTP codes:
      * :class:`InvitationExpired`         → 410 Gone
      * :class:`InvitationAlreadyConsumed` → 409 Conflict
      * :class:`InvitationEmailMismatch`   → 403 Forbidden
      * any other InvitationError          → 400 Bad Request
    """


class InvitationExpired(InvitationError):
    """The ``expires_at`` deadline has passed."""


class InvitationAlreadyConsumed(InvitationError):
    """The invitation was already accepted or revoked — terminal."""


class InvitationEmailMismatch(InvitationError):
    """The signed-in user's email doesn't match the invited address.

    The invite is for a specific person, not a bearer-token-for-anyone.
    Refuse strictly rather than allow anyone-with-the-link to join."""


async def create_invitation(
    session: AsyncSession,
    *,
    org_id: str,
    email: str,
    role: str,
    invited_by: OrganizationMember,
    ttl_hours: int = _DEFAULT_INVITE_TTL_HOURS,
) -> Invitation:
    """Mint a pending invitation. Cancels any existing pending invite
    for the same (org, email) pair so a re-invite produces one
    valid link rather than two.

    Refuses with ``InvitationError`` if the role is unknown or if the
    inviter doesn't outrank the target role (see :func:`_can_invite_role`).
    Email is lowercased so the case-insensitive accept-match works
    even on SQLite (no native CI collations).
    """
    from datetime import timedelta

    if role not in ALL_ROLES:
        raise InvitationError(f"unknown role: {role!r}")
    if not _can_invite_role(invited_by.role, role):
        raise InvitationError(f"a {invited_by.role} cannot invite at the {role} level")

    normalized_email = email.strip().lower()

    # Cancel any existing pending invite for this (org, email). Two
    # parallel invites would let either link redeem the seat — we want
    # exactly one canonical pending link per address per org.
    existing = (
        await session.exec(
            select(Invitation).where(
                Invitation.org_id == org_id,
                Invitation.email == normalized_email,
                Invitation.accepted_at.is_(None),  # type: ignore[union-attr]
                Invitation.revoked_at.is_(None),  # type: ignore[union-attr]
            )
        )
    ).all()
    for stale in existing:
        stale.revoked_at = utcnow()
        session.add(stale)

    invitation = Invitation(
        org_id=org_id,
        email=normalized_email,
        role=role,
        invited_by_user_id=invited_by.user_id,
        expires_at=utcnow() + timedelta(hours=ttl_hours),
    )
    session.add(invitation)
    await session.commit()
    await session.refresh(invitation)
    return invitation


async def find_invitation(
    session: AsyncSession, invitation_id: str
) -> Invitation | None:
    """Return the Invitation by id, or None. Doesn't validate
    expiry / consumed state — the caller does that (the preview
    endpoint shows expired invites with an error message rather
    than 404)."""
    return await session.get(Invitation, invitation_id)


async def list_pending_invitations(
    session: AsyncSession, org_id: str
) -> list[tuple[Invitation, User]]:
    """List non-terminal invites for an org, paired with the inviter.

    Returned tuple shape mirrors :func:`list_org_members` for symmetry —
    the dashboard's Members tab renders both as adjacent lists.
    """
    stmt = (
        select(Invitation, User)
        .join(User, User.id == Invitation.invited_by_user_id)
        .where(
            Invitation.org_id == org_id,
            Invitation.accepted_at.is_(None),  # type: ignore[union-attr]
            Invitation.revoked_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(Invitation.created_at)  # type: ignore[attr-defined]
    )
    return [(i, u) for i, u in (await session.exec(stmt)).all()]


def _ensure_utc_aware(dt):
    """Re-attach UTC tz to a datetime that lost it during a DB round-trip.

    SQLite stores TIMESTAMP as a string with no timezone info, so a
    value written as ``utcnow()`` (tz-aware UTC) comes back naive.
    Comparing a naive value against a tz-aware ``utcnow()`` raises
    ``TypeError``. The fix: treat naive DB-loaded values as already-
    UTC and attach the tz before any comparison.
    """
    from datetime import timezone

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _is_invitation_terminal(invitation: Invitation) -> bool:
    """True if the invitation is already accepted, revoked, or expired."""
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        return True
    return _ensure_utc_aware(invitation.expires_at) < utcnow()


async def accept_invitation(
    session: AsyncSession,
    *,
    invitation: Invitation,
    accepting_user: User,
) -> OrganizationMember:
    """Atomically: validate + insert OrganizationMember + mark consumed.

    Raises:
      * :class:`InvitationExpired`         — past ``expires_at``
      * :class:`InvitationAlreadyConsumed` — already accepted or revoked
      * :class:`InvitationEmailMismatch`   — caller's email ≠ invited email

    Idempotent on retry only in the same session — once ``accepted_at``
    is set, a second call raises ``InvitationAlreadyConsumed``. That's
    intentional: a double-click on the accept button shouldn't silently
    succeed; the UI should refresh and notice the user is already a
    member.

    If the user is already a member of the org (e.g., manual add or
    re-invite), the existing membership row is returned and the
    invitation is still marked consumed. The role is *upgraded* (never
    downgraded) when the invitation's role outranks the current one —
    so an owner can promote a teammate from member → admin by sending
    a new invite, but a member-tier re-invite of an existing admin or
    owner is a no-op rather than a silent demotion.
    """
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        raise InvitationAlreadyConsumed("invitation already accepted or revoked")
    if _ensure_utc_aware(invitation.expires_at) < utcnow():
        raise InvitationExpired("invitation expired")
    if invitation.email.lower() != accepting_user.email.lower():
        # Don't echo ``invitation.email`` back: the route forwards
        # ``str(exc)`` as the HTTP detail, and a logged-in attacker who
        # got hold of an invite id would otherwise be able to harvest
        # the invitee's address. Stay generic.
        raise InvitationEmailMismatch("invitation is for a different account")

    # If already a member (re-invite of an existing teammate), reuse
    # the existing row. Otherwise create a fresh membership.
    member = await find_member(
        session, org_id=invitation.org_id, user_id=accepting_user.id
    )
    if member is None:
        member = OrganizationMember(
            user_id=accepting_user.id,
            org_id=invitation.org_id,
            role=invitation.role,
        )
        session.add(member)
    elif _ROLE_RANK.get(invitation.role, -1) > _ROLE_RANK.get(member.role, -1):
        # Re-invite is a promotion: an admin invited as owner, or a
        # member invited as admin. Upgrade in place. We never downgrade
        # on the reverse — a stray member-level re-invite of an
        # existing owner mustn't silently strip privileges.
        member.role = invitation.role
        session.add(member)
    invitation.accepted_at = utcnow()
    session.add(invitation)
    await session.commit()
    await session.refresh(member)
    return member


async def revoke_invitation(session: AsyncSession, invitation: Invitation) -> None:
    """Mark an invitation revoked. Idempotent — already-terminal
    invites silently no-op (the caller has already gotten the desired
    outcome)."""
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        return
    invitation.revoked_at = utcnow()
    session.add(invitation)
    await session.commit()


async def send_invitation_email(
    *,
    invitation: Invitation,
    org_name: str,
    inviter_email: str,
) -> None:
    """Mail the invitee a clickable accept link.

    Same HEXGATE_DASHBOARD_URL the verify/reset flows use, same
    StderrEmailSender dev mode, same swap-for-real-provider story for
    production via :func:`mailer.set_email_sender`.
    """
    import os

    from hexgate_api.core.mailer import get_email_sender

    dashboard_url = os.environ.get(
        "HEXGATE_DASHBOARD_URL", "http://localhost:5173"
    ).rstrip("/")
    link = f"{dashboard_url}/invites/{invitation.id}/accept"
    ttl_hours = max(
        1,
        int(
            (_ensure_utc_aware(invitation.expires_at) - utcnow()).total_seconds() / 3600
        ),
    )

    body = (
        f"Hi,\n\n"
        f'{inviter_email} invited you to join the "{org_name}" '
        f"organisation on Hexgate as a {invitation.role}.\n\n"
        f"Open this link to accept (you'll be prompted to sign in or sign\n"
        f"up first if you don't have an account):\n\n"
        f"    {link}\n\n"
        f"The link expires in about {ttl_hours} hours. If you don't\n"
        f"recognise the sender, just delete this email — nothing happens\n"
        f"until you click.\n"
    )
    await get_email_sender().send(
        to=invitation.email,
        subject=f"{inviter_email} invited you to {org_name} on Hexgate",
        body=body,
    )
