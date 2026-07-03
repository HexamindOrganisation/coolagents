"""Org membership persistence + the role-rank rules shared with invitations.

The "at least one owner" invariant and the at-or-below role-escalation rule
live here so every caller (PATCH member role, accept invite) respects them.
"""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import ALL_ROLES, ROLE_ADMIN, ROLE_MEMBER, ROLE_OWNER
from hexgate_api.models import OrganizationMember, User


async def find_member(
    session: AsyncSession, *, org_id: str, user_id: str
) -> OrganizationMember | None:
    """Return the OrganizationMember row for (org, user), or None."""
    stmt = select(OrganizationMember).where(
        OrganizationMember.org_id == org_id,
        OrganizationMember.user_id == user_id,
    )
    return (await session.exec(stmt)).first()


async def list_org_members(
    session: AsyncSession, org_id: str
) -> list[tuple[OrganizationMember, User]]:
    """Return (membership, user) tuples for an org's members."""
    stmt = (
        select(OrganizationMember, User)
        .join(User, User.id == OrganizationMember.user_id)
        .where(OrganizationMember.org_id == org_id)
        .order_by(OrganizationMember.created_at)  # type: ignore[attr-defined]
    )
    return [(m, u) for m, u in (await session.exec(stmt)).all()]


async def _count_owners(session: AsyncSession, org_id: str) -> int:
    """How many ROLE_OWNER members an org currently has."""
    stmt = select(OrganizationMember).where(
        OrganizationMember.org_id == org_id,
        OrganizationMember.role == ROLE_OWNER,
    )
    return len((await session.exec(stmt)).all())


class LastOwnerError(Exception):
    """Raised when an action would leave an org with zero owners.

    Service-layer business-rule signal — routes translate to HTTP 409.
    """


async def remove_member(session: AsyncSession, *, org_id: str, user_id: str) -> bool:
    """Remove (user, org) membership. Returns True on delete, False if
    the row didn't exist. Refuses with :class:`LastOwnerError` if the
    removal would leave the org with zero owners.
    """
    member = await find_member(session, org_id=org_id, user_id=user_id)
    if member is None:
        return False
    if member.role == ROLE_OWNER and await _count_owners(session, org_id) <= 1:
        raise LastOwnerError(
            "cannot remove the last owner; promote another member to owner first"
        )
    await session.delete(member)
    await session.commit()
    return True


class RoleEscalationError(PermissionError):
    """Raised when a caller tries to set a member role above their own.

    Mirrors the :func:`_can_invite_role` rank check so the
    PATCH-member-role surface stays consistent with the invitation
    surface. Without this guard, an admin could PATCH their own
    membership row to ``{"role": "owner"}`` and seize the org —
    bypassing every other gate this layer enforces.
    """


# Role hierarchy as integers — higher is more privileged. Shared by
# :func:`_can_invite_role` and the accept-invite upgrade path so a
# refactor of one keeps both branches consistent.
_ROLE_RANK: dict[str, int] = {ROLE_MEMBER: 0, ROLE_ADMIN: 1, ROLE_OWNER: 2}


def _can_invite_role(inviter_role: str, target_role: str) -> bool:
    """True if a member with ``inviter_role`` can mint an invite for
    ``target_role``.

    Rule: at-or-below. Owners can invite anyone; admins can invite
    admin + member; members can't invite (the route layer rejects them
    upstream via require_org_admin). The rule stops privilege
    escalation by-design — admins can't mint owner invites and use them
    to promote themselves.
    """
    return _ROLE_RANK.get(inviter_role, -1) >= _ROLE_RANK.get(target_role, 99)


async def change_member_role(
    session: AsyncSession,
    *,
    org_id: str,
    user_id: str,
    new_role: str,
    caller_role: str,
) -> OrganizationMember | None:
    """Update a member's role. Returns the updated row, or None when
    the membership doesn't exist.

    Two refusal gates:
      * :class:`RoleEscalationError` — the caller can't assign a role
        above their own rank. Owner can set anything; admin can set
        admin + member; member can't reach this code path (the route
        layer rejects them via ``require_org_admin``).
      * :class:`LastOwnerError` — demoting the only owner is refused.

    ``caller_role`` is the caller's role on this org (resolved by the
    route layer via :func:`require_org_admin`).
    """
    if new_role not in ALL_ROLES:
        raise ValueError(f"unknown role: {new_role!r}")
    if not _can_invite_role(caller_role, new_role):
        raise RoleEscalationError(
            f"{caller_role} cannot assign role {new_role!r} — "
            "callers can only set roles at or below their own rank"
        )
    member = await find_member(session, org_id=org_id, user_id=user_id)
    if member is None:
        return None
    demoting_owner = member.role == ROLE_OWNER and new_role != ROLE_OWNER
    if demoting_owner and await _count_owners(session, org_id) <= 1:
        raise LastOwnerError(
            "cannot demote the last owner; promote another member to owner first"
        )
    member.role = new_role
    session.add(member)
    await session.commit()
    await session.refresh(member)
    return member
