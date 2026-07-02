"""Org-scoped auth gates — membership and admin/owner role checks.

``ROLE_ADMIN`` / ``ROLE_OWNER`` are imported lazily to avoid pulling the
services module into the import graph at dependency-definition time.
"""

from fastapi import Depends, HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.identity import require_user
from hexgate_api.models import Organization, OrganizationMember, Project, User


async def require_org_member(
    project_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Gate a project-scoped route on the active user's org membership.

    Resolves the project's ``org_id``, then confirms the active user has
    an ``OrganizationMember`` row for that org. Returns the ``User`` so
    handlers can use it directly without a second lookup.

    Status codes: ``404`` if the project doesn't exist (don't leak that
    fact by 403'ing); ``403`` if the project exists but the user isn't
    a member of its org.
    """
    project = await session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    membership = (
        await session.exec(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user.id,
                OrganizationMember.org_id == project.org_id,
            )
        )
    ).first()
    if membership is None:
        raise HTTPException(status_code=403, detail="not a member of this org")
    return user


async def require_org_membership(
    org_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> tuple[User, OrganizationMember]:
    """Gate an org-scoped route on the active user's membership.

    ``404`` if the org doesn't exist (don't leak which IDs are taken);
    ``403`` if the org exists but the user isn't a member.
    """
    org = await session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="org not found")
    membership = (
        await session.exec(
            select(OrganizationMember).where(
                OrganizationMember.org_id == org_id,
                OrganizationMember.user_id == user.id,
            )
        )
    ).first()
    if membership is None:
        raise HTTPException(status_code=403, detail="not a member of this org")
    return user, membership


async def require_org_admin(
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
) -> tuple[User, OrganizationMember]:
    """Stricter variant of :func:`require_org_membership` — caller must
    be ``admin`` or ``owner``. Used by management endpoints (PATCH org,
    invite member, remove member, change role)."""
    from hexgate_api.constants import ROLE_ADMIN, ROLE_OWNER

    _, member = membership
    if member.role not in {ROLE_OWNER, ROLE_ADMIN}:
        raise HTTPException(
            status_code=403, detail="admin or owner role required for this action"
        )
    return membership


async def require_org_admin_or_self(
    user_id: str,
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
) -> tuple[User, OrganizationMember]:
    """Variant for ``DELETE /v1/orgs/{org_id}/members/{user_id}``.

    Admin/owner can remove anyone in the org; plain members can only
    remove themselves (the "leave organization" flow). The path
    parameter ``user_id`` is the *target* of the removal — compared
    against the caller's ``user.id`` to decide whether self-only
    permission is sufficient.

    The last-owner guard fires inside :func:`hexgate_api.domains.members.service.remove_member`
    so either path is rejected when removal would orphan the org.
    """
    from hexgate_api.constants import ROLE_ADMIN, ROLE_OWNER

    caller, member = membership
    if member.role in {ROLE_OWNER, ROLE_ADMIN}:
        return membership
    if caller.id == user_id:
        return membership
    raise HTTPException(
        status_code=403,
        detail="only admins / owners can manage other members",
    )
