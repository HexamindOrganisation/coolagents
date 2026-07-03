"""Project-scoped auth gate requiring admin/owner role."""

from fastapi import Depends, HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.identity import require_user
from hexgate_api.models import OrganizationMember, Project, User


async def require_project_admin(
    project_id: str,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> tuple[User, OrganizationMember]:
    """Like :func:`require_org_member` (path-param ``project_id``,
    resolves project's org_id, requires membership) but additionally
    requires ``admin`` or ``owner`` role.

    Used by management endpoints on a project — PATCH name today;
    later DELETE and any "settings"-tab operations. The returned
    tuple gives handlers both the caller and their membership row so
    they can reference ``member.org_id`` without a second lookup.
    """
    from hexgate_api.constants import ROLE_ADMIN, ROLE_OWNER

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
    if membership.role not in {ROLE_OWNER, ROLE_ADMIN}:
        raise HTTPException(
            status_code=403,
            detail="admin or owner role required for this action",
        )
    return user, membership
