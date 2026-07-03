"""Project CRUD — create/list under an org, read/rename by project id."""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.org import require_org_member, require_org_membership
from hexgate_api.deps.project import require_project_admin
from hexgate_api.models import OrganizationMember, Project, User
from hexgate_api.schemas import ProjectCreate, ProjectRead, ProjectUpdate

router = APIRouter()


def _project_read(project: Project) -> ProjectRead:
    return ProjectRead(
        id=project.id,
        org_id=project.org_id,
        name=project.name,
        created_at=project.created_at,
    )


@router.post("/orgs/{org_id}/projects", status_code=201, tags=["orgs"])
async def api_create_project(
    body: ProjectCreate,
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
    session: AsyncSession = Depends(get_session),
) -> ProjectRead:
    """Create a project under an org. Any member can create — projects
    are a workspace primitive, not a destructive op. The intent is to
    tighten to admin-only later if needed (one-line change in the dep).

    409 if a project with the same name already exists in this org
    (the user probably meant to switch to the existing one).
    """
    from hexgate_api.features.projects.service import (
        ProjectNameTakenError,
        create_project,
    )

    _, caller_member = membership
    try:
        project = await create_project(
            session, org_id=caller_member.org_id, name=body.name
        )
    except ProjectNameTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _project_read(project)


@router.get("/orgs/{org_id}/projects", tags=["orgs"])
async def api_list_projects(
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
    session: AsyncSession = Depends(get_session),
) -> list[ProjectRead]:
    """List every project inside an org. Any member can list — the
    dashboard's project picker consumes this."""
    from hexgate_api.features.projects.service import list_projects

    _, caller_member = membership
    rows = await list_projects(session, caller_member.org_id)
    return [_project_read(p) for p in rows]


@router.get("/projects/{project_id}", tags=["projects"])
async def api_get_project(
    project_id: str,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> ProjectRead:
    """Detail view of a single project. The ``require_org_member`` dep
    resolves the project's org_id and gates on the caller being a
    member — same shape as the existing project-scoped routes
    (/agents, /tokens) so the auth surface stays uniform."""
    project = await session.get(Project, project_id)
    assert project is not None  # require_org_member already 404'd
    return _project_read(project)


@router.patch("/projects/{project_id}", tags=["projects"])
async def api_update_project(
    project_id: str,
    body: ProjectUpdate,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> ProjectRead:
    """Rename a project. Admin or owner required. 409 on name collision
    with another project in the same org."""
    from hexgate_api.features.projects.service import (
        ProjectNameTakenError,
        update_project_name,
    )

    try:
        project = await update_project_name(
            session, project_id=project_id, name=body.name
        )
    except ProjectNameTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    # require_project_admin already 404'd if the project was missing;
    # update_project_name returning None at this point would be a race.
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return _project_read(project)
