"""Project persistence: create, list, rename (unique name per org)."""

import uuid

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.models import Project


class ProjectNameTakenError(Exception):
    """Raised when create / rename would conflict with an existing
    project's name in the same org. Routes translate to HTTP 409.

    The unique(org_id, name) constraint on Project catches the race —
    this exception exists so the service layer can pre-check and
    surface a clean message rather than the bare ``IntegrityError``.
    """


async def create_project(
    session: AsyncSession,
    *,
    org_id: str,
    name: str,
) -> Project:
    """Insert a Project under ``org_id`` with a fresh UUID id.

    Raises :class:`ProjectNameTakenError` if a project with the same
    name already exists in this org. Pre-checks rather than relying on
    the IntegrityError from the unique constraint — gives a friendlier
    error to surface in the UI without parsing SQL error text.
    """
    existing = (
        await session.exec(
            select(Project).where(
                Project.org_id == org_id,
                Project.name == name,
            )
        )
    ).first()
    if existing is not None:
        raise ProjectNameTakenError(
            f"a project named {name!r} already exists in this org"
        )

    project = Project(id=str(uuid.uuid4()), org_id=org_id, name=name)
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


async def list_projects(session: AsyncSession, org_id: str) -> list[Project]:
    """All projects under an org, ordered by creation time so the
    user's seed/oldest project lands first in the dashboard list."""
    stmt = (
        select(Project).where(Project.org_id == org_id).order_by(Project.created_at)  # type: ignore[attr-defined]
    )
    return list((await session.exec(stmt)).all())


async def update_project_name(
    session: AsyncSession,
    *,
    project_id: str,
    name: str,
) -> Project | None:
    """Rename a project. Returns the updated row, or None when the
    project doesn't exist. Raises :class:`ProjectNameTakenError` if
    the new name collides with another project in the same org.

    A no-op rename (same name) is a 200 not a 409 — idempotent for
    "save" buttons that double-fire.
    """
    project = await session.get(Project, project_id)
    if project is None:
        return None
    if project.name == name:
        return project

    existing = (
        await session.exec(
            select(Project).where(
                Project.org_id == project.org_id,
                Project.name == name,
                Project.id != project_id,
            )
        )
    ).first()
    if existing is not None:
        raise ProjectNameTakenError(
            f"a project named {name!r} already exists in this org"
        )

    project.name = name
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project
