"""Ban persistence: create / list / revoke (dashboard) + active feed (SDK).

A ban overrides policy — it refuses execution of one agent, or of one
end-user across every agent in the project. *Active* means ``revoked_at``
is null; revoke is a soft delete that keeps the who/when trail on the row.
At most one active ban per target is enforced here (SQLite has no reliable
partial unique index), mirroring the invitation dedup pattern.
"""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import BAN_TYPE_AGENT
from hexgate_api.core.ids import new_id
from hexgate_api.models import Ban, utcnow


class BanConflictError(Exception):
    """An active ban already targets this exact agent/user. Routes -> 409."""


class BanNotFoundError(Exception):
    """No ban with this id in this project (unknown or cross-project). -> 404."""


async def _active_ban_for_target(
    session: AsyncSession,
    *,
    project_id: str,
    ban_type: str,
    target_agent_name: str | None,
    target_user_id: str | None,
) -> Ban | None:
    conditions = [
        Ban.project_id == project_id,
        Ban.ban_type == ban_type,
        Ban.revoked_at.is_(None),  # type: ignore[union-attr]
    ]
    if ban_type == BAN_TYPE_AGENT:
        conditions.append(Ban.target_agent_name == target_agent_name)
    else:
        conditions.append(Ban.target_user_id == target_user_id)
    return (await session.exec(select(Ban).where(*conditions))).first()


async def create_ban(
    session: AsyncSession,
    *,
    project_id: str,
    created_by_user_id: str,
    ban_type: str,
    target_agent_name: str | None,
    target_user_id: str | None,
    reason: str | None,
) -> Ban:
    """Insert an active ban. Raises :class:`BanConflictError` if an active
    ban already targets the same agent/user in this project (the operator
    likely wants to edit the existing one, not stack duplicates)."""
    existing = await _active_ban_for_target(
        session,
        project_id=project_id,
        ban_type=ban_type,
        target_agent_name=target_agent_name,
        target_user_id=target_user_id,
    )
    if existing is not None:
        raise BanConflictError("an active ban already exists for this target")

    ban = Ban(
        id=new_id(Ban),
        project_id=project_id,
        created_by_user_id=created_by_user_id,
        ban_type=ban_type,
        target_agent_name=target_agent_name,
        target_user_id=target_user_id,
        reason=reason,
    )
    session.add(ban)
    await session.commit()
    await session.refresh(ban)
    return ban


async def list_bans(
    session: AsyncSession,
    *,
    project_id: str,
    include_revoked: bool = False,
) -> list[Ban]:
    """Bans in a project, newest first. Active-only unless
    ``include_revoked`` (the dashboard's default view hides revoked ones)."""
    conditions = [Ban.project_id == project_id]
    if not include_revoked:
        conditions.append(Ban.revoked_at.is_(None))  # type: ignore[union-attr]
    stmt = select(Ban).where(*conditions).order_by(Ban.created_at.desc())  # type: ignore[attr-defined]
    return list((await session.exec(stmt)).all())


async def revoke_ban(
    session: AsyncSession,
    *,
    project_id: str,
    ban_id: str,
    revoked_by_user_id: str,
) -> Ban:
    """Soft-delete a ban (stamp ``revoked_at`` / ``revoked_by_user_id``).

    Scoped by ``project_id`` so one project can't revoke another's ban.
    Raises :class:`BanNotFoundError` if the id is unknown in this project.
    Idempotent: re-revoking an already-revoked ban leaves it unchanged.
    """
    ban = (
        await session.exec(
            select(Ban).where(Ban.id == ban_id, Ban.project_id == project_id)
        )
    ).first()
    if ban is None:
        raise BanNotFoundError(f"no ban {ban_id!r} in this project")

    if ban.revoked_at is None:
        ban.revoked_at = utcnow()
        ban.revoked_by_user_id = revoked_by_user_id
        session.add(ban)
        await session.commit()
        await session.refresh(ban)
    return ban


async def active_bans_for_project(
    session: AsyncSession, *, project_id: str
) -> list[Ban]:
    """Active bans served to the SDK feed, in a stable order (by id) so the
    ETag is deterministic across requests."""
    stmt = (
        select(Ban)
        .where(
            Ban.project_id == project_id,
            Ban.revoked_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(Ban.id)  # type: ignore[attr-defined]
    )
    return list((await session.exec(stmt)).all())
