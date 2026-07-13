"""Ban persistence: create / list / revoke + the active feed for the SDK.

Active = ``revoked_at`` is null; revoke is a soft delete. At most one active
ban per target, enforced here (SQLite has no reliable partial unique index).
"""

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.ids import new_id
from hexgate_api.models import Ban, User, utcnow

# Ban target kinds. BanCreate validates the wire value; these name the two
# kinds for service branching. Feature-local — the only consumer is this slice.
BAN_TYPE_AGENT = "agent"
BAN_TYPE_USER = "user"


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
    elif ban_type == BAN_TYPE_USER:
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
    """Insert an active ban; :class:`BanConflictError` if one already targets
    this agent/user in the project."""
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
    """Bans in a project, newest first; active-only unless ``include_revoked``."""
    conditions = [Ban.project_id == project_id]
    if not include_revoked:
        conditions.append(Ban.revoked_at.is_(None))  # type: ignore[union-attr]
    stmt = select(Ban).where(*conditions).order_by(Ban.created_at.desc())  # type: ignore[attr-defined]
    return list((await session.exec(stmt)).all())


async def emails_for_user_ids(
    session: AsyncSession, user_ids: set[str]
) -> dict[str, str]:
    """Map user id -> email for the given ids in one query. Ids with no live
    User row are omitted (account deleted) so callers fall back to the id."""
    ids = {uid for uid in user_ids if uid}
    if not ids:
        return {}
    rows = await session.exec(select(User.id, User.email).where(User.id.in_(ids)))  # type: ignore[attr-defined]
    return {uid: email for uid, email in rows.all()}


async def revoke_ban(
    session: AsyncSession,
    *,
    project_id: str,
    ban_id: str,
    revoked_by_user_id: str,
) -> Ban:
    """Soft-delete a ban, project-scoped so no cross-project revoke.
    :class:`BanNotFoundError` if unknown here; idempotent if already revoked."""
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
    """Active bans for the SDK feed, ordered by id for a deterministic ETag."""
    stmt = (
        select(Ban)
        .where(
            Ban.project_id == project_id,
            Ban.revoked_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(Ban.id)  # type: ignore[attr-defined]
    )
    return list((await session.exec(stmt)).all())
