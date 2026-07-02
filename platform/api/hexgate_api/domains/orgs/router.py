"""Organization CRUD — list/create/read/update, cookie-authed."""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.identity import require_user
from hexgate_api.deps.org import require_org_admin, require_org_membership
from hexgate_api.models import Organization, OrganizationMember, User
from hexgate_api.schemas import OrgCreate, OrgRead, OrgUpdate, OrgWithRole

router = APIRouter()


def _org_read(org: Organization) -> OrgRead:
    return OrgRead(id=org.id, slug=org.slug, name=org.name, created_at=org.created_at)


@router.get("/orgs", tags=["orgs"])
async def api_list_orgs(
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> list[OrgWithRole]:
    """List every org the active user belongs to, with their role on each.

    Used by the dashboard's org switcher (Phase 5) — one request, no
    N+1 over memberships, role on the edge so the UI knows what
    actions to enable per row.

    **Repair path:** if the user has zero orgs (e.g., the
    ``on_after_register`` hook errored after FastAPI-Users committed
    the User row, or the user predates the personal-default-org
    bootstrap), call :func:`ensure_personal_default_org` here. The
    dashboard's first call on each session goes through this endpoint,
    so the repair is opportunistic and silent. The helper is
    idempotent on the "user already owns an org" invariant, so a
    concurrent repair-then-create race can't double-bootstrap.
    """
    from hexgate_api.domains.orgs.service import (
        ensure_personal_default_org,
        list_orgs_for_user,
    )

    rows = await list_orgs_for_user(session, user.id)
    if not rows:
        await ensure_personal_default_org(session, user)
        await session.commit()
        rows = await list_orgs_for_user(session, user.id)
    return [
        OrgWithRole(
            id=o.id, slug=o.slug, name=o.name, created_at=o.created_at, role=role
        )
        for o, role in rows
    ]


@router.post("/orgs", status_code=201, tags=["orgs"])
async def api_create_org(
    body: OrgCreate,
    user: User = Depends(require_user),
    session: AsyncSession = Depends(get_session),
) -> OrgRead:
    """Create a new Organization. Caller becomes the owner in the same
    transaction (no transient state with zero members).

    ``body.slug`` is optional — derived from the name when omitted, with
    the same collision-fallback chain :func:`ensure_personal_default_org`
    uses for signup. When the caller-supplied slug collides, we return
    409 rather than silently picking a different one — explicit failure
    so the UI can prompt for a tweak.
    """
    from hexgate_api.domains.orgs.service import (
        _email_to_slug_base,
        _generate_unique_org_slug,
        create_org,
    )

    if body.slug:
        existing = (
            await session.exec(
                select(Organization).where(Organization.slug == body.slug)
            )
        ).first()
        if existing is not None:
            raise HTTPException(
                status_code=409, detail=f"slug {body.slug!r} is already taken"
            )
        slug = body.slug
    else:
        # Derive from name using the same sanitizer as the email-prefix
        # path; if the derived slug is contested, the helper picks a
        # numbered or hex-suffixed variant.
        slug = await _generate_unique_org_slug(session, _email_to_slug_base(body.name))

    org = await create_org(session, name=body.name, slug=slug, owner_user_id=user.id)
    return _org_read(org)


@router.get("/orgs/{org_id}", tags=["orgs"])
async def api_get_org(
    membership: tuple[User, OrganizationMember] = Depends(require_org_membership),
    session: AsyncSession = Depends(get_session),
) -> OrgRead:
    """Detail view of one org. Membership required (any role)."""
    _, member = membership
    org = await session.get(Organization, member.org_id)
    # ``require_org_membership`` already 404'd if org is missing; the
    # `is not None` is paranoia for the type checker.
    assert org is not None
    return _org_read(org)


@router.patch("/orgs/{org_id}", tags=["orgs"])
async def api_update_org(
    body: OrgUpdate,
    membership: tuple[User, OrganizationMember] = Depends(require_org_admin),
    session: AsyncSession = Depends(get_session),
) -> OrgRead:
    """Update name and/or slug. ``admin`` or ``owner`` role required.

    Slug changes break existing /orgs/{old-slug}/... bookmarks; we let
    callers do it because the row's ``id`` is the stable handle every
    FK points at (the slug is a URL helper, mutable on purpose).
    Returns 409 if the new slug collides with another org's.
    """
    _, member = membership
    org = await session.get(Organization, member.org_id)
    assert org is not None

    if body.slug is not None and body.slug != org.slug:
        existing = (
            await session.exec(
                select(Organization).where(Organization.slug == body.slug)
            )
        ).first()
        if existing is not None:
            raise HTTPException(
                status_code=409, detail=f"slug {body.slug!r} is already taken"
            )
        org.slug = body.slug

    if body.name is not None:
        org.name = body.name

    session.add(org)
    await session.commit()
    await session.refresh(org)
    return _org_read(org)
