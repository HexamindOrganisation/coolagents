"""Policy-module store + resolve/check API (see docs/adr/R-POL-001).

Project-scoped: a project holds boundary + capability modules and a role
binding, and the resolve/check endpoints compose them via the hexgate SDK.
Reads gate on org membership; writes gate on project admin/owner (policy edits
are a management action). Compiling an agent's bundle from these modules is a
later step — this slice is store + inspection only, so no agent is touched.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.deps.org import require_org_member
from hexgate_api.deps.project import require_project_admin
from hexgate_api.features.policy_modules import service
from hexgate_api.models import OrganizationMember, PolicyModule, User
from hexgate_api.schemas import (
    PolicyCheckResponse,
    PolicyLintOut,
    PolicyModuleRead,
    PolicyModuleWrite,
    ResolvedPolicyResponse,
    RoleBindingsRead,
    RoleBindingsWrite,
)

router = APIRouter()


def _module_read(row: PolicyModule) -> PolicyModuleRead:
    return PolicyModuleRead(
        tier=row.tier,
        path=row.path,
        content=row.content,
        content_hash=row.content_hash,
        updated_at=row.updated_at,
    )


# --- module CRUD -------------------------------------------------------------


@router.get("/projects/{project_id}/policy-modules", tags=["policy"])
async def api_list_policy_modules(
    project_id: str,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> list[PolicyModuleRead]:
    """Every boundary + capability module in the project's library."""
    rows = await service.list_modules(session, project_id)
    return [_module_read(r) for r in rows]


@router.put("/projects/{project_id}/policy-modules/{tier}/{path:path}", tags=["policy"])
async def api_put_policy_module(
    project_id: str,
    tier: str,
    path: str,
    body: PolicyModuleWrite,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> PolicyModuleRead:
    """Create or replace one module. 422 if the tier is unknown or the content
    is not a valid policy."""
    try:
        row = await service.upsert_module(
            session, project_id=project_id, tier=tier, path=path, content=body.content
        )
    except service.InvalidModuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _module_read(row)


@router.delete(
    "/projects/{project_id}/policy-modules/{tier}/{path:path}",
    status_code=204,
    tags=["policy"],
)
async def api_delete_policy_module(
    project_id: str,
    tier: str,
    path: str,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> Response:
    deleted = await service.delete_module(
        session, project_id=project_id, tier=tier, path=path
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="module not found")
    return Response(status_code=204)


# --- role bindings -----------------------------------------------------------


@router.get("/projects/{project_id}/policy-roles", tags=["policy"])
async def api_get_policy_roles(
    project_id: str,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> RoleBindingsRead:
    return RoleBindingsRead(roles=await service.get_roles(session, project_id))


@router.put("/projects/{project_id}/policy-roles", tags=["policy"])
async def api_set_policy_roles(
    project_id: str,
    body: RoleBindingsWrite,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> RoleBindingsRead:
    roles = await service.set_roles(session, project_id=project_id, roles=body.roles)
    return RoleBindingsRead(roles=roles)


# --- resolve / check ---------------------------------------------------------


@router.get("/projects/{project_id}/policy/resolve", tags=["policy"])
async def api_resolve_policy(
    project_id: str,
    role: str | None = None,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> ResolvedPolicyResponse:
    """The composed effective policy per role. 422 if the module set can't be
    composed (e.g. a capability that denies, or a role importing an unknown
    capability) — use /policy/check to see that as a lint instead."""
    from hexgate.security import DEFAULT_ROLE_NAME, LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    try:
        result = await service.resolve(session, project_id)
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if role is not None and role not in result.by_role:
        raise HTTPException(
            status_code=404,
            detail=f"role {role!r} not defined (known: {sorted(result.by_role)})",
        )

    items = result.by_role.items() if role is None else [(role, result.by_role[role])]
    return ResolvedPolicyResponse(
        roles={
            r: lr.effective[DEFAULT_ROLE_NAME].model_dump(mode="json")
            for r, lr in items
        }
    )


@router.get("/projects/{project_id}/policy/check", tags=["policy"])
async def api_check_policy(
    project_id: str,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> PolicyCheckResponse:
    """Lints over the composed project (dead grants, unused capabilities, link
    errors...). Diagnostics-as-data: always 200. ``ok`` is False if any lint is
    an error."""
    lints = await service.check(session, project_id)
    out = [
        PolicyLintOut(
            code=lint.code,
            severity=lint.severity,
            message=lint.message,
            source=lint.source,
            tier=lint.tier,
            tool=lint.tool,
            role=lint.role,
        )
        for lint in lints
    ]
    ok = not any(lint.severity == "error" for lint in lints)
    return PolicyCheckResponse(ok=ok, lints=out)
