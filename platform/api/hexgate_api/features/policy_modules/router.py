"""Policy-module store + resolve/check API (see docs/adr/R-POL-001).

Project-scoped: a project holds boundary + capability modules and a role
binding, and the resolve/check endpoints compose them via the hexgate SDK.
Reads gate on org membership; writes gate on project admin/owner (policy edits
are a management action). A write to a modular project recompiles its agents'
bundles from the resolved modules (see ``agents.service.recompile_project`` and
docs/adr/R-POL-002).
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.db import get_session
from hexgate_api.core.locks import project_lock
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

logger = logging.getLogger("hexgate.platform.policy_modules")


def _norm(roles: dict[str, dict[str, list[str]]]) -> dict[str, dict[str, list[str]]]:
    """Order-insensitive view of the ``(role, agent)`` matrix, so re-saving the
    same imports in a different order doesn't read as a change and trigger a
    needless recompile."""
    return {
        role: {agent: sorted(caps) for agent, caps in cells.items()}
        for role, cells in roles.items()
    }


def _module_read(row: PolicyModule) -> PolicyModuleRead:
    return PolicyModuleRead(
        tier=row.tier,
        path=row.path,
        content=row.content,
        content_hash=row.content_hash,
        updated_at=row.updated_at,
    )


async def _recompile_project_agents(session: AsyncSession, project_id: str) -> None:
    """Recompile the project's agent bundles after a policy change.

    Best-effort and never fatal to the write: the store row is the source of
    truth, the bundle is a derived artifact. A resolve failure leaves live
    bundles untouched (handled in the service); any other failure (opa, signing,
    a DB hiccup on the agent commit) is logged and swallowed so the policy edit
    still returns success. ``check`` surfaces an unresolvable state. R-POL-002.
    """
    from hexgate_api.core.keystore import keystore
    from hexgate_api.features.agents.service import recompile_project

    try:
        await recompile_project(session, project_id, keystore.sign)
    except Exception:  # noqa: BLE001 — bundles are derived + fail-safe
        logger.exception(
            "recompile after policy change failed for project %s", project_id
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
    # Serialize the write + recompile per project so overlapping edits can't
    # commit bundles out of order (see core.locks).
    async with project_lock(project_id):
        prev_hash = await service.get_module_hash(session, project_id, tier, path)
        try:
            row = await service.upsert_module(
                session,
                project_id=project_id,
                tier=tier,
                path=path,
                content=body.content,
            )
        except service.InvalidModuleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        # Recompile only when the content actually changed and the project is
        # modular: a byte-identical re-PUT, or any edit to a classic library,
        # changes no agent, so don't pay a resolve + opa compile for it.
        if row.content_hash != prev_hash and await service.is_modular(
            session, project_id
        ):
            await _recompile_project_agents(session, project_id)
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
    async with project_lock(project_id):
        # Refuse to delete a capability a role binding still imports: the delete
        # would otherwise succeed while the project stops resolving (linker:
        # "role imports unknown capability"), so no new bundle builds and every
        # agent keeps the old one — still granting the just-deleted capability.
        # Make the dangling reference the caller's problem to fix first.
        if tier == "capability":
            used_by = await service.roles_importing(session, project_id, path)
            if used_by:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"capability {path!r} is still imported by role(s) "
                        f"{used_by}; remove it from those role bindings first"
                    ),
                )

        deleted = await service.delete_module(
            session, project_id=project_id, tier=tier, path=path
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="module not found")
        if await service.is_modular(session, project_id):
            await _recompile_project_agents(session, project_id)
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
    # Hold the project lock across read-before → write → recompile so `before`
    # can't go stale under a concurrent PUT (comparing a pre-write snapshot
    # outside the lock could wrongly skip a needed recompile). See core.locks.
    async with project_lock(project_id):
        before = await service.get_roles(session, project_id)
        roles = await service.set_roles(
            session, project_id=project_id, roles=body.roles
        )
        # Idempotent re-save (order-insensitive): nothing changed, so skip the
        # resolve + opa compile.
        if _norm(roles) == _norm(before):
            return RoleBindingsRead(roles=roles)

        now_modular = bool(roles)
        was_modular = bool(before)

        # A modular project whose bindings don't resolve (a role importing an
        # unknown capability, a link error) must not be saved: is_modular would
        # flip True while agents keep stale/absent enforcement, with no way to
        # notice. Reject and restore the previous bindings so the project stays
        # in a resolvable state.
        if now_modular and not await service.resolves(session, project_id):
            await service.set_roles(session, project_id=project_id, roles=before)
            raise HTTPException(
                status_code=409,
                detail=(
                    "role bindings do not resolve to a valid policy; not saved "
                    "(see /policy/check for details)"
                ),
            )

        if now_modular and not was_modular:
            # classic→modular flip: agents currently hold policy_yaml-compiled
            # bundles that are now wrong. Require a freshly-built modular bundle;
            # if none can be built (e.g. opa unavailable) roll back rather than
            # leave is_modular True with stale classic WASM in force.
            from hexgate_api.core.keystore import keystore
            from hexgate_api.features.agents.service import recompile_project

            try:
                built = await recompile_project(session, project_id, keystore.sign)
            except Exception:  # noqa: BLE001 — any compile failure is "can't build"
                logger.exception(
                    "modular flip recompile failed for project %s", project_id
                )
                built = None
            if built is None:
                await service.set_roles(session, project_id=project_id, roles=before)
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "could not compile the modular policy bundle "
                        "(is opa available?); role bindings not saved"
                    ),
                )
        else:
            # Already modular (module/role tweak) or dropped back to classic —
            # the existing best-effort fail-safe applies (keep live bundles on a
            # transient failure; the store row is the source of truth).
            await _recompile_project_agents(session, project_id)

    return RoleBindingsRead(roles=roles)


# --- resolve / check ---------------------------------------------------------


@router.get("/projects/{project_id}/policy/resolve", tags=["policy"])
async def api_resolve_policy(
    project_id: str,
    role: str | None = None,
    agent: str = "*",
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> ResolvedPolicyResponse:
    """The composed effective policy per role, for one executing agent (``agent``,
    default the generic ``"*"``). 422 if the module set can't be composed (e.g. a
    capability that denies, or a role importing an unknown capability) — use
    /policy/check to see that as a lint instead."""
    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    try:
        result = await service.resolve(session, project_id, agent=agent)
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if role is not None and role not in result.by_role:
        raise HTTPException(
            status_code=404,
            detail=f"role {role!r} not defined (known: {sorted(result.by_role)})",
        )

    return ResolvedPolicyResponse(roles=service.roles_json(result, role=role))


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
