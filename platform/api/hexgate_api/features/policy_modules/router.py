"""Policy-module store + resolve/check API (see docs/adr/R-POL-001).

Project-scoped: a project holds boundary + capability modules and a role
binding, and the resolve/check endpoints compose them via the hexgate SDK.
Reads gate on org membership; writes gate on project admin/owner (policy edits
are a management action). A write to a modular project recompiles its agents'
bundles from the resolved modules (see ``agents.service.recompile_project`` and
docs/adr/R-POL-002).
"""

from __future__ import annotations

import json
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
    MoveModuleRequest,
    PolicyCheckResponse,
    PolicyDraft,
    PolicyFolderRead,
    PolicyLintOut,
    PolicyModuleRead,
    PolicyModuleWrite,
    PolicyPreviewRequest,
    PolicyPreviewResponse,
    PolicyTestRequest,
    PolicyTestResponse,
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


def _lint_out(lint) -> PolicyLintOut:
    return PolicyLintOut(
        code=lint.code,
        severity=lint.severity,
        message=lint.message,
        source=lint.source,
        tier=lint.tier,
        tool=lint.tool,
        role=lint.role,
    )


def _unpack_draft(draft: PolicyDraft | None):
    """PolicyDraft -> (draft_module tuple, draft_roles) for the service layer."""
    if draft is None:
        return None, None
    module = (
        (draft.module.tier, draft.module.path, draft.module.content)
        if draft.module
        else None
    )
    return module, draft.roles


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
        _prev_content, prev_hash = await service.get_module_peek(
            session, project_id, tier, path
        )
        modular = await service.is_modular(session, project_id)
        # Validate the edit BEFORE writing: an edit that breaks composition (e.g.
        # a capability with a deny, which the linker rejects) must not be accepted
        # silently — agents would keep the old bundle while the store held an
        # uncomposable module. Validating the draft in memory first means the
        # store is never briefly written with a broken module (no commit-then-
        # rollback window a concurrent GET could observe). Same pattern as the
        # roles PUT. Only for modular projects — a classic library edit changes
        # no agent, so composition doesn't gate it.
        if modular:
            try:
                composes = await service.resolves_with_module(
                    session, project_id, tier, path, body.content
                )
            except service.InvalidModuleError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if not composes:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"module {path!r} would break the project's policy "
                        "resolution; not saved (see /policy/check for details)"
                    ),
                )

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
        if modular and row.content_hash != prev_hash:
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


# --- folders (persisted empty folders) ---------------------------------------
# No recompile on folder writes: folders never reach resolve (they're not
# modules), so they can't change any agent's enforced bundle.


@router.get("/projects/{project_id}/policy-folders", tags=["policy"])
async def api_list_policy_folders(
    project_id: str,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> list[PolicyFolderRead]:
    """Persisted empty folders in the project's module library."""
    rows = await service.list_folders(session, project_id)
    return [PolicyFolderRead(tier=r.tier, path=r.path) for r in rows]


@router.put("/projects/{project_id}/policy-folders/{tier}/{path:path}", tags=["policy"])
async def api_put_policy_folder(
    project_id: str,
    tier: str,
    path: str,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> PolicyFolderRead:
    """Create an empty folder marker (idempotent). 422 if the tier is unknown."""
    try:
        row = await service.create_folder(
            session, project_id=project_id, tier=tier, path=path
        )
    except service.InvalidModuleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return PolicyFolderRead(tier=row.tier, path=row.path)


@router.delete(
    "/projects/{project_id}/policy-folders/{tier}/{path:path}",
    status_code=204,
    tags=["policy"],
)
async def api_delete_policy_folder(
    project_id: str,
    tier: str,
    path: str,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> Response:
    deleted = await service.delete_folder(
        session, project_id=project_id, tier=tier, path=path
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="folder not found")
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
        proposed = service.normalize_roles(body.roles)
        # Idempotent re-save (order-insensitive): nothing changed, so skip the
        # write + resolve + opa compile.
        if _norm(proposed) == _norm(before):
            return RoleBindingsRead(roles=before)

        now_modular = bool(proposed)
        was_modular = bool(before)

        # Validate the PROPOSED bindings BEFORE writing them: a modular project
        # whose bindings don't resolve (a role importing an unknown capability, a
        # link error) must not be saved. Validating in memory first means an
        # invalid binding is never briefly visible to a concurrent GET, and no
        # rollback of the store is needed.
        if now_modular and not await service.resolves_proposed(
            session, project_id, proposed
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "role bindings do not resolve to a valid policy; not saved "
                    "(see /policy/check for details)"
                ),
            )

        roles = await service.set_roles(session, project_id=project_id, roles=proposed)

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
    agent: str = service.DEFAULT_AGENT,
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
    except (
        LinkError,
        PolicySetError,
        ConstraintParseError,
        service.InvalidModuleError,
    ) as exc:
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
    ok = not any(lint.severity == "error" for lint in lints)
    return PolicyCheckResponse(ok=ok, lints=[_lint_out(x) for x in lints])


# --- editor: preview, test, move (see policy-editor-plan.md) -----------------

_OUTCOME_WIRE = {
    "ALLOW": "allow",
    "DENY": "deny",
    "NEEDS_APPROVAL": "approval_required",
}


@router.post("/projects/{project_id}/policy/preview", tags=["policy"])
async def api_preview_policy(
    project_id: str,
    body: PolicyPreviewRequest,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> PolicyPreviewResponse:
    """Resolve + lint the project with the editor's unsaved edit overlaid, without
    writing. Powers the debounced live preview. Always 200 (diagnostics-as-data)."""
    draft_module, draft_roles = _unpack_draft(body.draft)
    resolved, lints = await service.preview(
        session, project_id, draft_module=draft_module, draft_roles=draft_roles
    )
    return PolicyPreviewResponse(resolved=resolved, lints=[_lint_out(x) for x in lints])


@router.post("/projects/{project_id}/policy/test", tags=["policy"])
async def api_test_policy(
    project_id: str,
    body: PolicyTestRequest,
    _user: User = Depends(require_org_member),
    session: AsyncSession = Depends(get_session),
) -> PolicyTestResponse:
    """Evaluate one tool call against the whole resolved policy for a role — the
    'would this be allowed?' probe. 422 if the modules don't compose; 404 for an
    unknown role. Reflects the editor's unsaved edit via ``draft``."""
    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    draft_module, draft_roles = _unpack_draft(body.draft)
    try:
        verdict = await service.test_policy(
            session,
            project_id,
            role=body.role,
            tool=body.tool,
            args=body.args,
            attributes=body.attributes,
            draft_module=draft_module,
            draft_roles=draft_roles,
        )
    except service.InvalidModuleError as exc:
        raise HTTPException(status_code=422, detail=f"draft is invalid: {exc}") from exc
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        raise HTTPException(
            status_code=422, detail=f"policy does not compose: {exc}"
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=404, detail=f"role {exc.args[0]!r} not defined"
        ) from exc

    return PolicyTestResponse(
        outcome=_OUTCOME_WIRE.get(verdict.outcome.name, verdict.outcome.name.lower()),
        reason=verdict.reason,
        violations=[str(v) for v in (verdict.violations or [])],
        # Verdict.hint is a machine-readable dict (file-scope path hint); the wire
        # field is a string, so serialize it rather than 500 on a dict.
        hint=json.dumps(verdict.hint) if verdict.hint is not None else None,
    )


@router.patch(
    "/projects/{project_id}/policy-modules/{tier}/{path:path}", tags=["policy"]
)
async def api_move_policy_module(
    project_id: str,
    tier: str,
    path: str,
    body: MoveModuleRequest,
    _membership: tuple[User, OrganizationMember] = Depends(require_project_admin),
    session: AsyncSession = Depends(get_session),
) -> PolicyModuleRead:
    """Rename/move a module within its tier. A capability rename cascades to the
    role bindings that imported it. 404 if absent, 409 if the target exists."""
    try:
        row = await service.move_module(
            session, project_id=project_id, tier=tier, path=path, new_path=body.new_path
        )
    except service.ModulePathConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="module not found")
    if await service.is_modular(session, project_id):
        await _recompile_project_agents(session, project_id)
    return _module_read(row)
