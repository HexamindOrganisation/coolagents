"""Policy-module store persistence + resolve/check over the hexgate SDK.

A project's policy is composed from boundary + capability modules and a role
binding, not one policy_yaml per agent (see docs/adr/R-POL-001). This module is
the store (CRUD) plus thin wrappers that turn the stored rows into the SDK's
``ModuleContent`` list and call ``resolve_for_project`` / ``check_project``. The
fold itself lives in the SDK; nothing here reimplements it.
"""

from __future__ import annotations

import hashlib
import json

import yaml
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.ids import new_id
from hexgate_api.models import PolicyModule, RoleBinding, utcnow

VALID_TIERS = ("boundary", "capability")


class InvalidModuleError(Exception):
    """A module's tier is unknown, or its content doesn't parse as a policy.

    Routes translate this to HTTP 422. Raised before the row is written so a
    malformed module never lands in the store.
    """


def _content_hash(content: str) -> str:
    """sha256 of the module's canonical JSON — the SAME scheme the SDK loader
    uses (``hexgate.security.module_loader``), so a module authored on the
    platform and the same module loaded from a file hash identically regardless
    of YAML formatting. ``default=str`` matches the loader for scalars YAML can
    produce that JSON can't (e.g. an unquoted date)."""
    payload = yaml.safe_load(content) or {}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_policy(content: str):
    """Parse a module's YAML into an AgentPolicy. The one place content is parsed,
    shared by write-time validation and read-time ModuleContent building so they
    can't drift."""
    from hexgate.security import AgentPolicy

    return AgentPolicy.model_validate(yaml.safe_load(content) or {})


def _validate_policy_yaml(content: str) -> None:
    """Reject content that isn't a valid AgentPolicy before it's stored."""
    try:
        _parse_policy(content)
    except Exception as exc:  # noqa: BLE001 — surface as a clean 422
        raise InvalidModuleError(f"module is not a valid policy: {exc}") from exc


# --- module CRUD -------------------------------------------------------------


async def list_modules(session: AsyncSession, project_id: str) -> list[PolicyModule]:
    stmt = (
        select(PolicyModule)
        .where(PolicyModule.project_id == project_id)
        .order_by(PolicyModule.tier, PolicyModule.path)  # type: ignore[arg-type]
    )
    return list((await session.exec(stmt)).all())


async def _get_module(
    session: AsyncSession, project_id: str, tier: str, path: str
) -> PolicyModule | None:
    return (
        await session.exec(
            select(PolicyModule).where(
                PolicyModule.project_id == project_id,
                PolicyModule.tier == tier,
                PolicyModule.path == path,
            )
        )
    ).first()


async def upsert_module(
    session: AsyncSession,
    *,
    project_id: str,
    tier: str,
    path: str,
    content: str,
) -> PolicyModule:
    """Create or replace one module. Validates the tier and the policy content.

    Insert falls back to update on the unique constraint, so two concurrent
    creates of the same module don't 500: the loser rolls back and updates the
    row the winner just wrote.
    """
    if tier not in VALID_TIERS:
        raise InvalidModuleError(
            f"unknown tier {tier!r} (expected one of {VALID_TIERS})"
        )
    _validate_policy_yaml(content)

    existing = await _get_module(session, project_id, tier, path)
    if existing is None:
        row = PolicyModule(
            id=new_id(PolicyModule),
            project_id=project_id,
            tier=tier,
            path=path,
            content=content,
            content_hash=_content_hash(content),
        )
        session.add(row)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            # A create-race leaves the row present on re-query, so fall through
            # to update it. Any other IntegrityError (e.g. a bad project_id FK)
            # is not a race — re-raise rather than assert on a None re-query.
            existing = await _get_module(session, project_id, tier, path)
            if existing is None:
                raise
        else:
            await session.refresh(row)
            return row

    existing.content = content
    existing.content_hash = _content_hash(content)
    existing.updated_at = utcnow()
    session.add(existing)
    await session.commit()
    await session.refresh(existing)
    return existing


async def delete_module(
    session: AsyncSession, *, project_id: str, tier: str, path: str
) -> bool:
    """Remove one module. Returns False if it didn't exist."""
    row = await _get_module(session, project_id, tier, path)
    if row is None:
        return False
    await session.delete(row)
    await session.commit()
    return True


# --- role bindings -----------------------------------------------------------


async def get_roles(session: AsyncSession, project_id: str) -> dict[str, list[str]]:
    rows = (
        await session.exec(
            select(RoleBinding).where(RoleBinding.project_id == project_id)
        )
    ).all()
    return {row.role: list(row.capabilities) for row in rows}


async def roles_importing(
    session: AsyncSession, project_id: str, path: str
) -> list[str]:
    """Role names whose binding still imports the capability ``path``.

    Used to block deleting a capability that a role still references: without
    this the delete succeeds but the project stops resolving (the SDK linker
    raises "role imports unknown capability"), so no new bundle is built and
    every agent keeps the old one — still granting the deleted capability.
    """
    roles = await get_roles(session, project_id)
    return sorted(role for role, caps in roles.items() if path in caps)


async def set_roles(
    session: AsyncSession, *, project_id: str, roles: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Replace the project's role bindings wholesale (a small, edited-together set).

    Retries once on an IntegrityError: two concurrent wholesale replaces can each
    delete the existing rows and re-insert the same ``(project_id, role)``,
    colliding on the unique constraint. The retry re-reads the winner's rows and
    replaces them cleanly instead of surfacing a 500 (same posture as
    ``upsert_module``'s create-race handling).
    """
    for attempt in range(2):
        existing = (
            await session.exec(
                select(RoleBinding).where(RoleBinding.project_id == project_id)
            )
        ).all()
        for row in existing:
            await session.delete(row)
        # Emit the DELETEs before the INSERTs — otherwise the unit-of-work can
        # order an INSERT first and trip the (project_id, role) unique constraint
        # when a role name recurs across edits (the common wholesale-replace case).
        await session.flush()
        for role, caps in roles.items():
            session.add(
                RoleBinding(
                    id=new_id(RoleBinding),
                    project_id=project_id,
                    role=role,
                    capabilities=list(caps),
                )
            )
        try:
            await session.commit()
            break
        except IntegrityError:
            await session.rollback()
            if attempt == 1:
                raise
    return await get_roles(session, project_id)


# --- resolve / check (over the SDK) ------------------------------------------


def _to_module_content(row: PolicyModule):
    from hexgate.security import ModuleContent

    return ModuleContent(
        name=row.path,
        kind=row.tier,  # "boundary" | "capability" == LayerKind
        policy=_parse_policy(row.content),
        source=f"{row.tier}/{row.path}",
        content_hash=row.content_hash,
    )


async def _sdk_inputs(session: AsyncSession, project_id: str):
    rows = await list_modules(session, project_id)
    boundaries = [_to_module_content(r) for r in rows if r.tier == "boundary"]
    capabilities = [_to_module_content(r) for r in rows if r.tier == "capability"]
    # No role bindings maps to None, not {}: the SDK reads None as "no roles, one
    # default importing every capability" (the all-compose behaviour the local
    # `hexgate policy resolve` and docs/adr/R-POL-001 document), whereas {} is a
    # present-but-empty binding that fail-closes. The platform has no typo-able
    # roles file, so "no bindings" is the no-roles case, not the empty one.
    roles = await get_roles(session, project_id) or None
    return boundaries, capabilities, roles


async def resolve(session: AsyncSession, project_id: str):
    """Compose the project into a role-keyed PolicySet. Raises the SDK's
    LinkError / PolicySetError / ConstraintParseError on an invalid set."""
    from hexgate.security import resolve_for_project

    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    return resolve_for_project(boundaries, capabilities, roles)


async def check(session: AsyncSession, project_id: str):
    """Lint the composed project. A hard link failure folds into a single
    error lint inside the SDK, so this always returns a list."""
    from hexgate.security import check_project

    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    return check_project(boundaries, capabilities, roles)


async def resolves(session: AsyncSession, project_id: str) -> bool:
    """Whether the project's modules currently compose into a valid policy.

    A cheap, opa-free precondition for accepting a policy write: ``True`` only if
    ``resolve`` succeeds. Catches the same set as the compile fail-safe — the SDK
    link/compose errors plus ``yaml.YAMLError`` / pydantic ``ValidationError``
    from re-parsing a stored row (see ``agents.service._modular_bundle``).
    """
    from pydantic import ValidationError

    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    try:
        await resolve(session, project_id)
        return True
    except (
        LinkError,
        PolicySetError,
        ConstraintParseError,
        ValidationError,
        yaml.YAMLError,
    ):
        return False


# --- enforcement integration (see docs/adr/R-POL-002) ------------------------


async def is_modular(session: AsyncSession, project_id: str) -> bool:
    """Whether the project compiles agents from modules rather than policy_yaml.

    A project is modular once it has at least one role binding. Binding a role is
    the deliberate opt-in: uploading a capability or boundary module alone does
    not flip enforcement, so a half-built library never bricks live agents.
    """
    row = (
        await session.exec(
            select(RoleBinding.id)  # type: ignore[arg-type]
            .where(RoleBinding.project_id == project_id)
            .limit(1)
        )
    ).first()
    return row is not None


def roles_json(result, role: str | None = None) -> dict:
    """The effective policy per role, as JSON-able dicts.

    Delegates to the SDK's ``effective_policy_by_role`` so the resolve endpoint
    and the compile path serialize a project the same way ``hexgate policy
    resolve`` does — same role order (sorted), same bytes. ``role`` narrows to a
    single role (the resolve endpoint's ``?role=``); ``None`` returns all.
    """
    from hexgate.security import effective_policy_by_role

    return effective_policy_by_role(result, None if role is None else [role])


async def resolved_policy_yaml(session: AsyncSession, project_id: str) -> str:
    """The project's resolved role-keyed policy as inline-roles YAML.

    Serializes to the ``roles:`` shape ``build_signed_bundle`` accepts, so the
    platform compile path is byte-for-byte the same as a single-file policy.
    Raises the SDK's ``LinkError`` / ``PolicySetError`` / ``ConstraintParseError``
    if the modules don't compose, so callers can leave live bundles untouched.
    """
    result = await resolve(session, project_id)
    return yaml.safe_dump({"roles": roles_json(result)}, sort_keys=False)
