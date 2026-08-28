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
import logging
from collections.abc import Iterable

import yaml
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.ids import new_id
from hexgate_api.models import PolicyModule, RoleBinding, utcnow

logger = logging.getLogger("hexgate.platform.policy_modules")

VALID_TIERS = ("boundary", "capability")

# The generic/default agent key in a role binding. Mirrors
# ``hexgate.security.DEFAULT_AGENT``; kept local so the store CRUD (get/set_roles)
# doesn't import the SDK at module load — the SDK is imported lazily in resolve.
DEFAULT_AGENT = "*"


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


async def get_module_hash(
    session: AsyncSession, project_id: str, tier: str, path: str
) -> str | None:
    """The stored module's ``content_hash``, or ``None`` if it doesn't exist.

    Lets a caller tell a real content change from a byte-identical re-PUT and
    skip the (expensive) recompile when nothing changed."""
    row = await _get_module(session, project_id, tier, path)
    return row.content_hash if row is not None else None


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


RoleMatrixJson = dict[str, dict[str, list[str]]]
"""The platform's JSON-friendly binding shape: role -> agent-or-"*" -> caps."""


def _normalize_cell(stored: object) -> dict[str, list[str]]:
    """One stored ``RoleBinding.capabilities`` value → ``{agent: [caps]}``.

    A legacy flat ``[names]`` list reads as the generic ``{"*": [names]}`` agent,
    so old rows keep their exact meaning with no migration. A mapping is already
    the matrix and passes through.
    """
    if isinstance(stored, dict):
        return {str(agent): list(caps) for agent, caps in stored.items()}
    if isinstance(stored, list):
        return {DEFAULT_AGENT: [str(c) for c in stored]}
    # The column is model-constrained to list|dict, so this only fires on a
    # corrupt row (a direct DB edit, a future bug). Fail closed (the role grants
    # nothing) but don't swallow it silently — log so check()/ops can see it.
    logger.warning(
        "role_binding.capabilities has unexpected shape %r; treating as empty",
        type(stored).__name__,
    )
    return {}


async def get_roles(session: AsyncSession, project_id: str) -> RoleMatrixJson:
    """The project's role bindings as ``role -> agent-or-"*" -> capabilities``.

    Legacy flat rows normalize to the generic ``"*"`` agent, so a project written
    before the agent axis reads back identically.
    """
    rows = (
        await session.exec(
            select(RoleBinding).where(RoleBinding.project_id == project_id)
        )
    ).all()
    return {row.role: _normalize_cell(row.capabilities) for row in rows}


async def roles_importing(
    session: AsyncSession, project_id: str, path: str
) -> list[str]:
    """Role names whose binding still imports the capability ``path`` under ANY agent.

    Used to block deleting a capability that a role still references: without
    this the delete succeeds but the project stops resolving (the SDK linker
    raises "role imports unknown capability"), so no new bundle is built and
    every agent keeps the old one — still granting the deleted capability.
    """
    roles = await get_roles(session, project_id)
    return sorted(
        role
        for role, cells in roles.items()
        if any(path in caps for caps in cells.values())
    )


async def set_roles(
    session: AsyncSession,
    *,
    project_id: str,
    roles: RoleMatrixJson | dict[str, list[str]],
) -> RoleMatrixJson:
    """Replace the project's role bindings wholesale (a small, edited-together set).

    Accepts either the matrix (``role -> {agent: [caps]}``) or the flat form
    (``role -> [caps]``, normalized to the generic ``"*"`` agent), so a flat
    caller stays valid. Stores each role's ``{agent: [caps]}`` mapping in the
    row's JSON value — no schema change.

    Retries once on an IntegrityError: two concurrent wholesale replaces can each
    delete the existing rows and re-insert the same ``(project_id, role)``,
    colliding on the unique constraint. The retry re-reads the winner's rows and
    replaces them cleanly instead of surfacing a 500 (same posture as
    ``upsert_module``'s create-race handling).
    """
    normalized = {role: _normalize_cell(cells) for role, cells in roles.items()}
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
        for role, cells in normalized.items():
            session.add(
                RoleBinding(
                    id=new_id(RoleBinding),
                    project_id=project_id,
                    role=role,
                    capabilities=dict(cells),
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
    from hexgate.security import AgentBinding

    rows = await list_modules(session, project_id)
    boundaries = [_to_module_content(r) for r in rows if r.tier == "boundary"]
    capabilities = [_to_module_content(r) for r in rows if r.tier == "capability"]
    # Convert the stored JSON matrix into the SDK's RoleMatrix (AgentBinding cells).
    # No role bindings maps to None, not {}: the SDK reads None as "no roles, one
    # default importing every capability" (the all-compose behaviour the local
    # `hexgate policy resolve` and docs/adr/R-POL-001 document), whereas {} is a
    # present-but-empty binding that fail-closes. The platform has no typo-able
    # roles file, so "no bindings" is the no-roles case, not the empty one.
    matrix = await get_roles(session, project_id)
    roles = {
        role: {
            agent: AgentBinding(capabilities=tuple(caps))
            for agent, caps in cells.items()
        }
        for role, cells in matrix.items()
    } or None
    return boundaries, capabilities, roles


async def resolve(session: AsyncSession, project_id: str, agent: str = DEFAULT_AGENT):
    """Compose one agent's role-keyed PolicySet (Path A). Raises the SDK's
    LinkError / PolicySetError / ConstraintParseError on an invalid set.

    ``agent`` selects the executing agent's column of the ``(role, agent)`` matrix
    (default ``"*"`` — the generic view). Each agent resolves to its own bundle."""
    from hexgate.security import resolve_for_project

    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    return resolve_for_project(boundaries, capabilities, roles, agent=agent)


async def check(session: AsyncSession, project_id: str):
    """Lint the composed project. A hard link failure folds into a single
    error lint inside the SDK, so this always returns a list."""
    from hexgate.security import check_project

    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    return check_project(boundaries, capabilities, roles)


def _bound_agents(matrix: RoleMatrixJson) -> set[str]:
    """Every agent column present in the bindings, plus the generic ``"*"``.

    The set of agents whose resolution must be validated: a named agent's column
    can import a capability the ``"*"`` column doesn't, so validating only ``"*"``
    would miss an unknown-capability error in a named column."""
    return {DEFAULT_AGENT} | {agent for cells in matrix.values() for agent in cells}


async def resolves(session: AsyncSession, project_id: str) -> bool:
    """Whether the project's modules compose into a valid policy for EVERY agent.

    A cheap, opa-free precondition for accepting a policy write: ``True`` only if
    every agent column resolves (not just ``"*"``), so a named-agent cell that
    imports an unknown capability is rejected at write time rather than accepted
    and then silently failing to compile. Catches the same set as the compile
    fail-safe — the SDK link/compose errors plus ``yaml.YAMLError`` / pydantic
    ``ValidationError`` from re-parsing a stored row (see
    ``agents.service._modular_bundle``).
    """
    from pydantic import ValidationError

    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    agents = _bound_agents(await get_roles(session, project_id))
    try:
        await resolved_yaml_by_agent(session, project_id, agents)
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


async def resolved_policy_yaml(
    session: AsyncSession, project_id: str, agent: str = DEFAULT_AGENT
) -> str:
    """One agent's resolved role-keyed policy as inline-roles YAML.

    Serializes to the ``roles:`` shape ``build_signed_bundle`` accepts, so the
    platform compile path is byte-for-byte the same as a single-file policy.
    ``agent`` selects that agent's column of the ``(role, agent)`` matrix (Path A:
    one bundle per agent). Raises the SDK's ``LinkError`` / ``PolicySetError`` /
    ``ConstraintParseError`` if the modules don't compose, so callers can leave
    live bundles untouched.
    """
    result = await resolve(session, project_id, agent=agent)
    return yaml.safe_dump({"roles": roles_json(result)}, sort_keys=False)


async def resolved_yaml_by_agent(
    session: AsyncSession, project_id: str, agents: Iterable[str]
) -> dict[str, str]:
    """Resolve several agents' policy YAML, loading modules + bindings **once**.

    Compiling a modular project fans out over its agents; resolving each via
    ``resolved_policy_yaml`` would re-read the store and re-parse every module per
    agent. This loads the SDK inputs once and resolves each agent's column in
    memory. Raises the SDK's link/compose errors if any agent's set doesn't
    compose, so callers keep the last-good bundle (fail-safe)."""
    from hexgate.security import resolve_for_project

    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    out: dict[str, str] = {}
    for agent in agents:
        result = resolve_for_project(boundaries, capabilities, roles, agent=agent)
        out[agent] = yaml.safe_dump({"roles": roles_json(result)}, sort_keys=False)
    return out
