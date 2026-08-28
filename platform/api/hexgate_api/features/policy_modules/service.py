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
from hexgate_api.models import PolicyFolder, PolicyModule, RoleBinding, utcnow

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


def _hash_payload(payload) -> str:
    """sha256 of the module's canonical JSON — the SAME scheme the SDK loader
    uses (``hexgate.security.module_loader``), so a module authored on the
    platform and the same module loaded from a file hash identically regardless
    of YAML formatting. ``default=str`` matches the loader for scalars YAML can
    produce that JSON can't (e.g. an unquoted date)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _content_hash(content: str) -> str:
    """Parse raw YAML text and canonical-hash it."""
    return _hash_payload(yaml.safe_load(content) or {})


def _load(content: str):
    """Parse a module's YAML once → ``(payload, AgentPolicy)``. Raises on invalid
    YAML / schema; callers wrap into ``InvalidModuleError`` where a clean 4xx or a
    lint is wanted, so the raw pydantic/YAML error never escapes as a 500."""
    from hexgate.security import AgentPolicy

    payload = yaml.safe_load(content) or {}
    return payload, AgentPolicy.model_validate(payload)


def _parse_policy(content: str):
    """Parse a module's YAML into an AgentPolicy (read paths that don't also need
    the raw payload for hashing)."""
    return _load(content)[1]


def _validate_module(tier: str, path: str, content: str):
    """Validate a module about to be stored — schema **and** tier semantics — and
    return ``(payload, policy)`` so the caller hashes without re-parsing.

    A capability that ``deny``s is rejected here (fail fast, clean 422) rather
    than parsing cleanly and then poisoning the whole project's resolve via the
    SDK's library-wide capability-deny check."""
    try:
        payload, policy = _load(content)
    except Exception as exc:  # noqa: BLE001 — surface as a clean 422
        raise InvalidModuleError(f"module is not a valid policy: {exc}") from exc
    if tier == "capability":
        for tool, tp in policy.tools.items():
            if tp.mode == "deny":
                raise InvalidModuleError(
                    f"capability {path!r} denies {tool!r}; capabilities may only "
                    f"grant — move the deny to a boundary"
                )
    return payload, policy


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


async def get_module_peek(
    session: AsyncSession, project_id: str, tier: str, path: str
) -> tuple[str | None, str | None]:
    """``(content, content_hash)`` of the stored module, or ``(None, None)``.

    One read, so a caller can both detect a real change (compare the hash) and
    restore the prior content if an edit turns out to break the project."""
    row = await _get_module(session, project_id, tier, path)
    return (row.content, row.content_hash) if row is not None else (None, None)


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
    payload, _policy = _validate_module(tier, path, content)  # parses once
    content_hash = _hash_payload(payload)

    existing = await _get_module(session, project_id, tier, path)
    if existing is None:
        row = PolicyModule(
            id=new_id(PolicyModule),
            project_id=project_id,
            tier=tier,
            path=path,
            content=content,
            content_hash=content_hash,
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
    existing.content_hash = content_hash
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


# --- folders (persisted empty folders; see models.PolicyFolder) --------------
# Folders are usually derived from module paths; these rows exist only to keep
# an EMPTY folder visible before any module lands in it. They never reach
# resolve/analyze (those read modules), so no recompile on folder writes.


async def _get_folder(
    session: AsyncSession, project_id: str, tier: str, path: str
) -> PolicyFolder | None:
    stmt = select(PolicyFolder).where(
        PolicyFolder.project_id == project_id,
        PolicyFolder.tier == tier,
        PolicyFolder.path == path,
    )
    return (await session.exec(stmt)).first()


async def list_folders(session: AsyncSession, project_id: str) -> list[PolicyFolder]:
    """Every persisted empty folder in the project's library."""
    stmt = (
        select(PolicyFolder)
        .where(PolicyFolder.project_id == project_id)
        .order_by(PolicyFolder.tier, PolicyFolder.path)  # type: ignore[arg-type]
    )
    return list((await session.exec(stmt)).all())


async def create_folder(
    session: AsyncSession, *, project_id: str, tier: str, path: str
) -> PolicyFolder:
    """Create an empty folder marker. Idempotent: returns the existing row if
    the folder is already present (so re-creating is a no-op, not a 409)."""
    if tier not in VALID_TIERS:
        raise InvalidModuleError(
            f"unknown tier {tier!r} (expected one of {VALID_TIERS})"
        )
    existing = await _get_folder(session, project_id, tier, path)
    if existing is not None:
        return existing
    row = PolicyFolder(
        id=new_id(PolicyFolder), project_id=project_id, tier=tier, path=path
    )
    session.add(row)
    try:
        await session.commit()
    except IntegrityError:
        # A concurrent create won the unique constraint — return its row.
        await session.rollback()
        existing = await _get_folder(session, project_id, tier, path)
        if existing is None:
            raise
        return existing
    await session.refresh(row)
    return row


async def delete_folder(
    session: AsyncSession, *, project_id: str, tier: str, path: str
) -> bool:
    """Remove an empty-folder marker. Returns False if it didn't exist. Modules
    under the prefix (if any) are untouched — the folder then stays derived."""
    row = await _get_folder(session, project_id, tier, path)
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

    # Modules are validated at write, but a stored one can still fail to parse
    # after an SDK schema tightening or an out-of-band edit. Surface that as a
    # clean InvalidModuleError (→ a lint on check, a 422 on resolve) rather than
    # letting a raw pydantic error escape as a 500.
    try:
        policy = _parse_policy(row.content)
    except Exception as exc:  # noqa: BLE001
        raise InvalidModuleError(
            f"stored module {row.tier}/{row.path} is invalid: {exc}"
        ) from exc
    return ModuleContent(
        name=row.path,
        kind=row.tier,  # "boundary" | "capability" == LayerKind
        policy=policy,
        source=f"{row.tier}/{row.path}",
        content_hash=row.content_hash,
    )


def _to_role_matrix(matrix: RoleMatrixJson):
    """The stored JSON matrix (``role -> agent -> [caps]``) → the SDK's RoleMatrix
    (AgentBinding cells), or ``None`` when empty.

    No role bindings maps to ``None``, not ``{}``: the SDK reads ``None`` as "no
    roles, one default importing every capability" (the all-compose behaviour the
    local ``hexgate policy resolve`` and docs/adr/R-POL-001 document), whereas
    ``{}`` is a present-but-empty binding that fail-closes. The platform has no
    typo-able roles file, so "no bindings" is the no-roles case, not the empty one.
    """
    from hexgate.security import AgentBinding

    return {
        role: {
            agent: AgentBinding(capabilities=tuple(caps))
            for agent, caps in cells.items()
        }
        for role, cells in matrix.items()
    } or None


async def _sdk_inputs(session: AsyncSession, project_id: str):
    rows = await list_modules(session, project_id)
    boundaries = [_to_module_content(r) for r in rows if r.tier == "boundary"]
    capabilities = [_to_module_content(r) for r in rows if r.tier == "capability"]
    roles = _to_role_matrix(await get_roles(session, project_id))
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
    """Lint the composed project. Always returns a list: a hard link failure
    folds into a link-error lint inside the SDK, and a stored module that no
    longer parses becomes an ``invalid-module`` lint here — never a raise."""
    from hexgate.security import check_project
    from hexgate.security.analyzer import PolicyLint

    try:
        boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    except InvalidModuleError as exc:
        return [PolicyLint("invalid-module", "error", str(exc))]
    return check_project(boundaries, capabilities, roles)


def compose_error_types() -> tuple[type[BaseException], ...]:
    """Exceptions meaning "the module set doesn't compose right now".

    The single source of truth shared by the write-time guard (:func:`resolves`)
    and the compile fail-safe (``agents.service``), so they can't drift on which
    errors fold to "keep the last-good bundle" versus escape as a 500 — the SDK
    link/compose errors plus ``yaml.YAMLError`` / pydantic ``ValidationError``
    from re-parsing a stored row. SDK imports stay lazy so this module loads
    without the SDK."""
    from pydantic import ValidationError

    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError

    return (
        LinkError,
        PolicySetError,
        ConstraintParseError,
        ValidationError,
        yaml.YAMLError,
    )


def _resolve_all_agents(boundaries, capabilities, roles) -> None:
    """Resolve EVERY agent column of ``roles`` (not just ``"*"``, so a named-agent
    cell importing an unknown capability is caught). Raises the SDK compose errors
    on failure; resolves only (no YAML serialization)."""
    from hexgate.security import resolve_for_project

    agents = {DEFAULT_AGENT}
    if roles:
        agents |= {agent for cells in roles.values() for agent in cells}
    for agent in agents:
        resolve_for_project(boundaries, capabilities, roles, agent=agent)


def normalize_roles(
    roles: RoleMatrixJson | dict[str, list[str]],
) -> RoleMatrixJson:
    """A flat-or-matrix role binding → the matrix JSON shape (flat → ``"*"``)."""
    return {role: _normalize_cell(cells) for role, cells in roles.items()}


async def resolves(session: AsyncSession, project_id: str) -> bool:
    """Whether the project's STORED modules + bindings compose for every agent.

    A cheap, opa-free precondition for accepting a write that edits a MODULE
    (the bindings are already stored). ``True`` only if every agent column
    resolves. ``_sdk_inputs`` is inside the ``try`` because it re-parses every
    stored module — a row that no longer parses is a compose failure (→ False →
    409), not a 500."""
    try:
        boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
        _resolve_all_agents(boundaries, capabilities, roles)
        return True
    except compose_error_types():
        return False


async def resolves_proposed(
    session: AsyncSession, project_id: str, proposed: RoleMatrixJson
) -> bool:
    """Whether the STORED modules compose with the PROPOSED role bindings, for
    every agent — validated in memory **before** writing, so an invalid binding
    is never briefly visible via a concurrent GET and no rollback is needed.
    ``_sdk_inputs`` is inside the ``try`` for the same reason as :func:`resolves`."""
    try:
        boundaries, capabilities, _stored = await _sdk_inputs(session, project_id)
        _resolve_all_agents(boundaries, capabilities, _to_role_matrix(proposed))
        return True
    except compose_error_types():
        return False


def _draft_module_content(tier: str, path: str, content: str):
    """A :class:`ModuleContent` from an unsaved draft (hash recomputed, not stored)."""
    from hexgate.security import ModuleContent

    return ModuleContent(
        name=path,
        kind=tier,
        policy=_parse_policy(content),  # raises on invalid YAML / schema
        source=f"{tier}/{path}",
        content_hash=_content_hash(content),
    )


async def resolves_with_module(
    session: AsyncSession, project_id: str, tier: str, path: str, content: str
) -> bool:
    """Whether the project still resolves with this DRAFT module overlaid, without
    writing it — validated in memory **before** the write, so a resolution-breaking
    edit (e.g. a capability with a deny) is rejected without a commit-then-rollback
    window a concurrent GET could observe.

    Raises :class:`InvalidModuleError` if the content isn't a valid policy (the
    caller maps that to 422); returns ``False`` only when the content is valid but
    the project no longer composes with it (→ 409)."""
    _validate_policy_yaml(content)  # → InvalidModuleError (422) on malformed content
    try:
        boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
        overlay = _draft_module_content(tier, path, content)
        if tier == "boundary":
            boundaries = [m for m in boundaries if m.name != path] + [overlay]
        else:
            capabilities = [m for m in capabilities if m.name != path] + [overlay]
        _resolve_all_agents(boundaries, capabilities, roles)
        return True
    except compose_error_types():
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


# --- editor: preview, test, move (see policy-editor-plan.md) -----------------


class ModulePathConflictError(Exception):
    """A move/rename target path already exists in that tier. Routes -> HTTP 409."""


def _draft_module_content(tier: str, path: str, content: str):
    """A ModuleContent from an unsaved draft (hash recomputed, not stored)."""
    from hexgate.security import ModuleContent

    return ModuleContent(
        name=path,
        kind=tier,
        policy=_parse_policy(content),  # raises on invalid YAML / schema
        source=f"{tier}/{path}",
        content_hash=_content_hash(content),
    )


async def _draft_inputs(
    session: AsyncSession,
    project_id: str,
    *,
    draft_module: tuple[str, str, str] | None = None,
    draft_roles: RoleMatrixJson | dict[str, list[str]] | None = None,
):
    """:func:`_sdk_inputs` with an optional unsaved-edit overlay.

    The editor edits one thing at a time, so at most one of ``draft_module``
    ``(tier, path, content)`` or ``draft_roles`` is set. The overlaid module
    replaces the stored one of the same ``(tier, path)`` (or is added if new);
    ``draft_roles`` (the ``(role, agent)`` matrix, or a flat ``role: [caps]``)
    replaces the stored bindings, collapsing ``{}`` to ``None`` so an emptied
    ``roles.yaml`` behaves like "no bindings" (all-compose), consistent with the
    stored path.
    """
    boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    return _overlay_draft(
        boundaries,
        capabilities,
        roles,
        draft_module=draft_module,
        draft_roles=draft_roles,
    )


def _overlay_draft(
    boundaries,
    capabilities,
    roles,
    *,
    draft_module: tuple[str, str, str] | None = None,
    draft_roles: dict[str, list[str]] | None = None,
):
    """Overlay one unsaved edit onto resolved inputs — the draft-parse step,
    split out so ``preview`` can attribute a *draft* parse failure to the draft,
    not to a stored module that separately fails to load. Raises if the draft
    module content doesn't parse/validate."""
    if draft_module is not None:
        tier, path, content = draft_module
        mc = _draft_module_content(tier, path, content)
        if tier == "boundary":
            boundaries = [m for m in boundaries if m.name != path] + [mc]
        else:
            capabilities = [m for m in capabilities if m.name != path] + [mc]
    if draft_roles is not None:
        roles = _to_role_matrix({r: _normalize_cell(c) for r, c in draft_roles.items()})
    return boundaries, capabilities, roles


async def preview(
    session: AsyncSession,
    project_id: str,
    *,
    draft_module: tuple[str, str, str] | None = None,
    draft_roles: dict[str, list[str]] | None = None,
):
    """Resolve + lint the project with an optional unsaved-edit overlay, without
    writing. Returns ``(resolved_by_role, lints)`` — always, diagnostics-as-data:
    a draft that won't parse or compose comes back as an error lint with an empty
    resolution rather than raising."""
    from hexgate.security import (
        LinkError,
        PolicySetError,
        analyze_project,
        resolve_for_project,
    )
    from hexgate.security.analyzer import PolicyLint
    from hexgate.security.constraints import ConstraintParseError

    try:
        boundaries, capabilities, roles = await _sdk_inputs(session, project_id)
    except Exception as exc:  # noqa: BLE001 — a STORED module no longer parses
        # Not the draft's fault — don't pin it to the edited file's path.
        return {}, [PolicyLint("parse-error", "error", str(exc), source=None)]

    try:
        boundaries, capabilities, roles = _overlay_draft(
            boundaries,
            capabilities,
            roles,
            draft_module=draft_module,
            draft_roles=draft_roles,
        )
    except Exception as exc:  # noqa: BLE001 — the draft itself doesn't parse
        src = draft_module[1] if draft_module else None
        return {}, [PolicyLint("parse-error", "error", str(exc), source=src)]

    try:
        result = resolve_for_project(boundaries, capabilities, roles)
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        return {}, [PolicyLint("link-error", "error", str(exc))]

    lints = analyze_project(result, boundaries, capabilities, roles)
    return roles_json(result), lints


async def test_policy(
    session: AsyncSession,
    project_id: str,
    *,
    role: str,
    tool: str,
    agent: str = DEFAULT_AGENT,
    args: dict,
    attributes: dict | None = None,
    draft_module: tuple[str, str, str] | None = None,
    draft_roles: RoleMatrixJson | dict[str, list[str]] | None = None,
):
    """Evaluate one tool call against the resolved policy for ``role`` + ``agent``.

    Resolves the executing ``agent``'s column of the ``(role, agent)`` matrix (all
    boundaries + that cell's capabilities), with the same optional draft overlay
    as :func:`preview`, then runs the pydantic engine. Returns the SDK ``Verdict``.
    Raises the SDK compose errors if the set doesn't resolve, and ``KeyError``
    (mapped to 404) for an unknown role.
    """
    from hexgate.security import resolve_for_project

    boundaries, capabilities, roles = await _draft_inputs(
        session, project_id, draft_module=draft_module, draft_roles=draft_roles
    )
    result = resolve_for_project(boundaries, capabilities, roles, agent=agent)
    if role not in result.policy_set.roles:
        raise KeyError(role)
    return result.policy_set.evaluate(
        role=role, tool=tool, args=dict(args), attributes=attributes
    )


async def move_module(
    session: AsyncSession, *, project_id: str, tier: str, path: str, new_path: str
) -> PolicyModule | None:
    """Rename/move a module within its tier. Returns None if it doesn't exist.

    A capability rename cascades to every role binding that imported it (roles
    reference capabilities by name), all in one transaction, so a reorg never
    leaves a dangling binding. Boundaries are not referenced by name, so no
    cascade. Raises :class:`ModulePathConflictError` if ``new_path`` is taken.
    """
    row = await _get_module(session, project_id, tier, path)
    if row is None:
        return None
    if new_path == path:
        return row
    if await _get_module(session, project_id, tier, new_path) is not None:
        raise ModulePathConflictError(
            f"a {tier} module {new_path!r} already exists in this project"
        )

    row.path = new_path
    row.updated_at = utcnow()
    session.add(row)

    if tier == "capability":
        bindings = (
            await session.exec(
                select(RoleBinding).where(RoleBinding.project_id == project_id)
            )
        ).all()
        for b in bindings:
            cells = _normalize_cell(b.capabilities)  # {agent: [caps]}
            if any(path in caps for caps in cells.values()):
                # reassign (not in-place) so SQLAlchemy tracks the JSON change;
                # rename the capability in every agent column that imports it.
                b.capabilities = {
                    # dedupe (order-preserving): if a cell already imported
                    # new_path, renaming path->new_path would double it.
                    agent: list(
                        dict.fromkeys(new_path if c == path else c for c in caps)
                    )
                    for agent, caps in cells.items()
                }
                session.add(b)

    await session.commit()
    await session.refresh(row)
    return row
