"""Agent + version persistence, policy-bundle compilation, manifest registration.

Groups the agent read/write helpers, the save-time WASM bundle compile+sign
(``compile_bundle`` shells out to the SDK/opa), and the ``hexgate register``
upsert path (manifest → Agent + AgentVersion + Tool rows, with a generated
starter policy on first registration).
"""

import asyncio
import hashlib
import json
import logging
from typing import Callable

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core.ids import new_id
from hexgate_api.models import Agent, AgentVersion, Tool
from hexgate_api.schemas import AgentManifest, ToolDefinition
from hexgate_api.features.agents.seed_data import SEED_AGENTS
from hexgate_api.features.agents.compiler import (
    _default_policy_for_manifest,
    compile_bundle,
)

# The generic/default agent key. Shared from the policy-modules service (the one
# platform copy) so store and compile can't drift on the sentinel. This import is
# SDK-free — policy_modules.service imports the SDK lazily — so it's safe at load.
from hexgate_api.features.policy_modules.service import DEFAULT_AGENT

logger = logging.getLogger("hexgate.platform.agents")


async def ensure_seeded_agents(session: AsyncSession, project_id: str) -> None:
    """Idempotently add any missing seeded agents to a project."""
    existing = {a.name for a in await list_agents(session, project_id)}
    added = False
    for seed in SEED_AGENTS:
        if seed["name"] in existing:
            continue
        session.add(
            Agent(
                id=new_id(Agent),
                project_id=project_id,
                name=seed["name"],
                agent_yaml=seed["agent_yaml"],
                policy_yaml=seed["policy_yaml"],
                system_md=seed["system_md"],
            )
        )
        added = True
    if added:
        await session.commit()


async def list_agents(session: AsyncSession, project_id: str) -> list[Agent]:
    stmt = select(Agent).where(Agent.project_id == project_id).order_by(Agent.name)  # type: ignore[attr-defined]
    return list((await session.exec(stmt)).all())


async def get_agent(session: AsyncSession, project_id: str, name: str) -> Agent | None:
    stmt = select(Agent).where(Agent.project_id == project_id, Agent.name == name)
    return (await session.exec(stmt)).first()


async def _compile_memoized(
    cache: dict[str, tuple[bytes, str, bytes] | None],
    policy_yaml: str,
    sign: Callable[[bytes], bytes],
) -> tuple[bytes, str, bytes] | None:
    """Compile ``policy_yaml`` once per distinct policy within a fan-out.

    A classic recompile/backfill runs opa once per agent, serially — but agents
    routinely share a policy (the seeds especially), so identical policies were
    recompiled N times, delaying startup readiness. Memoize by ``sha256`` of the
    policy text so each distinct policy shells out to opa at most once per call.
    """
    key = hashlib.sha256(policy_yaml.encode("utf-8")).hexdigest()
    if key not in cache:
        cache[key] = await asyncio.to_thread(compile_bundle, policy_yaml, sign)
    return cache[key]


def _apply_bundle(agent: Agent, bundle: tuple[bytes, str, bytes] | None) -> None:
    """Set an agent's three bundle columns from a compile result, or null all
    three when ``bundle`` is ``None`` (drop a stale bundle → the SDK falls back
    to the pydantic engine). One place so the triple can't drift when a bundle
    column is added or its ordering changes."""
    if bundle is None:
        agent.compiled_wasm = None
        agent.bundle_manifest = None
        agent.bundle_signature = None
    else:
        agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle


async def _modular_bundle(
    session: AsyncSession,
    project_id: str,
    sign: Callable[[bytes], bytes],
    *,
    agent: str = DEFAULT_AGENT,
    compiled: dict[str, tuple[bytes, str, bytes] | None] | None = None,
) -> tuple[bytes, str, bytes] | None:
    """Resolve + compile the bundle for ONE agent's column of the matrix (Path A).

    ``agent`` selects the executing agent's ``(role, agent)`` column (default the
    generic ``"*"``). Each agent resolves to its own role-keyed bundle, so a
    signed artifact carries only that agent's authority.

    Returns ``None`` (never raises) when the project doesn't resolve or the
    resolved policy can't compile (e.g. ``opa`` absent), so callers can leave
    live bundles untouched — the fail-safe in docs/adr/R-POL-002. The SDK
    resolve exceptions are imported here, on the modular path only, so a classic
    save never touches the SDK.

    ``compiled`` is an optional sha256-keyed compile cache: a fan-out over agents
    that resolve to identical policy then shells out to ``opa`` only once.

    The except tuple also covers ``yaml.YAMLError`` / pydantic ``ValidationError``:
    ``resolved_policy_yaml`` re-parses every stored module, and a row valid at
    write time can later fail to parse (an SDK schema tightening, or a row edited
    directly in the DB). Those must fold to "no bundle", not escape as a 500.
    """
    from hexgate_api.features.policy_modules import service as modules

    try:
        policy_yaml = await modules.resolved_policy_yaml(
            session, project_id, agent=agent
        )
    except modules.compose_error_types() as exc:
        logger.warning(
            "modular project %s agent %r does not resolve; no bundle: %s",
            project_id,
            agent,
            exc,
        )
        return None
    # opa is a synchronous subprocess — run it off the event loop (inside
    # _compile_memoized) so a policy write doesn't block every in-flight request.
    return await _compile_memoized(
        {} if compiled is None else compiled, policy_yaml, sign
    )


async def _resolved_yaml_or_none(
    session: AsyncSession, project_id: str, agent_names: set[str]
) -> dict[str, str] | None:
    """Resolve every named agent's policy YAML in one store read (fan-out helper).

    Returns ``None`` (never raises) if the project doesn't compose for some agent —
    the R-POL-002 fail-safe, so callers keep live bundles. Resolving here (once)
    rather than per agent avoids re-reading the store + re-parsing every module N
    times."""
    from hexgate_api.features.policy_modules import service as modules

    try:
        return await modules.resolved_yaml_by_agent(session, project_id, agent_names)
    except modules.compose_error_types() as exc:
        logger.warning(
            "modular project %s does not resolve; no bundles: %s", project_id, exc
        )
        return None


async def bundle_for_agent(
    session: AsyncSession, agent: Agent, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Compile the signed bundle for one agent, from the right source.

    Modular project (has a role binding): the agent's own column of the resolved
    ``(role, agent)`` matrix (Path A — one bundle per agent, keyed by name).
    Classic project: the agent's own ``policy_yaml`` (unchanged). See R-POL-002.
    """
    from hexgate_api.features.policy_modules import service as modules

    if await modules.is_modular(session, agent.project_id):
        return await _modular_bundle(session, agent.project_id, sign, agent=agent.name)
    return await asyncio.to_thread(compile_bundle, agent.policy_yaml, sign)


async def recompile_project(
    session: AsyncSession, project_id: str, sign: Callable[[bytes], bytes]
) -> int | None:
    """Recompile every agent in a project after its modules or roles change.

    Modular: resolve + compile **per agent** (each agent gets its own column of
    the (role, agent) matrix), memoizing the opa compile so agents that resolve
    identically build once. It's all-or-nothing: if ANY agent can't be built
    (unresolvable project, or a resolved policy that won't compile), live bundles
    are left untouched for the WHOLE project — the fail-safe in docs/adr/R-POL-002
    (never a partial update where some agents move and others are stale).

    Classic — including a project that just dropped its last role binding, so
    enforcement returns to each agent's ``policy_yaml`` — recompiles each agent
    from its own policy and **nulls the bundle when that policy no longer
    compiles**, matching ``update_agent`` and the ``Agent.compiled_wasm``
    invariant (a broken policy drops its stale bundle so the SDK falls back to
    pydantic rather than serving a now-wrong WASM).

    Returns the number of agents whose bundle was set, or ``None`` when the
    project is modular but its bundle could not be built (live bundles left
    untouched). The ``None`` return lets a caller distinguish "nothing to do"
    (``0``: no agents) from "could not build" — the classic→modular flip relies
    on it to avoid leaving agents on a stale classic bundle (see the roles PUT).
    """
    from hexgate_api.features.policy_modules import service as modules

    agents = await list_agents(session, project_id)
    if not agents:
        return 0

    count = 0
    if await modules.is_modular(session, project_id):
        # Resolve every agent's column in ONE store read, then compile each
        # (memoized so agents that resolve identically shell out to opa once).
        yaml_by_agent = await _resolved_yaml_or_none(
            session, project_id, {a.name for a in agents}
        )
        if yaml_by_agent is None:
            return None  # unresolvable → keep ALL live (fail-safe)
        compiled: dict[str, tuple[bytes, str, bytes] | None] = {}
        built: dict[str, tuple[bytes, str, bytes]] = {}
        for agent in agents:
            bundle = await _compile_memoized(compiled, yaml_by_agent[agent.name], sign)
            if bundle is None:
                return None  # any agent unbuildable → keep ALL live (no partial state)
            built[agent.id] = bundle
        for agent in agents:
            _apply_bundle(agent, built[agent.id])  # each agent's own bundle
            session.add(agent)
            count += 1
    else:
        from hexgate_api.features.agents.compiler import DENY_ALL_POLICY_YAML

        compiled: dict[str, tuple[bytes, str, bytes] | None] = {}
        for agent in agents:
            # An agent registered while the project was modular kept a deny-all
            # policy_yaml as its fail-closed fallback; on a revert to classic that
            # fallback becomes the ENFORCED policy. Fail-closed (safe), but the
            # operator should re-author it — surface it rather than silently
            # compiling deny-all. (See docs/adr/R-POL-002.)
            if agent.policy_yaml == DENY_ALL_POLICY_YAML:
                logger.warning(
                    "agent %s in project %s reverted to classic with a deny-all "
                    "fallback policy; edit its policy to grant tools",
                    agent.name,
                    project_id,
                )
            # Classic: each agent from its own policy (memoized per distinct
            # policy). A policy that no longer compiles nulls the stale bundle
            # (fall back to pydantic), never keeps a wrong one.
            bundle = await _compile_memoized(compiled, agent.policy_yaml, sign)
            _apply_bundle(agent, bundle)
            session.add(agent)
            count += 1

    if count:
        await session.commit()
    return count


async def get_latest_agent_version_id(
    session: AsyncSession, project_id: str, agent_name: str
) -> str:
    """Return the latest AgentVersion.id for (project, agent), or "" if unresolved."""
    agent = await get_agent(session, project_id, agent_name)
    if agent is None:
        return ""
    stmt = (
        select(AgentVersion.id)
        .where(AgentVersion.agent_id == agent.id)
        .order_by(AgentVersion.version.desc())  # type: ignore[attr-defined]
        .limit(1)
    )
    return (await session.exec(stmt)).first() or ""


async def get_latest_agent_versions_map(
    session: AsyncSession, agent_ids: list[str]
) -> dict[str, AgentVersion]:
    """Return a map of {agent_id: latest AgentVersion}
    for a list of agent ids in a single query.

    Agents with no registered version are omitted from the map.
    """
    if not agent_ids:
        return {}
    max_version_per_agent = (
        select(
            AgentVersion.agent_id,
            func.max(AgentVersion.version).label("max_version"),
        )
        .where(AgentVersion.agent_id.in_(agent_ids))
        .group_by(AgentVersion.agent_id)
        .subquery()
    )
    statement = select(AgentVersion).join(
        max_version_per_agent,
        (AgentVersion.agent_id == max_version_per_agent.c.agent_id)
        & (AgentVersion.version == max_version_per_agent.c.max_version),
    )
    return {
        version.agent_id: version for version in (await session.exec(statement)).all()
    }


async def update_agent(
    session: AsyncSession,
    project_id: str,
    name: str,
    *,
    agent_yaml: str | None = None,
    policy_yaml: str | None = None,
    system_md: str | None = None,
    sign: Callable[[bytes], bytes] | None = None,
) -> Agent | None:
    from datetime import datetime, timezone

    agent = await get_agent(session, project_id, name)
    if agent is None:
        return None
    if agent_yaml is not None:
        agent.agent_yaml = agent_yaml
    if policy_yaml is not None:
        agent.policy_yaml = policy_yaml
    if system_md is not None:
        agent.system_md = system_md

    # Recompile from the agent's own policy — classic projects only. We rebuild
    # rather than diff so a fixed policy re-acquires a bundle and a newly-broken
    # one drops its stale (now-wrong) bundle. A modular agent's bundle is owned
    # by recompile_project; leave it untouched here so editing agent_yaml while
    # the project's modules are mid-change never blanks a live bundle (R-POL-002).
    if sign is not None:
        from hexgate_api.features.policy_modules import service as modules

        if not await modules.is_modular(session, project_id):
            bundle = await asyncio.to_thread(compile_bundle, agent.policy_yaml, sign)
            _apply_bundle(agent, bundle)

    agent.updated_at = datetime.now(timezone.utc)
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent


async def backfill_bundles(
    session: AsyncSession, sign: Callable[[bytes], bytes]
) -> int:
    """Compile + sign a bundle for every agent that doesn't already have one.

    Seeded agents are inserted directly (``ensure_default_project`` builds
    ``Agent(...)`` without the save-time compile hook), so on a fresh DB
    they start bundle-less and would be served via the pydantic fallback.
    Running this at startup means even a brand-new platform serves signed
    WASM bundles for the seeds on the very first request.

    Idempotent: agents that already carry a bundle are skipped, and a
    policy that won't compile (or a platform without opa) is simply left
    bundle-less. Returns the number of agents backfilled.
    """
    from collections import defaultdict

    from hexgate_api.features.policy_modules import service as modules

    agents = (await session.exec(select(Agent))).all()
    pending: dict[str, list[Agent]] = defaultdict(list)
    for agent in agents:
        if agent.compiled_wasm is None:
            pending[agent.project_id].append(agent)

    count = 0
    for project_id, project_agents in pending.items():
        compiled: dict[str, tuple[bytes, str, bytes] | None] = {}
        if await modules.is_modular(session, project_id):
            # Resolve all agents' columns in one store read; if the project
            # doesn't resolve, leave every agent bundle-less (consistent — same
            # as recompile). Backfill stays best-effort only on the opa COMPILE:
            # unlike recompile it fills the agents that compile and skips the rest,
            # because startup backfill is opportunistic (a skipped agent falls back
            # to pydantic on its own policy_yaml) and shouldn't fail the whole boot.
            yaml_by_agent = await _resolved_yaml_or_none(
                session, project_id, {a.name for a in project_agents}
            )
            if yaml_by_agent is None:
                continue
            for agent in project_agents:
                bundle = await _compile_memoized(
                    compiled, yaml_by_agent[agent.name], sign
                )
                if bundle is None:
                    continue
                _apply_bundle(agent, bundle)
                session.add(agent)
                count += 1
        else:
            for agent in project_agents:
                bundle = await _compile_memoized(compiled, agent.policy_yaml, sign)
                if bundle is None:
                    continue  # leave bundle-less (already None) — don't count
                _apply_bundle(agent, bundle)
                session.add(agent)
                count += 1
    if count:
        await session.commit()
    return count


def compute_manifest_hash(manifest: AgentManifest) -> str:
    """Reproducible SHA-256 of an agent manifest.

    Canonical JSON encoding (sorted keys, no whitespace) so the same manifest
    always hashes to the same hex digest regardless of Python dict ordering.

    ``exclude_none=True`` keeps hash continuity across schema growth: when a
    new ``Optional`` field lands with a ``None`` default, an old manifest
    re-registered against the new schema still produces the same digest it
    did before — so ``_find_version_by_hash`` matches and we don't create a
    duplicate ``AgentVersion`` row for what is functionally the same content.
    """
    payload = manifest.model_dump(mode="json", exclude_none=True)
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def register_manifest(
    session: AsyncSession,
    project_id: str,
    manifest: AgentManifest,
    *,
    sign: Callable[[bytes], bytes],
) -> tuple[AgentVersion, bool]:
    """Upsert an agent + version from an AgentManifest.

    Returns ``(version, created)`` where ``created`` is False if a version
    with the same content_hash already existed under this agent — in which
    case nothing is written and the existing row is returned.

    On FIRST registration of an agent (the ``Agent`` row is being created
    for the first time), this also:

      1. Generates a starter role-aware ``policy_yaml`` from the manifest's
         tool list (see :func:`_default_policy_for_manifest`). The dev sees
         this in the dashboard's policy editor and edits from there.
      2. Compiles + signs the bundle so ``hexgate serve`` runs against
         signed WASM from the very first request, not the pydantic
         fallback. Signing failures degrade gracefully (no bundle stored,
         SDK falls through to pydantic) — same shape as ``update_agent``.

    On subsequent registers of an existing agent, ``agent.policy_yaml`` is
    left alone — policy belongs to the operator, manifest updates are just
    snapshot churn.
    """
    content_hash = compute_manifest_hash(manifest)
    agent, agent_created = await _get_or_create_agent(
        session, project_id, manifest.name
    )

    if agent_created:
        # Brand-new agent — seed the policy + bundle so the dashboard's
        # Policies editor has something to render and ``hexgate serve``
        # has a signed bundle to ship.
        #
        # In a MODULAR project the agent enforces the shared modular bundle;
        # policy_yaml is only the pydantic fallback if that bundle can't be
        # built/served. Seed it deny-all (fail closed) rather than the
        # permissive tool-derived starter, so a transient modular-compile
        # failure can't hand the new agent more than the modules would allow.
        from hexgate_api.features.agents.compiler import DENY_ALL_POLICY_YAML
        from hexgate_api.features.policy_modules import service as modules

        if await modules.is_modular(session, project_id):
            agent.policy_yaml = DENY_ALL_POLICY_YAML
        else:
            agent.policy_yaml = _default_policy_for_manifest(manifest)
        _apply_bundle(agent, await bundle_for_agent(session, agent, sign))
        # Already in session via _get_or_create_agent; the mutation flushes
        # at commit time below alongside the AgentVersion + Tool rows.

    if not agent_created:
        existing = await _find_version_by_hash(session, agent.id, content_hash)
        if existing is not None:
            return existing, False

    next_version = 1 if agent_created else await _next_version_number(session, agent.id)
    version = await _create_agent_version(
        session, agent.id, manifest, content_hash, next_version
    )
    await _create_tools(session, version.id, manifest.tools)

    await session.commit()
    await session.refresh(version)
    return version, True


async def _get_or_create_agent(
    session: AsyncSession, project_id: str, name: str
) -> tuple[Agent, bool]:
    """Return the Agent for (project_id, name), creating it if missing.

    The agent_yaml / policy_yaml columns are legacy NOT-NULL fields from the
    YAML-edited dashboard flow; code-defined agents leave them empty since the
    actual content lives on each AgentVersion.
    """
    agent = await get_agent(session, project_id, name)
    if agent is not None:
        return agent, False
    agent = Agent(
        id=new_id(Agent),
        project_id=project_id,
        name=name,
        agent_yaml="",
        policy_yaml="",
        system_md="",
    )
    session.add(agent)
    await session.flush()
    return agent, True


async def _find_version_by_hash(
    session: AsyncSession, agent_id: str, content_hash: str
) -> AgentVersion | None:
    """Return the existing AgentVersion with this content_hash, if any."""
    stmt = select(AgentVersion).where(
        AgentVersion.agent_id == agent_id,
        AgentVersion.content_hash == content_hash,
    )
    return (await session.exec(stmt)).first()


async def _next_version_number(session: AsyncSession, agent_id: str) -> int:
    """Return the next sequential version number for an agent."""
    last = (
        await session.exec(
            select(AgentVersion)
            .where(AgentVersion.agent_id == agent_id)
            .order_by(AgentVersion.version.desc())  # type: ignore[attr-defined]
        )
    ).first()
    return (last.version + 1) if last is not None else 1


async def _create_agent_version(
    session: AsyncSession,
    agent_id: str,
    manifest: AgentManifest,
    content_hash: str,
    version: int,
) -> AgentVersion:
    """Create and persist a new AgentVersion row for `manifest`."""
    row = AgentVersion(
        id=new_id(AgentVersion),
        agent_id=agent_id,
        version=version,
        description=manifest.description,
        content_hash=content_hash,
        manifest=manifest.model_dump(mode="json"),
    )
    session.add(row)
    await session.flush()
    return row


async def _create_tools(
    session: AsyncSession,
    agent_version_id: str,
    tools: list[ToolDefinition],
) -> None:
    """Insert one Tool row per ToolDefinition under an agent version."""
    for tool in tools:
        session.add(
            Tool(
                id=new_id(Tool),
                agent_version_id=agent_version_id,
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema.model_dump(mode="json"),
            )
        )
