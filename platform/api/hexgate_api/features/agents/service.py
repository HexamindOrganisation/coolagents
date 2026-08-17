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


async def _modular_bundle(
    session: AsyncSession, project_id: str, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Resolve a modular project once and compile its single shared bundle.

    Returns ``None`` (never raises) when the project doesn't resolve or the
    resolved policy can't compile (e.g. ``opa`` absent), so callers can leave
    live bundles untouched — the fail-safe in docs/adr/R-POL-002. The SDK
    resolve exceptions are imported here, on the modular path only, so a classic
    save never touches the SDK.
    """
    from hexgate.security import LinkError, PolicySetError
    from hexgate.security.constraints import ConstraintParseError
    from hexgate_api.features.policy_modules import service as modules

    try:
        policy_yaml = await modules.resolved_policy_yaml(session, project_id)
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        logger.warning(
            "modular project %s does not resolve; no bundle: %s", project_id, exc
        )
        return None
    # opa is a synchronous subprocess — run it off the event loop so a policy
    # write doesn't block every other in-flight request for the compile.
    return await asyncio.to_thread(compile_bundle, policy_yaml, sign)


async def bundle_for_agent(
    session: AsyncSession, agent: Agent, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Compile the signed bundle for one agent, from the right source.

    Modular project (has a role binding): the project's resolved role-keyed
    policy. Classic project: the agent's own ``policy_yaml`` (unchanged
    behavior). See docs/adr/R-POL-002.
    """
    from hexgate_api.features.policy_modules import service as modules

    if await modules.is_modular(session, agent.project_id):
        return await _modular_bundle(session, agent.project_id, sign)
    return await asyncio.to_thread(compile_bundle, agent.policy_yaml, sign)


async def recompile_project(
    session: AsyncSession, project_id: str, sign: Callable[[bytes], bytes]
) -> int:
    """Recompile every agent in a project after its modules or roles change.

    Modular: resolve + compile once, reusing the single bundle for all agents.
    On an unresolvable project (or a resolved policy that won't compile) live
    bundles are left untouched — the fail-safe in docs/adr/R-POL-002, because the
    modules haven't changed what each agent should enforce, we just can't build
    it right now.

    Classic — including a project that just dropped its last role binding, so
    enforcement returns to each agent's ``policy_yaml`` — recompiles each agent
    from its own policy and **nulls the bundle when that policy no longer
    compiles**, matching ``update_agent`` and the ``Agent.compiled_wasm``
    invariant (a broken policy drops its stale bundle so the SDK falls back to
    pydantic rather than serving a now-wrong WASM). Returns the count touched.
    """
    from hexgate_api.features.policy_modules import service as modules

    agents = await list_agents(session, project_id)
    if not agents:
        return 0

    count = 0
    if await modules.is_modular(session, project_id):
        bundle = await _modular_bundle(session, project_id, sign)
        if bundle is None:
            return 0  # fail-safe: leave live bundles as-is
        for agent in agents:
            agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
            session.add(agent)
            count += 1
    else:
        for agent in agents:
            bundle = await asyncio.to_thread(compile_bundle, agent.policy_yaml, sign)
            if bundle is None:
                # A classic agent's own policy failed to compile: drop the stale
                # bundle (fall back to pydantic), never keep a wrong one.
                agent.compiled_wasm = None
                agent.bundle_manifest = None
                agent.bundle_signature = None
            else:
                agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = (
                    bundle
                )
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
            if bundle is not None:
                agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = (
                    bundle
                )
            else:
                agent.compiled_wasm = None
                agent.bundle_manifest = None
                agent.bundle_signature = None

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
        if await modules.is_modular(session, project_id):
            # Resolve + compile once for the whole project, not once per agent.
            bundle = await _modular_bundle(session, project_id, sign)
            if bundle is None:
                continue
            for agent in project_agents:
                agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = (
                    bundle
                )
                session.add(agent)
                count += 1
        else:
            for agent in project_agents:
                bundle = await asyncio.to_thread(
                    compile_bundle, agent.policy_yaml, sign
                )
                if bundle is None:
                    continue
                agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = (
                    bundle
                )
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
        agent.policy_yaml = _default_policy_for_manifest(manifest)
        bundle = await bundle_for_agent(session, agent, sign)
        if bundle is not None:
            agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
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
