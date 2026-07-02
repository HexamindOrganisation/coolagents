"""Agent + version persistence, policy-bundle compilation, manifest registration.

Groups the agent read/write helpers, the save-time WASM bundle compile+sign
(``compile_bundle`` shells out to the SDK/opa), and the ``hexgate register``
upsert path (manifest → Agent + AgentVersion + Tool rows, with a generated
starter policy on first registration).
"""

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
from hexgate_api.seeds import SEED_AGENTS

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


def compile_bundle(
    policy_yaml: str, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Compile ``policy_yaml`` to a signed WASM bundle.

    Runs the SDK's YAML → Rego → WASM compiler, builds a manifest with the
    content hashes, and signs the manifest's exact bytes with ``sign`` (the
    platform's root key). Returns ``(wasm_bytes, manifest_text, signature)``,
    or ``None`` when compilation can't happen — ``opa`` not installed, or the
    policy is malformed. A ``None`` return is not an error: the caller stores
    no bundle and the SDK falls back to the pydantic engine.

    Stays sync because it doesn't touch the DB — only shells out to ``opa``
    via the SDK. Callers run it inside an async handler via the default
    threadpool (``asyncio.to_thread``) if they need to keep the event loop
    responsive during a long compile; for our tiny policies a direct call
    is fine.
    """
    # Imported lazily so the platform still boots if the SDK / opa aren't
    # present — only save-time compilation needs them. build_signed_bundle
    # is the SAME helper `hexgate policy build` uses, so the manifest format
    # and its byte-exact serialization can't drift between the two.
    from hexgate.security import build_signed_bundle
    from hexgate.security.rego_wasm import OpaNotFoundError

    try:
        bundle = build_signed_bundle(policy_yaml, sign=sign)
    except OpaNotFoundError:
        logger.warning(
            "compile_bundle: opa not on PATH — storing no bundle "
            "(SDK will fall back to pydantic). Install opa to ship signed bundles."
        )
        return None
    except Exception as exc:
        # Any other compile failure (bad constraint, schema error, opa build
        # error) degrades gracefully — the save still succeeds without a bundle.
        logger.warning("compile_bundle: policy did not compile: %s", exc)
        return None

    return bundle.wasm_bytes, bundle.manifest_bytes.decode("utf-8"), bundle.signature


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

    # Recompile + re-sign the bundle from the (possibly updated) policy. We
    # always rebuild rather than diff so a fixed policy re-acquires a bundle
    # and a newly-broken one drops its stale (now-wrong) bundle.
    if sign is not None:
        bundle = compile_bundle(agent.policy_yaml, sign)
        if bundle is not None:
            agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
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
    count = 0
    agents = (await session.exec(select(Agent))).all()
    for agent in agents:
        if agent.compiled_wasm is not None:
            continue
        bundle = compile_bundle(agent.policy_yaml, sign)
        if bundle is None:
            continue
        agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
        session.add(agent)
        count += 1
    if count:
        await session.commit()
    return count


# --- Agent manifest registration --------------------------------------------


# Tool-name heuristics used by ``_classify_tool`` to bucket a tool into one of
# four categories. Matched against the LOWERCASED tool name with a substring
# search — so ``Read_File`` and ``read_file`` both land in "read". The
# patterns are deliberately broad: misclassification on a brand-new agent is
# a one-time editing chore, while missing a write-shape tool would silently
# hand a freshly-registered agent more power than the operator intended.
_SHELL_PATTERNS = (
    "bash",
    "shell",
    "exec",
    "run_command",
    "subprocess",
    "spawn",
)
_WRITE_PATTERNS = (
    "write_",
    "_write",
    "edit_",
    "create_",
    "update_",
    "delete_",
    "remove_",
    "patch_",
    "post_",
    "put_",
)
_READ_PATTERNS = (
    "read_",
    "_read",
    "search",
    "fetch",
    "list_",
    "get_",
    "find_",
    "grep",
    "glob",
    "view_",
    "describe_",
    "inspect_",
)


def _classify_tool(name: str) -> str:
    """Return one of ``"read" | "write" | "shell" | "unknown"`` for a tool name.

    Order matters: shell wins over write (a tool literally named
    ``run_command`` matches both ``run_command`` and ``_command``), and read
    is checked last so write-prefix takes precedence over a misleading
    ``read_`` substring elsewhere in the name.

    ``"unknown"`` is the fail-closed bucket — callers should treat it as
    write-shape so a brand-new agent doesn't silently inherit power the
    operator didn't authorize.
    """
    lower = name.lower()
    if any(p in lower for p in _SHELL_PATTERNS):
        return "shell"
    if any(p in lower for p in _WRITE_PATTERNS):
        return "write"
    if any(p in lower for p in _READ_PATTERNS):
        return "read"
    return "unknown"


def _emit_tool_lines(names: list[str], mode: str, indent: int = 6) -> str:
    """Render ``{name: { mode: ... }}`` lines for a YAML policy block.

    Returns an empty string when ``names`` is empty — the caller can drop
    the surrounding ``tools:`` key entirely if all its buckets are empty,
    keeping the generated YAML clean (no dangling ``tools:`` with no
    children, which the AgentPolicy validator rejects).
    """
    pad = " " * indent
    return "".join(f"{pad}{n}: {{ mode: {mode} }}\n" for n in names)


def _default_policy_for_manifest(manifest: AgentManifest) -> str:
    """Build a starter role-aware ``policy_yaml`` from a manifest's tools.

    Modeled on the ``support_bot`` seed at :mod:`platform.api.seeds`:

      - ``read_only`` (mixin) — every read-shape tool from the manifest.
      - ``default`` — inherits ``read_only``, used when no User scope is set.
      - ``member`` — inherits ``read_only``; writes + shells + unknowns
        require approval.
      - ``admin`` — inherits ``read_only``; writes pass through, shells
        still require approval.

    Unknown tools (those that didn't match any heuristic) land in the
    write bucket — fail-closed, surfaced to the operator via a comment so
    they can reclassify in the dashboard editor.

    Only called for brand-new agents (first POST /v1/agents for a given
    name); re-registers of an existing agent leave the operator's edited
    policy alone.
    """
    reads: list[str] = []
    writes: list[str] = []
    shells: list[str] = []
    unknowns: list[str] = []
    for tool in manifest.tools:
        bucket = _classify_tool(tool.name)
        if bucket == "read":
            reads.append(tool.name)
        elif bucket == "shell":
            shells.append(tool.name)
        elif bucket == "write":
            writes.append(tool.name)
        else:
            unknowns.append(tool.name)

    # Heads-up comment for unknown-bucket tools — the operator sees them
    # in the dashboard editor and can move them to a more appropriate
    # bucket. Empty when every tool classified cleanly.
    unknown_note = (
        "# Heuristic could not classify these tools — treating as writes\n"
        "# (fail-closed). Move them to read_only or shells as appropriate:\n"
        + "".join(f"#   - {n}\n" for n in unknowns)
        + "\n"
        if unknowns
        else ""
    )

    # ``read_only`` body — drop the ``tools:`` key when the manifest has
    # zero read-shape tools to avoid emitting ``tools:`` with no children
    # (rejected by the policy parser).
    read_only_tools = f"    tools:\n{_emit_tool_lines(reads, 'allow')}" if reads else ""

    # member + admin override blocks. ``writes + unknowns`` always get the
    # role-appropriate mode; shells are pinned to approval_required across
    # both roles because shells are the highest-blast-radius primitive
    # and shouldn't differ between operator personas.
    member_overrides = writes + unknowns + shells
    member_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'approval_required')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if member_overrides
        else ""
    )
    admin_overrides = writes + unknowns + shells
    admin_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'allow')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if admin_overrides
        else ""
    )

    return f"""version: 1
# Generated by `hexgate register`. Edit freely — re-running register
# never overwrites this; it only updates the manifest snapshot.
#
# Four entries:
#   read_only  (mixin)  factored-out 'safe to read' allowlist
#   default             fallback when no User scope is set
#   member              typical user; writes + shells require approval
#   admin               power user; writes allow, shells still gate
#
# Note: 'admin' here is an AGENT policy role (used by the SDK at request
# time via User(role="admin")), distinct from the ORG admin role on
# /orgs/:id/members.

{unknown_note}roles:
  read_only:
    is_mixin: true
    default_policy:
      mode: deny
{read_only_tools}
  default:
    inherits: [read_only]

  member:
    inherits: [read_only]
{member_tools}
  admin:
    inherits: [read_only]
{admin_tools}"""


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
        bundle = compile_bundle(agent.policy_yaml, sign)
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
