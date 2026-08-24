"""Batch agent_version_id resolution against the relational store.

The only Postgres-backed step in the job — auth is fully handled at the
Collector. One session per poll, one lookup per unique (project, agent)
pair; unresolved pairs map to "" and are inserted as-is, matching the HTTP
ingest's tolerance (an unregistered agent name must not lose the record).
"""

from __future__ import annotations

from hexgate_api.core.db import async_session_factory
from hexgate_api.features.agents.service import get_latest_agent_version_id


async def resolve_versions(
    pairs: set[tuple[str, str]],
) -> dict[tuple[str, str], str]:
    """Map each ``(project_id, agent_name)`` to its latest AgentVersion.id."""
    if not pairs:
        return {}
    resolved: dict[tuple[str, str], str] = {}
    async with async_session_factory() as session:
        for project_id, agent_name in sorted(pairs):
            resolved[(project_id, agent_name)] = await get_latest_agent_version_id(
                session, project_id, agent_name
            )
    return resolved
