"""Batch agent_version_id resolution against the relational store.

The only Postgres-backed step in the job — auth is fully handled at the
Collector. Two queries per poll regardless of batch size: the agents for
every unique (project, agent) pair, then their latest versions in one go.
Unresolved pairs map to "" and are inserted as-is, matching the HTTP
ingest's tolerance (an unregistered agent name must not lose the record).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import and_, or_
from sqlmodel import select

from hexgate_api.core.db import async_session_factory
from hexgate_api.features.agents.service import get_latest_agent_versions_map
from hexgate_api.models import Agent


async def resolve_versions(
    pairs: set[tuple[str, str]],
    session_factory: Callable[[], Any] = async_session_factory,
) -> dict[tuple[str, str], str]:
    """Map each ``(project_id, agent_name)`` to its latest AgentVersion.id."""
    if not pairs:
        return {}
    resolved = {pair: "" for pair in pairs}
    async with session_factory() as session:
        agents_stmt = select(Agent).where(
            or_(
                *(
                    and_(Agent.project_id == project_id, Agent.name == agent_name)
                    for project_id, agent_name in sorted(pairs)
                )
            )
        )
        agents = (await session.exec(agents_stmt)).all()
        pair_by_agent_id = {
            agent.id: (agent.project_id, agent.name) for agent in agents
        }
        latest = await get_latest_agent_versions_map(session, list(pair_by_agent_id))
        for agent_id, version in latest.items():
            resolved[pair_by_agent_id[agent_id]] = version.id
    return resolved
