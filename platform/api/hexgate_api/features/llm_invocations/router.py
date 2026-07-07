"""LLM invocation endpoints: SDK usage ingest (bearer)."""

import asyncio
import logging

from clickhouse_connect.driver.exceptions import ClickHouseError, OperationalError
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.features.audit.service import (
    AuditEventOutOfWindow,
    validate_event_window,
)
from hexgate_api.features.llm_invocations.service import insert_llm_invocation
from hexgate_api.core.db import get_session
from hexgate_api.deps.clickhouse import _audit_unavailable, require_clickhouse
from hexgate_api.deps.tokens import require_project
from hexgate_api.schemas import LlmInvocationAccepted, LlmInvocationEvent
from hexgate_api.features.agents.service import get_latest_agent_version_id

_log = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/audit/llm-invocations",
    response_model=LlmInvocationAccepted,
    status_code=202,
    tags=["llm_invocations"],
)
async def ingest_llm_invocation(
    body: LlmInvocationEvent,
    project_id: str = Depends(require_project),
    session: AsyncSession = Depends(get_session),
    clickhouse_client=Depends(require_clickhouse),
) -> LlmInvocationAccepted:
    """Ingest one LLM invocation. project_id (bearer), received_at (CH default),
    and agent_version_id (platform lookup) are server-resolved.

    Idempotency: the SDK SHOULD retry a failed or ambiguous send (503,
    timeout) with the SAME event_id. The ingest path is idempotent because
    the storage engine (ReplacingMergeTree, event_id in the sort key)
    collapses duplicates on background merges — eventual, so counts may
    briefly include a retry until the next merge. Do NOT mint a fresh
    event_id per attempt; that turns a retry into a real duplicate.
    """
    try:
        validate_event_window(body.occurred_at)
    except AuditEventOutOfWindow as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    agent_version_id = await get_latest_agent_version_id(
        session, project_id, body.agent_name
    )

    try:
        # Sync client + wait_for_async_insert=1 → a real network round-trip;
        # run it off the event loop like the audit read handlers.
        await asyncio.to_thread(
            insert_llm_invocation,
            clickhouse_client,
            event=body,
            project_id=project_id,
            agent_version_id=agent_version_id,
        )
    except OperationalError as exc:  # transient transport failure — retryable
        _log.warning("llm invocation insert failed (transient): %s", exc)
        raise _audit_unavailable()
    except ClickHouseError as exc:  # storage rejected the row — retry won't help
        _log.error("llm invocation insert rejected by ClickHouse: %s", exc)
        raise HTTPException(
            status_code=422, detail="llm invocation rejected by storage"
        )

    return LlmInvocationAccepted(event_id=body.event_id)
