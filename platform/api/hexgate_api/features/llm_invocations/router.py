"""LLM invocation endpoints: SDK usage ingest (bearer)."""

import asyncio
import logging
from datetime import datetime

from clickhouse_connect.driver.exceptions import ClickHouseError, OperationalError
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.query_scope import (
    WINDOW_HOURS,
    EventOutOfWindow,
    prepare_date_range,
    validate_event_window,
)
from hexgate_api.features.llm_invocations.service import (
    insert_llm_invocation,
    summarize_llm_invocations,
)
from hexgate_api.core.db import get_session
from hexgate_api.deps.clickhouse import _audit_unavailable, require_clickhouse
from hexgate_api.deps.org import require_org_member
from hexgate_api.deps.tokens import require_project
from hexgate_api.schemas import (
    AuditWindow,
    LlmInvocationAccepted,
    LlmInvocationEvent,
    LlmInvocationSummary,
)
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
    except EventOutOfWindow as exc:
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


# Dashboard read — project-scoped aggregation, cookie-authed like the
# audit summary endpoint (require_org_member via the project path param).
@router.get(
    "/projects/{project_id}/llm/summary",
    response_model=LlmInvocationSummary,
    dependencies=[Depends(require_org_member)],
    tags=["llm_invocations"],
)
async def api_llm_invocation_summary(
    project_id: str,
    window: AuditWindow = "24h",
    agent: str | None = None,
    user: str | None = None,
    model: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> LlmInvocationSummary:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        # The clickhouse_connect client is sync — run it off the event loop
        # so a slow aggregation can't stall every other in-flight request.
        data = await asyncio.to_thread(
            summarize_llm_invocations,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            agent=agent,
            user=user,
            model=model,
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()
    return LlmInvocationSummary.model_validate(data)
