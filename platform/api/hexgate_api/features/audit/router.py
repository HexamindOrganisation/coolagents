"""Audit endpoints: SDK decision ingest (bearer) + dashboard reads (cookie)."""

import asyncio
import logging
from datetime import datetime

from clickhouse_connect.driver.exceptions import (
    ClickHouseError,
    OperationalError,
    ProgrammingError,
)
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.features.audit.service import (
    AuditPayloadTooLarge,
    anomalies,
    insert_ban_enforcement,
    insert_decision,
    list_ban_enforcements,
    list_decisions,
    summarize,
    timeseries,
)
from hexgate_api.query_scope import (
    WINDOW_HOURS,
    EventOutOfWindow,
    prepare_date_range,
    validate_event_window,
)
from hexgate_api.core.db import get_session
from hexgate_api.deps.clickhouse import _audit_unavailable, require_clickhouse
from hexgate_api.deps.org import require_org_member
from hexgate_api.deps.project import require_project_admin
from hexgate_api.deps.tokens import require_project
from hexgate_api.schemas import (
    AuditAnomaly,
    AuditDecisionPage,
    AuditOutcome,
    AuditSummary,
    AuditTimeseriesPoint,
    AuditWindow,
    BanEnforcementAccepted,
    BanEnforcementEvent,
    BanEnforcementPage,
    DecisionAccepted,
    DecisionEvent,
)
from hexgate_api.features.agents.service import get_latest_agent_version_id

_log = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/audit/decisions",
    response_model=DecisionAccepted,
    status_code=202,
    tags=["audit"],
)
async def ingest_decision(
    body: DecisionEvent,
    project_id: str = Depends(require_project),
    session: AsyncSession = Depends(get_session),
    clickhouse_client=Depends(require_clickhouse),
) -> DecisionAccepted:
    """Ingest one policy decision. project_id (bearer), received_at (CH default),
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
        # run it off the event loop like the read handlers below.
        await asyncio.to_thread(
            insert_decision,
            clickhouse_client,
            event=body,
            project_id=project_id,
            agent_version_id=agent_version_id,
        )
    except AuditPayloadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except OperationalError as exc:  # transient transport failure — retryable
        _log.warning("audit insert failed (transient): %s", exc)
        raise _audit_unavailable()
    except ProgrammingError as exc:
        # The driver resolves our column names against the table before it
        # sends anything, so a schema behind this build fails here and no row
        # ever reaches storage. 503, not 422: nothing is wrong with the
        # *event*, and a 422 tells the SDK to discard a record that would
        # land fine once the migration is applied. Startup already refuses to
        # boot on this (service.verify_schema) — reaching it means ClickHouse
        # was unreachable at boot, or the table changed under a live process.
        _log.error("audit insert impossible against current schema: %s", exc)
        raise _audit_unavailable()
    except ClickHouseError as exc:  # storage rejected the row — retry won't help
        _log.error("audit insert rejected by ClickHouse: %s", exc)
        raise HTTPException(status_code=422, detail="audit event rejected by storage")

    return DecisionAccepted(event_id=body.event_id)


@router.post(
    "/audit/ban-enforcements",
    response_model=BanEnforcementAccepted,
    status_code=202,
    tags=["audit"],
)
async def ingest_ban_enforcement(
    body: BanEnforcementEvent,
    project_id: str = Depends(require_project),
    session: AsyncSession = Depends(get_session),
    clickhouse_client=Depends(require_clickhouse),
) -> BanEnforcementAccepted:
    """Ingest one ban enforcement (bearer). project_id / received_at /
    agent_version_id are server-resolved; idempotent on event_id."""
    try:
        validate_event_window(body.occurred_at)
    except EventOutOfWindow as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    agent_version_id = await get_latest_agent_version_id(
        session, project_id, body.agent_name
    )

    try:
        await asyncio.to_thread(
            insert_ban_enforcement,
            clickhouse_client,
            event=body,
            project_id=project_id,
            agent_version_id=agent_version_id,
        )
    except OperationalError as exc:  # transient transport failure — retryable
        _log.warning("ban-enforcement insert failed (transient): %s", exc)
        raise _audit_unavailable()
    except ProgrammingError as exc:  # server can't accept this shape at all
        _log.error("ban-enforcement insert impossible against current schema: %s", exc)
        raise _audit_unavailable()
    except ClickHouseError as exc:  # storage rejected the row — retry won't help
        _log.error("ban-enforcement insert rejected by ClickHouse: %s", exc)
        raise HTTPException(
            status_code=422, detail="ban enforcement rejected by storage"
        )

    return BanEnforcementAccepted(event_id=body.event_id)


# Dashboard audit reads — project-scoped aggregation, cookie-authed like the
# other dashboard reads (org membership via the project path param).
#
# ``role`` filter semantics: absent = no filter; ``role=`` (empty value) =
# the no-role bucket. No sentinel string is reserved on the wire — the
# dashboard renders "(none)" purely as a display label.
#
# The filter matches **membership** in the caller's role set, so one call by
# ["billing", "support"] is returned by role=billing and role=support alike.
# That strictly subsumes the pre-multi-role ``role = X`` equality, so no
# caller-visible query changes meaning.


@router.get(
    "/projects/{project_id}/audit/summary",
    response_model=AuditSummary,
    dependencies=[Depends(require_org_member)],
    tags=["audit"],
)
async def api_audit_summary(
    project_id: str,
    window: AuditWindow = "24h",
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> AuditSummary:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        # The clickhouse_connect client is sync — run it off the event loop
        # so a slow aggregation can't stall every other in-flight request.
        data = await asyncio.to_thread(
            summarize,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            agent=agent,
            role=role,
            tool=tool,
            user=user,
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()
    return AuditSummary.model_validate(data)


@router.get(
    "/projects/{project_id}/audit/timeseries",
    response_model=list[AuditTimeseriesPoint],
    dependencies=[Depends(require_org_member)],
    tags=["audit"],
)
async def api_audit_timeseries(
    project_id: str,
    window: AuditWindow = "24h",
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> list[AuditTimeseriesPoint]:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        return await asyncio.to_thread(
            timeseries,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            agent=agent,
            role=role,
            tool=tool,
            user=user,
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()


@router.get(
    "/projects/{project_id}/audit/decisions",
    response_model=AuditDecisionPage,
    dependencies=[Depends(require_org_member)],
    tags=["audit"],
)
async def api_audit_decisions(
    project_id: str,
    window: AuditWindow = "24h",
    agent: str | None = None,
    role: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    outcome: AuditOutcome | None = None,
    session_id: str | None = None,
    limit: int = 25,
    offset: int = 0,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> AuditDecisionPage:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        page = await asyncio.to_thread(
            list_decisions,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            agent=agent,
            role=role,
            tool=tool,
            user=user,
            outcome=outcome,
            session_id=session_id,
            limit=max(1, min(limit, 200)),
            offset=max(0, offset),
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()
    return page


# Ban enforcements read on their own admin-gated endpoint (like ban CRUD),
# kept out of the tool-decision reads above so those views stay pure — a ban
# is refused before any tool call and never lands in policy_decision.
@router.get(
    "/projects/{project_id}/audit/ban-enforcements",
    response_model=BanEnforcementPage,
    dependencies=[Depends(require_project_admin)],
    tags=["audit"],
)
async def api_audit_ban_enforcements(
    project_id: str,
    window: AuditWindow = "24h",
    limit: int = 25,
    offset: int = 0,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> BanEnforcementPage:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        page = await asyncio.to_thread(
            list_ban_enforcements,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            limit=max(1, min(limit, 200)),
            offset=max(0, offset),
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()
    return page


@router.get(
    "/projects/{project_id}/audit/anomalies",
    response_model=list[AuditAnomaly],
    dependencies=[Depends(require_org_member)],
    tags=["audit"],
)
async def api_audit_anomalies(
    project_id: str,
    window: AuditWindow = "24h",
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    clickhouse_client=Depends(require_clickhouse),
) -> list[AuditAnomaly]:
    start_date, end_date = prepare_date_range(start_date, end_date)
    try:
        return await asyncio.to_thread(
            anomalies,
            clickhouse_client,
            project_id=project_id,
            since_hours=WINDOW_HOURS[window],
            start_date=start_date,
            end_date=end_date,
        )
    except ClickHouseError:
        raise _audit_unavailable()
