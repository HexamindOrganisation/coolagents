"""Liveness/readiness probes, exposed both unprefixed and under ``/v1``."""

from fastapi import APIRouter, Response

from hexgate_api.core.clickhouse import ping as clickhouse_ping

router = APIRouter()
v1_router = APIRouter()


def _readiness() -> tuple[dict[str, str], int]:
    """Build the readiness body and its HTTP status. Returns 503 when ClickHouse
    is unreachable so probes deroute the pod instead of sending it ingest traffic
    that would only 503 — k8s keys off the status code, not the body."""
    reachable = clickhouse_ping()
    body = {
        "status": "ok" if reachable else "unavailable",
        "service": "hexgate-api",
        "clickhouse": "ok" if reachable else "unreachable",
    }
    return body, 200 if reachable else 503


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness — must not touch downstream deps, or an outage cascades into
    restarts. Dependency checks live in /ready."""
    return {"status": "ok", "service": "hexgate-api"}


@router.get("/ready")
def ready(response: Response) -> dict[str, str]:
    """Readiness — pings ClickHouse; 503 when unreachable."""
    body, response.status_code = _readiness()
    return body


@v1_router.get("/health")
async def v1_health() -> dict[str, str]:
    return {"status": "ok", "service": "hexgate-api", "version": "v1"}


@v1_router.get("/ready")
def v1_ready(response: Response) -> dict[str, str]:
    body, response.status_code = _readiness()
    return {**body, "version": "v1"}
