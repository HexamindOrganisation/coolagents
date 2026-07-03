"""Serve the built React dashboard (``dist/``) from the FastAPI app, same-origin.

The production image bakes the dashboard build into itself (see
``platform/api/Dockerfile``) and points ``HEXGATE_DASHBOARD_DIST`` at it, so the
API answers both ``/v1/*`` and the SPA on one origin — no separate edge
container, no CORS, no cross-origin cookie config. The same helper backs the
single-tenant demo bundle (:mod:`demo`).

:func:`mount_spa` MUST be called *after* ``app.include_router(v1)`` so the
``/v1`` API + WebSocket routes match before the catch-all SPA fallback —
Starlette matches in registration order, so registering this last is what keeps
``/v1/*`` from being shadowed by ``index.html``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from hexgate_api import API_ROOT

_log = logging.getLogger(__name__)

# Request paths under the API namespace must never fall through to the SPA.
# An unknown path here (a typo'd or removed /v1 route, a version mismatch) has
# to return FastAPI's default 404 JSON — NOT index.html with HTTP 200 — or an
# SDK/client that branches on the status code or JSON-parses the body silently
# treats a not-found endpoint as success and then chokes on HTML-as-JSON.
# These match the first path segment, so e.g. ``v1/agentz`` and ``health/x``
# are excluded while real SPA routes like ``playground`` fall through.
_API_PATH_HEADS = frozenset({"v1", "health", "ready", "docs", "redoc", "openapi.json"})


def _is_api_path(full_path: str) -> bool:
    """True for catch-all paths that belong to the API, not the SPA."""
    return full_path.split("/", 1)[0] in _API_PATH_HEADS


def _not_found() -> JSONResponse:
    """FastAPI's default 404 body, so API clients see a real not-found."""
    return JSONResponse({"detail": "Not Found"}, status_code=404)


# The dev-checkout layout after ``pnpm build``. A deployment image sets
# HEXGATE_DASHBOARD_DIST=/app/static instead — this path does NOT exist there.
# API_ROOT.parent is platform/; the dashboard build lands in platform/dashboard/dist.
_DEV_DASHBOARD_DIST = API_ROOT.parent / "dashboard" / "dist"


def dashboard_dist() -> Path:
    """Resolve the built dashboard directory.

    Defaults to ``platform/dashboard/dist`` relative to this file (the layout
    after ``pnpm build`` in a dev checkout); the production image overrides it
    with ``HEXGATE_DASHBOARD_DIST`` since the build is copied to ``/app/static``.

    A *set-but-empty* override (cleared, whitespace, or overridden to "") is
    treated as a misconfiguration, not as "unset": we still fall back to the
    dev path so the app boots, but we WARN, because in a deployment image that
    dev path is absent and the whole SPA would 404 silently otherwise.
    """
    raw = os.environ.get("HEXGATE_DASHBOARD_DIST")
    if raw is not None:
        override = raw.strip()
        if override:
            return Path(override)
        _log.warning(
            "HEXGATE_DASHBOARD_DIST is set but empty/whitespace — ignoring it and "
            "falling back to the dev path %s, which does NOT exist in a deployment "
            "image. Unset the var for dev, or point it at the dashboard build.",
            _DEV_DASHBOARD_DIST,
        )
    return _DEV_DASHBOARD_DIST


def mount_spa(app: FastAPI) -> None:
    """Attach static SPA serving (assets mount + catch-all → index.html) to ``app``.

    Idempotent in intent but registers routes, so call exactly once, last.
    """
    dist = dashboard_dist()
    if not (dist / "index.html").is_file():
        # Build missing — don't crash the API; /v1 still works, the SPA 404s
        # with a clear hint instead of an opaque mount error at import time.
        # But shout it at startup: otherwise the container stays "healthy",
        # /v1 keeps answering, and the broken (blank) UI ships silently — only
        # discovered by an end user hitting a 404 page. This is the loud signal
        # ops needs to catch a bad image COPY or wrong HEXGATE_DASHBOARD_DIST.
        _log.warning(
            "⚠ dashboard build NOT FOUND at %s — the SPA will return 404 on "
            "every route while /v1 keeps working. In production this is a blank "
            "UI: check the image COPY into /app/static and HEXGATE_DASHBOARD_DIST.",
            dist,
        )

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _no_build(full_path: str) -> Response:
            # API paths still 404 as JSON, never the build hint.
            if _is_api_path(full_path):
                return _not_found()
            return Response(
                f"dashboard build not found at {dist} — run `pnpm build` in "
                "platform/dashboard or set HEXGATE_DASHBOARD_DIST",
                status_code=404,
                media_type="text/plain",
            )

        return

    _log.info("dashboard SPA mounted from %s", dist)

    # Hashed assets get a real static mount (correct content-type + caching);
    # everything else falls through to the SPA catch-all → index.html, so
    # client-side routes like /playground resolve on a hard refresh.
    assets = dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    dist_resolved = dist.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> Response:
        # Never let an unknown /v1/* (or other API path) resolve to index.html
        # with a 200 — return the API's default 404 JSON instead.
        if _is_api_path(full_path):
            return _not_found()
        candidate = (dist / full_path).resolve()
        # Resolve first, then containment-check, so `../` traversal can't escape dist.
        if (
            full_path
            and candidate.is_file()
            and candidate.is_relative_to(dist_resolved)
        ):
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
