"""SPA catch-all mounting (``spa.mount_spa``).

Locks in the behaviour the dashboard-in-API refactor must preserve now that
the SPA is mounted in production (not just demo):

1. An unknown API path (``/v1/*``, ``/health`` …) returns FastAPI's default
   404 JSON, never index.html with HTTP 200 — otherwise an SDK client that
   branches on the status code or JSON-parses the body mis-handles a typo'd
   or removed endpoint as success and then chokes on HTML-as-JSON.
2. A real client-side route falls through to index.html, so a hard refresh
   on /playground resolves.

Both the built-dashboard path and the missing-build path are covered. The app
is assembled locally (a ``/v1`` route + ``mount_spa``) so the catch-all logic
is exercised without the global app's DB-touching lifespan.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hexgate_api.core import spa


def _app_with_v1() -> FastAPI:
    app = FastAPI()

    @app.get("/v1/ping")
    async def ping() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def _with_build(tmp_path, monkeypatch) -> FastAPI:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>app</title>")
    monkeypatch.setenv("HEXGATE_DASHBOARD_DIST", str(dist))
    app = _app_with_v1()
    spa.mount_spa(app)
    return app


def test_registered_v1_route_unaffected(tmp_path, monkeypatch) -> None:
    client = TestClient(_with_build(tmp_path, monkeypatch))
    assert client.get("/v1/ping").json() == {"ok": "yes"}


def test_unknown_v1_path_returns_json_404_not_spa(tmp_path, monkeypatch) -> None:
    client = TestClient(_with_build(tmp_path, monkeypatch))
    resp = client.get("/v1/agentz")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}
    assert "text/html" not in resp.headers["content-type"]


def test_frontend_route_falls_through_to_index_html(tmp_path, monkeypatch) -> None:
    client = TestClient(_with_build(tmp_path, monkeypatch))
    resp = client.get("/playground")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_missing_build_api_path_still_json_404(tmp_path, monkeypatch) -> None:
    # Empty dir → no index.html → the _no_build resilience handler.
    monkeypatch.setenv("HEXGATE_DASHBOARD_DIST", str(tmp_path / "nope"))
    app = _app_with_v1()
    spa.mount_spa(app)
    client = TestClient(app)

    # Frontend route → plaintext build-missing hint (API stays up).
    resp = client.get("/playground")
    assert resp.status_code == 404
    assert "text/plain" in resp.headers["content-type"]

    # API path → JSON 404, never the build hint.
    resp = client.get("/v1/agentz")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "Not Found"}


def test_is_api_path_unit() -> None:
    assert spa._is_api_path("v1/agents")
    assert spa._is_api_path("health")
    assert spa._is_api_path("openapi.json")
    assert not spa._is_api_path("playground")
    assert not spa._is_api_path("")


def test_dashboard_dist_uses_override(monkeypatch) -> None:
    monkeypatch.setenv("HEXGATE_DASHBOARD_DIST", "/app/static")
    assert spa.dashboard_dist() == Path("/app/static")


def test_dashboard_dist_unset_falls_back_to_dev_path(monkeypatch) -> None:
    monkeypatch.delenv("HEXGATE_DASHBOARD_DIST", raising=False)
    assert spa.dashboard_dist() == spa._DEV_DASHBOARD_DIST


def test_dashboard_dist_empty_override_warns_and_falls_back(
    monkeypatch, caplog
) -> None:
    # Set-but-empty is a misconfiguration: still boots on the dev path, but
    # must WARN so a deploy image (where that path is absent) isn't silent.
    monkeypatch.setenv("HEXGATE_DASHBOARD_DIST", "   ")
    with caplog.at_level("WARNING"):
        assert spa.dashboard_dist() == spa._DEV_DASHBOARD_DIST
    assert any(
        "HEXGATE_DASHBOARD_DIST is set but empty" in r.message for r in caplog.records
    )
