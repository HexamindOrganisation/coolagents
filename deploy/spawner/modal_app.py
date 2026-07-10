"""Hexgate demo spawner — a tiny Modal web service that launches a Daytona
sandbox per visitor and redirects them into it.

    Docs "Launch demo" button
        → GET /launch  → daytona.create(snapshot) → start boot.py → "starting…" page
        → GET /status  → is marimo up yet? → page redirects to the signed notebook URL
        → Daytona sandbox runs the demo (~6¢/session, auto-stops after idle)

Why Modal: the spawner is pure request/response HTTP (no WebSocket), so none of
the marimo-WS problems that sank the *demo* on Modal apply here. It scales to
zero → near-free.

Deploy (from asianf/, no PR merge needed):
    modal secret create daytona DAYTONA_API_KEY=dtn_...
    modal deploy deploy/spawner/modal_app.py
    → prints a stable URL; the docs button points at <url>/launch

daytona / fastapi are only in the container image, so all of their imports are
LAZY (inside the function) — module load must work on a laptop without them for
`modal deploy` to register the app.
"""

import modal

image = modal.Image.debian_slim().pip_install("daytona", "fastapi")
app = modal.App("hexgate-spawner")

SNAPSHOT = "hexgate-demo"
MARIMO_PORT = 3000
API_PORT = 8000
VENV = "/app/platform/api/.venv/bin"
MAX_LIVE_SANDBOXES = 20          # global cost cap
PER_IP_COOLDOWN_SECONDS = 20     # crude per-IP rate limit


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("daytona")],  # provides DAYTONA_API_KEY
    scaledown_window=300,
)
@modal.asgi_app()
def web():
    import os
    import time

    from daytona import (
        CreateSandboxFromSnapshotParams,
        Daytona,
        DaytonaConfig,
        SessionExecuteRequest,
    )
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

    web_app = FastAPI()
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
    _last_launch: dict[str, float] = {}  # ip -> ts (per-container, MVP)

    def _running_count() -> int:
        """Best-effort count of live sandboxes for the cost cap. Never blocks a
        launch on a list() failure — the auto-stop is the real backstop."""
        try:
            return len(daytona.list())
        except Exception:
            return 0

    def _signed(sandbox, port: int) -> str:
        return sandbox.create_signed_preview_url(port, expires_in_seconds=3600).url

    def _page(title: str, body: str, redirect_js: str = "") -> str:
        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>{title}</title><style>
body{{font-family:system-ui;background:#0b0b0f;color:#e5e7eb;display:grid;
place-items:center;height:100vh;margin:0;text-align:center}}
.card{{max-width:32rem;padding:2rem}}
.spin{{width:2.5rem;height:2.5rem;border:3px solid #333;border-top-color:#3b82f6;
border-radius:50%;animation:s 1s linear infinite;margin:1.5rem auto}}
@keyframes s{{to{{transform:rotate(360deg)}}}}a{{color:#60a5fa}}</style></head>
<body><div class=card>{body}</div>{redirect_js}</body></html>"""

    @web_app.get("/launch")
    def launch(request: Request):
        ip = (request.headers.get("x-forwarded-for", "") or
              (request.client.host if request.client else "")).split(",")[0].strip()

        now = time.time()
        if ip and now - _last_launch.get(ip, 0) < PER_IP_COOLDOWN_SECONDS:
            return HTMLResponse(_page(
                "Slow down",
                "<h2>One launch at a time 🙂</h2><p>Please wait a few seconds and retry.</p>",
            ), status_code=429)

        if _running_count() >= MAX_LIVE_SANDBOXES:
            return HTMLResponse(_page(
                "Demo at capacity",
                "<h2>Demo is at capacity</h2><p>Too many live sessions right now — "
                "please try again in a few minutes.</p>",
            ), status_code=503)
        _last_launch[ip] = now

        sandbox = daytona.create(
            CreateSandboxFromSnapshotParams(
                snapshot=SNAPSHOT,
                # Cost control: stop 15 min after the visitor goes idle (compute
                # billing stops), and ephemeral → auto-delete on stop so no
                # storage lingers. Net: pay only while it's actively used.
                auto_stop_interval=15,
                ephemeral=True,
            )
        )
        dash_url = _signed(sandbox, API_PORT)
        notebook_url = _signed(sandbox, MARIMO_PORT)

        # Fire-and-forget the stack (process.exec would block on a server that
        # never exits; a background session doesn't).
        sandbox.process.create_session("boot")
        sandbox.process.execute_session_command(
            "boot",
            SessionExecuteRequest(
                command=(
                    f"cd /app && PATH={VENV}:$PATH "
                    f"HEXGATE_DEMO=1 HEXGATE_COOKIE_SECURE=1 "
                    f"HEXGATE_MARIMO_PORT={MARIMO_PORT} HEXGATE_DASH_URL='{dash_url}' "
                    f"{VENV}/python deploy/boot.py > /tmp/boot.log 2>&1"
                ),
                run_async=True,
            ),
        )

        # "Starting…" page polls /status until marimo answers, then redirects.
        poll = f"""<script>
const sb={sandbox.id!r}, url={notebook_url!r};
async function tick() {{
  try {{
    const r = await fetch('/status?sb='+encodeURIComponent(sb));
    const j = await r.json();
    if (j.ready) {{ location.href = url; return; }}
  }} catch (e) {{}}
  setTimeout(tick, 3000);
}}
tick();
</script>"""
        return HTMLResponse(_page(
            "Starting your Hexgate demo…",
            "<h2>🛡️ Spinning up your sandbox…</h2>"
            "<div class=spin></div>"
            "<p>~1 minute. You'll be redirected automatically.</p>"
            f"<p style='opacity:.5;font-size:.85rem'>If it stalls, "
            f"<a href='{notebook_url}'>open it manually</a>.</p>",
            poll,
        ))

    @web_app.get("/status")
    def status(sb: str):
        try:
            sandbox = daytona.get(sb)
            code = ""
            for attr in ("result", "output", "stdout"):
                r = sandbox.process.exec(
                    f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{MARIMO_PORT} || echo 000"
                )
                code = getattr(r, attr, None) or code
            return JSONResponse({"ready": "200" in (code or "")})
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"ready": False, "error": str(exc)})

    @web_app.get("/")
    def root():
        return RedirectResponse("/launch")

    return web_app
