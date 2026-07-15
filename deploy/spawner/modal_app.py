"""Hexgate demo spawner — a tiny Modal web service that launches a Daytona
sandbox per visitor and redirects them into it.

    Docs "Launch demo" button → the spawner's landing page (GET /)
        → click Launch → POST /launch → daytona.create(snapshot) → "starting…" page
        → GET /status → is marimo up yet? → page redirects to the signed notebook URL
        → Daytona sandbox runs the demo (~6¢/session, auto-stops after idle)

Abuse / cost control (every sandbox is billed to Hexamind):
  * /launch is POST-only, and GET / serves a page with a button — crawlers,
    link-unfurlers and prefetchers issue GETs, so they see a page and never
    spawn. The docs button links to GET / (safe), not straight to /launch.
  * A hard, FAIL-CLOSED concurrent cap (live count from Daytona, the shared
    source of truth) plus a daily launch budget in a `modal.Dict` (survives
    Modal autoscaling, unlike per-container memory).
  * Optional Cloudflare Turnstile: set the TURNSTILE_SITEKEY / TURNSTILE_SECRET
    env (in the `daytona` secret) and the landing button gates on a browser
    challenge. Off by default — see `_verify_turnstile`.

Why Modal: the spawner is pure request/response HTTP (no WebSocket), so none of
the marimo-WS problems that sank the *demo* on Modal apply here. It scales to
zero → near-free.

Deploy (from the repo root, no PR merge needed):
    modal secret create daytona DAYTONA_API_KEY=dtn_...   # + optional TURNSTILE_*
    modal deploy deploy/spawner/modal_app.py
    → prints a stable URL; the docs button points at <url>/ (the landing page)

daytona / fastapi are only in the container image, so all of their imports are
LAZY (inside the function) — module load must work on a laptop without them for
`modal deploy` to register the app.
"""

import modal

image = modal.Image.debian_slim().pip_install("daytona", "fastapi", "python-multipart")
app = modal.App("hexgate-spawner")

SNAPSHOT = "hexgate-demo"
MARIMO_PORT = 3000
API_PORT = 8000
VENV = "/app/platform/api/.venv/bin"
MAX_LIVE_SANDBOXES = 20  # hard concurrent cap (fail-closed)
MAX_LAUNCHES_PER_DAY = 200  # daily budget backstop against a slow drip
# Per-IP cooldown (shared across containers). 0 = OFF, so one machine can open
# several demos at once (live showcase). Set > 0 to throttle rapid launches from
# a single IP on a public/abuse-prone deploy; the concurrent cap + daily budget
# are the real cost guards either way.
PER_IP_COOLDOWN_SECONDS = 0


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("daytona")
    ],  # DAYTONA_API_KEY (+ optional TURNSTILE_*)
    scaledown_window=300,
)
@modal.asgi_app()
def web():
    import json
    import os
    import time
    import urllib.parse
    import urllib.request
    from datetime import datetime, timezone

    from daytona import (
        CreateSandboxFromSnapshotParams,
        Daytona,
        DaytonaConfig,
        SessionExecuteRequest,
    )
    from fastapi import FastAPI, Form, Request
    from fastapi.responses import HTMLResponse, JSONResponse

    web_app = FastAPI()
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))

    # Shared state across Modal containers — per-container dicts don't hold under
    # autoscaling (Guillaume's review on #78). Keys: `ip:<ip>` -> last-launch ts,
    # `launches:<YYYY-MM-DD>` -> count.
    state = modal.Dict.from_name("hexgate-spawner-state", create_if_missing=True)

    TURNSTILE_SITEKEY = os.environ.get("TURNSTILE_SITEKEY", "")
    TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")

    def _running_count() -> int | None:
        """Live sandbox count, or None if Daytona can't be read (caller then
        fails OPEN — see /launch). Logs the error so a persistent failure is
        visible in `modal app logs` instead of silently bricking the demo."""
        try:
            # daytona.list() returns a generator (SDK >= 0.197) — materialize
            # before len(). list(...) is harmless if a list is returned instead.
            return len(list(daytona.list()))
        except Exception as exc:  # noqa: BLE001
            print(f"[spawner] daytona.list() failed: {type(exc).__name__}: {exc}", flush=True)
            return None

    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _launches_today() -> int:
        return int(state.get(f"launches:{_today()}", 0))

    def _record_launch(ip: str) -> None:
        if ip:
            state[f"ip:{ip}"] = time.time()
        k = f"launches:{_today()}"
        # Read-modify-write isn't atomic across containers; a small overshoot of
        # the daily budget is acceptable (the concurrent cap is the hard guard).
        state[k] = int(state.get(k, 0)) + 1

    def _verify_turnstile(token: str) -> bool:
        """Cloudflare Turnstile check. DISABLED (allows all) unless
        TURNSTILE_SECRET is set — that's the hook: add the secret + sitekey to
        turn it on. When on, a failed/unreachable verify FAILS CLOSED."""
        if not TURNSTILE_SECRET:
            return True
        try:
            body = urllib.parse.urlencode(
                {"secret": TURNSTILE_SECRET, "response": token}
            ).encode()
            req = urllib.request.Request(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=body
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                return bool(json.loads(r.read()).get("success"))
        except Exception:  # noqa: BLE001
            return False

    def _signed(sandbox, port: int) -> str:
        return sandbox.create_signed_preview_url(port, expires_in_seconds=3600).url

    def _page(title: str, body: str, extra_head: str = "", tail: str = "") -> str:
        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>{title}</title>{extra_head}<style>
body{{font-family:system-ui;background:#0b0b0f;color:#e5e7eb;display:grid;
place-items:center;height:100vh;margin:0;text-align:center}}
.card{{max-width:32rem;padding:2rem}}
.spin{{width:2.5rem;height:2.5rem;border:3px solid #333;border-top-color:#3b82f6;
border-radius:50%;animation:s 1s linear infinite;margin:1.5rem auto}}
@keyframes s{{to{{transform:rotate(360deg)}}}}a{{color:#60a5fa}}
button{{font:inherit;padding:.75rem 1.5rem;border-radius:.5rem;border:0;
background:#3b82f6;color:#fff;cursor:pointer;margin-top:1rem}}</style></head>
<body><div class=card>{body}</div>{tail}</body></html>"""

    def _client_ip(request: Request) -> str:
        return (
            (
                request.headers.get("x-forwarded-for", "")
                or (request.client.host if request.client else "")
            )
            .split(",")[0]
            .strip()
        )

    @web_app.get("/")
    def root():
        # A landing page with a button that POSTs to /launch. Bots GET this and
        # see a page — they don't POST, so no sandbox is created. When Turnstile
        # is configured, render its widget so the button gates on the challenge.
        head = (
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
            if TURNSTILE_SITEKEY
            else ""
        )
        widget = (
            f'<div class="cf-turnstile" data-sitekey="{TURNSTILE_SITEKEY}"></div>'
            if TURNSTILE_SITEKEY
            else ""
        )
        return HTMLResponse(
            _page(
                "Hexgate live demo",
                "<h2>🛡️ Hexgate live demo</h2>"
                "<p>Spin up a throwaway sandbox with the notebook, dashboard, and a "
                "live agent. It auto-stops when you're done.</p>"
                f'<form method="post" action="/launch">{widget}'
                '<button type="submit">▶ Launch demo</button></form>',
                extra_head=head,
            )
        )

    @web_app.post("/launch")
    def launch(
        request: Request,
        # Turnstile's widget posts a hyphenated field name — alias to match it.
        cf_turnstile_response: str = Form(default="", alias="cf-turnstile-response"),
    ):
        # 1. Bot challenge (no-op unless Turnstile is configured).
        if not _verify_turnstile(cf_turnstile_response):
            return HTMLResponse(
                _page(
                    "Verification needed",
                    "<h2>Quick check needed</h2><p>Please complete the challenge on "
                    "the <a href='/'>launch page</a> and try again.</p>",
                ),
                status_code=403,
            )

        ip = _client_ip(request)
        now = time.time()

        # 2. Per-IP cooldown (shared via the Dict). Skipped entirely when 0.
        if (
            PER_IP_COOLDOWN_SECONDS
            and ip
            and now - float(state.get(f"ip:{ip}", 0)) < PER_IP_COOLDOWN_SECONDS
        ):
            return HTMLResponse(
                _page(
                    "Slow down",
                    "<h2>One launch at a time 🙂</h2><p>Please wait a few seconds and retry.</p>",
                ),
                status_code=429,
            )

        # 3. Daily budget backstop.
        if _launches_today() >= MAX_LAUNCHES_PER_DAY:
            return HTMLResponse(
                _page(
                    "Demo at capacity",
                    "<h2>Demo is resting for today</h2><p>The daily demo budget is "
                    "used up — please try again tomorrow.</p>",
                ),
                status_code=503,
            )

        # 4. Concurrent cap. If the live count can't be read, LOG and PROCEED
        #    (fail-open) — a Daytona list() blip must not brick a live demo. The
        #    daily budget above is the hard backstop. Hit /debug to see why a
        #    read failed.
        count = _running_count()
        if count is not None and count >= MAX_LIVE_SANDBOXES:
            return HTMLResponse(
                _page(
                    "Demo at capacity",
                    "<h2>Demo is at capacity</h2><p>Too many live sessions right now — "
                    "please try again in a few minutes.</p>",
                ),
                status_code=503,
            )

        # Create + boot. Wrapped so a Daytona failure (commonly a concurrent
        # sandbox / resource quota when another demo is already live) surfaces
        # as a readable page + a log line, not a blank 500.
        try:
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
            _record_launch(ip)  # only count a launch that actually created a sandbox
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
        except Exception as exc:  # noqa: BLE001
            print(f"[spawner] launch failed: {type(exc).__name__}: {exc}", flush=True)
            return HTMLResponse(
                _page(
                    "Couldn't start the demo",
                    "<h2>Couldn't start a sandbox</h2>"
                    f"<p style='opacity:.7'>{type(exc).__name__}: {exc}</p>"
                    "<p style='opacity:.5;font-size:.85rem'>Often a Daytona "
                    "concurrent-sandbox or resource quota when another demo is "
                    "already running.</p>",
                ),
                status_code=502,
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
        return HTMLResponse(
            _page(
                "Starting your Hexgate demo…",
                "<h2>🛡️ Spinning up your sandbox…</h2>"
                "<div class=spin></div>"
                "<p>~1 minute. You'll be redirected automatically.</p>"
                f"<p style='opacity:.5;font-size:.85rem'>If it stalls, "
                f"<a href='{notebook_url}'>open it manually</a>.</p>",
                tail=poll,
            )
        )

    @web_app.get("/debug")
    def debug():
        # Quick health probe: does daytona.list() work with the deployed
        # DAYTONA_API_KEY? Surfaces the real error (auth / SDK version / API
        # change) instead of the generic "at capacity" page.
        import importlib.metadata as _md

        out = {"daytona_sdk": _md.version("daytona"), "api_url": os.environ.get("HEXGATE_API_URL")}
        try:
            out["sandbox_count"] = len(list(daytona.list()))
            out["ok"] = True
        except Exception as exc:  # noqa: BLE001
            out["ok"] = False
            out["error"] = f"{type(exc).__name__}: {exc}"
        return JSONResponse(out)

    @web_app.get("/status")
    def status(sb: str):
        try:
            sandbox = daytona.get(sb)
            # One exec; then read whichever attr the SDK populated (don't re-run
            # the curl once per attribute name).
            r = sandbox.process.exec(
                f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{MARIMO_PORT} || echo 000"
            )
            code = ""
            for attr in ("result", "output", "stdout"):
                code = getattr(r, attr, None) or code
            return JSONResponse({"ready": "200" in (code or "")})
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"ready": False, "error": str(exc)})

    return web_app
