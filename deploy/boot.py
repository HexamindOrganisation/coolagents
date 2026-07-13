"""Boot one self-contained demo world inside a single container.

Starts, in order, in one process tree:

  1. Platform API (uvicorn ``hexgate_api.main:app``) on :8000 — its lifespan creates a
     fresh SQLite, seeds one org/user/project/agents, and (with HEXGATE_DEMO=1)
     serves the built dashboard same-origin + exposes /v1/demo-login.
  2. A minted HEXGATE_API_KEY for the seeded project (see provision.py).
  3. ``hexgate serve <AGENT_SPEC>`` — dials out to the local API's /v1/serve
     and runs the agent, streaming events back through the relay.
  4. marimo (the notebook UI the visitor lands on) on :2718.

Then it blocks, holding everything up until a child dies or it's signalled.
Container scaledown takes the whole world (SQLite, org, project) with it —
nothing to garbage-collect in a shared DB.

Runs locally for testing (``python deploy/boot.py``) and is the entrypoint the
Modal wrapper calls. ``dash_url`` (the public dashboard URL) is written to
``/tmp/hexgate_dash_url`` for the notebook to read and render as a link.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent          # repo root
API_DIR = REPO_ROOT / "platform" / "api"
DEPLOY_DIR = Path(__file__).resolve().parent
# Which notebook marimo serves. Defaults to the BYOK "define your own agent"
# demo; the gates demo sets HEXGATE_NOTEBOOK=deploy/gates-demo/notebook.py.
NOTEBOOK = Path(os.environ.get("HEXGATE_NOTEBOOK", str(DEPLOY_DIR / "demo_notebook.py")))

API_PORT = int(os.environ.get("HEXGATE_API_PORT", "8000"))
MARIMO_PORT = int(os.environ.get("HEXGATE_MARIMO_PORT", "2718"))
DASH_URL_FILE = Path(os.environ.get("HEXGATE_DASH_URL_FILE", "/tmp/hexgate_dash_url"))
# The public hexkit URL, when the integrated (gates) demo runs hexkit alongside.
# The notebook's "run it in a different app" section links to it if present.
HEXKIT_URL_FILE = Path(os.environ.get("HEXGATE_HEXKIT_URL_FILE", "/tmp/hexkit_url"))
SERVE_KEY_FILE = Path(os.environ.get("HEXGATE_SERVE_KEY_FILE", "/tmp/hexgate_serve_key"))

_procs: list[subprocess.Popen] = []


def _spawn(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.Popen:
    print(f"[boot] starting: {' '.join(cmd)}  (cwd={cwd})", flush=True)
    # start_new_session=True isolates the child in its own process group, so the
    # terminal's Ctrl-C goes only to boot.py — boot owns shutdown and signals
    # each child once, avoiding the SIGINT+SIGTERM race that left uvicorn
    # half-shutdown (port 8000 still bound) when boot exited too fast.
    p = subprocess.Popen(cmd, cwd=str(cwd), env=env, start_new_session=True)
    _procs.append(p)
    return p


def _wait_healthy(url: str, timeout: float = 90.0) -> None:
    """Poll a public, no-auth endpoint until the API answers."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    print(f"[boot] API healthy at {url}", flush=True)
                    return
        except Exception:
            time.sleep(0.5)
    raise TimeoutError(f"API did not become healthy at {url} within {timeout}s")


def start_services(dash_url: str | None = None) -> dict[str, str]:
    """Bring up the API (background) + mint the serve token, and RETURN the env.

    Everything except marimo. Modal's web_server entry runs marimo in the
    *foreground* (so its port is the served port) and only needs the API + key
    ready first — hence this split from :func:`run`, which is the local
    "start everything and block" path.
    """
    env = dict(os.environ)
    env.setdefault("HEXGATE_DEMO", "1")           # API serves dashboard + demo-login
    env.setdefault("HEXGATE_COOKIE_SECURE", "1")  # cookie rides the https tunnel
    api_base = f"http://127.0.0.1:{API_PORT}"
    env["HEXGATE_API_URL"] = api_base
    env["HEXGATE_ROOT"] = str(REPO_ROOT)  # so the notebook can find examples/*.py
    # The API package is imported by module name; make `main`, `examples.*` importable.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(API_DIR), str(REPO_ROOT), env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)

    # Publish the dashboard URL for the notebook to read. Falls back to the
    # local API origin when not running behind a tunnel (local testing).
    DASH_URL_FILE.write_text((dash_url or api_base).strip())

    # Publish the public hexkit URL too, when the integrated demo passes one
    # (HEXGATE_HEXKIT_URL). The gates notebook links to it; absent = the
    # notebook shows its "running locally" note instead.
    hexkit_url = os.environ.get("HEXGATE_HEXKIT_URL", "").strip()
    if hexkit_url:
        HEXKIT_URL_FILE.write_text(hexkit_url)

    # --- Platform API (background) --------------------------------------
    _spawn(
        ["uvicorn", "hexgate_api.main:app", "--host", "0.0.0.0", "--port", str(API_PORT)],
        cwd=API_DIR,
        env=env,
    )
    _wait_healthy(f"{api_base}/v1/.well-known/keys")

    # --- Mint the serve token + seed AFTER the API is healthy -----------
    # Must come after _wait_healthy: run-integrated.sh treats SERVE_KEY_FILE
    # appearing as "platform ready" and immediately binds the hexkit backend to
    # the API, so the key must not exist before uvicorn answers. docs_agent is
    # seeded without a compiled bundle — the SDK binds it via the pydantic
    # policy_yaml fallback, which is fine here (the demo never requires signed
    # bundles). The seed is best-effort (see provision) so a bad policy.yaml
    # can't take down the BYOK notebook path.
    sys.path.insert(0, str(DEPLOY_DIR))
    sys.path.insert(0, str(API_DIR))
    from provision import provision_serve_token  # noqa: E402  (path set above)

    SERVE_KEY_FILE.write_text(provision_serve_token())
    print("[boot] seeded demo agents + minted HEXGATE_API_KEY", flush=True)
    # serve itself runs in the notebook kernel (serve_manager), bound to the
    # live agent object. boot only hands it the key (file) + HEXGATE_API_URL (env).
    return env


def marimo_argv() -> list[str]:
    """The marimo command — the demo's landing UI. `edit` = interactive (read
    the def, run cells); `--no-token` since the throwaway container has nothing
    to protect."""
    return [
        "marimo", "edit", str(NOTEBOOK),
        "--headless", "--host", "0.0.0.0", "-p", str(MARIMO_PORT),
        "--no-token",
    ]


def run(dash_url: str | None = None) -> None:
    """Start the API, then marimo as a child, and block — used by
    `make demo-notebook` and by the demo sandbox (see deploy/spawner)."""
    env = start_services(dash_url)
    _spawn(marimo_argv(), cwd=REPO_ROOT, env=env)
    _block_until_exit()


_TERM_GRACE = 5.0  # seconds; long enough for uvicorn graceful shutdown


def _signal_group(p: subprocess.Popen, sig: int) -> None:
    """Signal the child's whole process group — covers uvicorn workers, etc."""
    try:
        os.killpg(os.getpgid(p.pid), sig)
    except ProcessLookupError:
        pass  # already gone


def _block_until_exit() -> None:
    shutting_down = False

    def _shutdown(*_):
        nonlocal shutting_down
        if shutting_down:
            return  # already in progress — ignore re-entrant signal
        shutting_down = True
        for p in _procs:
            if p.poll() is None:
                _signal_group(p, signal.SIGTERM)
        # Wait for graceful exit, then SIGKILL stragglers. Without this
        # the parent died first and uvicorn was orphaned with port still bound.
        for p in _procs:
            try:
                p.wait(timeout=_TERM_GRACE)
            except subprocess.TimeoutExpired:
                print(f"[boot] pid={p.pid} did not exit in {_TERM_GRACE}s; killing", flush=True)
                _signal_group(p, signal.SIGKILL)
                p.wait()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    # If any child dies, tear the whole world down — a half-up demo is worse
    # than a clean restart.
    while True:
        for p in _procs:
            if p.poll() is not None:
                print(f"[boot] child pid={p.pid} exited ({p.returncode}); shutting down", flush=True)
                _shutdown()
        time.sleep(1.0)


if __name__ == "__main__":
    # HEXGATE_DASH_URL lets the launcher (the Modal spawner) pass the public
    # dashboard URL so the notebook's "Open playground" link is reachable.
    run(dash_url=os.environ.get("HEXGATE_DASH_URL"))
