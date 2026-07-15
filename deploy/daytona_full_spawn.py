#!/usr/bin/env python3
"""Spawn the end-to-end gates demo in one Daytona sandbox: hexgate platform +
marimo + hexkit (proxy + front-app + gdocs backend), all at once. Boots the
stack via deploy/gates-demo/run-integrated.sh, reports memory + which ports
answer, then hands you the signed URLs (marimo notebook, dashboard, hexkit UI).

    export DAYTONA_API_KEY=dtn_...
    uv run --with daytona python deploy/daytona_full_spawn.py   # after building the snapshot

The sandbox is ephemeral (auto-stops when idle) and deleted on exit. Build the
snapshot first with deploy/daytona_full_snapshot.py.
"""

from __future__ import annotations

import os
import time

from daytona import CreateSandboxFromSnapshotParams, Daytona, DaytonaConfig, SessionExecuteRequest

SNAPSHOT = "hexgate-hexkit-demo"
HEXGATE_VENV = "/app/platform/api/.venv/bin"

# Browser-facing ports (need signed preview URLs; must be in 3000–9999).
MARIMO_PORT = 3000    # hexgate marimo notebook (the tour)
DASH_PORT = 8000      # hexgate platform API + dashboard (policy)
HEXKIT_PORT = 8873    # hexkit front-app (the agent UI)
# Internal (not browser-facing): hexkit proxy 8800, agent-server 8880.
ALL_PORTS = {"marimo": 3000, "dashboard": 8000, "hexkit-proxy": 8800,
             "hexkit-frontend": 8873, "agent-server": 8880}


def _stdout(r) -> str:
    # Return the stdout attr even when empty ("") — do NOT fall back to repr(r),
    # which made the OOM grep below false-positive on empty results.
    for attr in ("result", "output", "stdout"):
        if hasattr(r, attr):
            v = getattr(r, attr)
            if v is not None:
                return v
    return ""


def _mem(sandbox) -> str:
    """Container memory via cgroup v2 (the slim image has no `free`)."""
    cur = _stdout(sandbox.process.exec("cat /sys/fs/cgroup/memory.current 2>/dev/null || echo")).strip()
    mx = _stdout(sandbox.process.exec("cat /sys/fs/cgroup/memory.max 2>/dev/null || echo")).strip()
    if cur.isdigit():
        used = int(cur) / 2**30
        limit = "unbounded" if mx == "max" else (f"{int(mx) / 2**30:.2f} GiB" if mx.isdigit() else mx or "?")
        return f"used {used:.2f} GiB / limit {limit}"
    mi = _stdout(sandbox.process.exec("head -3 /proc/meminfo 2>/dev/null || echo")).strip()
    return mi or "memory unavailable"


def _signed(sandbox, port: int) -> str:
    try:
        return sandbox.create_signed_preview_url(port, expires_in_seconds=3600).url
    except AttributeError:
        return getattr(sandbox.get_preview_link(port), "url", "?")


def _session(sandbox, name: str, command: str) -> None:
    sandbox.process.create_session(name)
    sandbox.process.execute_session_command(name, SessionExecuteRequest(command=command, run_async=True))


def _delete(daytona: Daytona, sandbox) -> None:
    try:
        sandbox.delete()
    except Exception:
        try:
            daytona.delete(sandbox)
        except Exception as exc:  # noqa: BLE001
            print(f"⚠ auto-delete failed ({exc}) — delete it in the dashboard.")
            return
    print("✅ sandbox deleted.")


def main() -> None:
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))
    print(f"Creating sandbox from '{SNAPSHOT}'…")
    sandbox = daytona.create(
        CreateSandboxFromSnapshotParams(snapshot=SNAPSHOT, auto_stop_interval=15, ephemeral=True)
    )
    try:
        dash_url = _signed(sandbox, DASH_PORT)
        hexkit_url = _signed(sandbox, HEXKIT_PORT)

        # One session runs the whole integrated gates demo: platform + marimo
        # (gates notebook) + gdocs backend + proxy + front-app. The signed public
        # URLs are passed in so the notebook can link to hexkit + the dashboard.
        _session(sandbox, "gates",
                 f"cd /app && HEXGATE_DASH_URL='{dash_url}' HEXGATE_HEXKIT_URL='{hexkit_url}' "
                 f"HEXGATE_MARIMO_PORT={MARIMO_PORT} "
                 f"bash deploy/gates-demo/run-integrated.sh > /tmp/gates.log 2>&1")

        print("Booting the full stack (~90s: platform + marimo + gdocs backend + proxy + front-app)…")
        time.sleep(100)

        # --- fit report ---
        print("\n==== MEMORY (cgroup — the whole point) ====")
        print(" ", _mem(sandbox))
        print("==== PORT READINESS  (proxy :8800 -> 404 is EXPECTED — it serves /api) ====")
        for label, port in ALL_PORTS.items():
            code = _stdout(sandbox.process.exec(
                f"curl -s -o /dev/null -w '%{{http_code}}' http://localhost:{port} || echo 000"
            )).strip()
            print(f"  {label:16} :{port}  -> {code}")
        for log in ("gates", "gates-hexgate", "gates-agent", "gates-proxy", "gates-frontend"):
            oom = _stdout(sandbox.process.exec(f"grep -i -m1 killed /tmp/{log}.log || true")).strip()
            if oom:
                print(f"  ⚠ possible OOM in {log}.log: {oom}")

        print("\n==== SIGNED URLS ====")
        print("  marimo notebook :", _signed(sandbox, MARIMO_PORT))
        print("  dashboard       :", dash_url, "(+ /v1/demo-login for auto-login)")
        print("  hexkit UI       :", hexkit_url)
        print("\nIf a port shows 000, tail its log: sandbox.process.exec('cat /tmp/gates*.log')")
        input("\nPress Enter when done — the sandbox will be deleted… ")
    finally:
        print(f"\nDeleting sandbox {getattr(sandbox, 'id', '?')}…")
        _delete(daytona, sandbox)


if __name__ == "__main__":
    main()
