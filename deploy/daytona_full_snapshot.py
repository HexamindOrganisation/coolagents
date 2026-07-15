#!/usr/bin/env python3
"""Build the COMBINED snapshot for the end-to-end gates demo:
hexgate (platform + marimo) + hexkit (the "any app" agent UI), baked together.

Clones BOTH repos and runs their own setup so a single Daytona sandbox can host
the whole stack (platform + marimo + hexkit's tiers + the gdocs backend). The
manual end-to-end launcher — spawn it with deploy/daytona_full_spawn.py. (The
committed single-repo path is deploy/daytona_snapshot.py + the daytona-snapshot
workflow; wiring this combined build into CI is the post-#81 follow-up.)

    export DAYTONA_API_KEY=dtn_...
    uv run --with daytona python deploy/daytona_full_snapshot.py          # reuse if exists
    uv run --with daytona python deploy/daytona_full_snapshot.py --force  # delete + rebuild

Then: uv run --with daytona python deploy/daytona_full_spawn.py

Heavy build (two repos, two Node builds) — expect a few minutes.
"""

from __future__ import annotations

import os
import sys
import time

from daytona import (
    CreateSnapshotParams,
    Daytona,
    DaytonaConfig,
    Image,
    Resources,
)

SNAPSHOT = "hexgate-hexkit-demo"
HEXGATE_REPO = "https://github.com/HexamindOrganisation/hexgate"
HEXKIT_REPO = "https://github.com/HexamindOrganisation/hexkit"
# Branches to bake. hexkit is on main (gdocs-agent #16 merged). hexgate is
# pinned to the gates branch INTERIM so the demo builds with no override — the
# gates code isn't on main yet. FLIP TO "main" WHEN #81 MERGES (tracked as the
# productionization follow-up). Override either with HEXGATE_REF / HEXKIT_REF.
HEXGATE_REF = os.environ.get("HEXGATE_REF", "feat/gates-demo")
HEXKIT_REF = os.environ.get("HEXKIT_REF", "main")


def _delete_snapshot(daytona: Daytona) -> None:
    daytona.snapshot.delete(daytona.snapshot.get(SNAPSHOT))


def main() -> None:
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))

    image = (
        Image.base("python:3.13-slim-bookworm")
        .run_commands(
            "apt-get update && apt-get install -y --no-install-recommends "
            "git curl ca-certificates gnupg make psmisc",  # make + fuser (run-backends.sh)
            "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - "
            "&& apt-get install -y nodejs",
            "npm install -g pnpm@9",
            "pip install --no-cache-dir uv",
            # ---- hexgate (platform API + dashboard + marimo) at /app ----
            f"git clone --depth 1 --branch {HEXGATE_REF} {HEXGATE_REPO} /app",
            "cd /app/platform/api && uv sync",
            "uv pip install --python /app/platform/api/.venv marimo",
            "cd /app/platform/dashboard && pnpm install --frozen-lockfile && pnpm build",
            # ---- hexkit (front-app + proxy + agent-server) at /hexkit ----
            f"git clone --depth 1 --branch {HEXKIT_REF} {HEXKIT_REPO} /hexkit",
            "cd /hexkit && make setup",            # venvs + custom-UI build + front-app npm install
            "cd /hexkit && make install-hexgate",  # agent-server venv → py3.13 + hexgate (>=0.2.8, has mcp)
            # ---- the gates demo's gdocs agent backend (its own py3.13 venv) ----
            "cd /hexkit && uv venv --python 3.13 demo/gdocs-agent/.venv",
            "cd /hexkit && uv pip install --python demo/gdocs-agent/.venv -e demo/gdocs-agent",
        )
        .workdir("/app")
    )

    def _create() -> None:
        print("Building COMBINED snapshot (several minutes; logs stream)…\n")
        daytona.snapshot.create(
            CreateSnapshotParams(
                name=SNAPSHOT,
                image=image,
                # Max Daytona allows. Two repos + two node builds + venvs is heavy;
                # if disk overflows at build time, that's a signal we're too big.
                resources=Resources(cpu=4, memory=8, disk=10),
            ),
            on_logs=lambda chunk: print(chunk, end=""),
        )

    try:
        _create()
    except Exception as exc:  # noqa: BLE001
        if "already exists" not in str(exc).lower():
            raise
        if "--force" not in sys.argv:
            print(f"\n✅ snapshot '{SNAPSHOT}' already exists — reusing it.")
            print("   Run with --force to delete + rebuild.")
            return
        print(f"\nSnapshot '{SNAPSHOT}' exists — deleting + rebuilding (--force)…")
        _delete_snapshot(daytona)
        for _ in range(20):
            try:
                _create()
                break
            except Exception as e:  # noqa: BLE001
                if "already exists" in str(e).lower():
                    time.sleep(3)
                    continue
                raise
        else:
            raise SystemExit(f"'{SNAPSHOT}' still present after delete — clear it in the dashboard.")

    print(f"\n\n✅ snapshot '{SNAPSHOT}' ready. Next: python deploy/daytona_full_spawn.py")


if __name__ == "__main__":
    main()
