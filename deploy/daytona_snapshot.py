#!/usr/bin/env python3
"""Build + register the Daytona snapshot for the hexgate demo (run once, or when
main changes). Bakes deps + the built dashboard into the image so sandboxes
spawn INSTANTLY (no per-launch uv sync / pnpm build).

    pip install daytona
    export DAYTONA_API_KEY=dtn_...
    python deploy/daytona_snapshot.py

Then spawn a test sandbox with deploy/daytona_spawn.py.

Clones HEXGATE_SNAPSHOT_REF (a branch or tag; defaults to `main`) so a release
build bakes the RELEASED code rather than whatever `main` happens to be. The
daytona-snapshot workflow sets it to the release tag.

NOTE: SDK names can shift; see https://www.daytona.io/docs/en/declarative-builder/
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

SNAPSHOT = "hexgate-demo"
REPO = "https://github.com/HexamindOrganisation/hexgate"
# Branch or tag to bake into the image. The release workflow pins this to the
# release tag so the snapshot is the released code, not a moving `main`.
REF = os.environ.get("HEXGATE_SNAPSHOT_REF", "main")


def _delete_snapshot(daytona: Daytona) -> None:
    """Delete the existing snapshot. Per the SDK, delete() takes the Snapshot
    OBJECT (get(name) returns it) — a name string won't work. Errors surface
    (e.g. if a running sandbox still holds it)."""
    daytona.snapshot.delete(daytona.snapshot.get(SNAPSHOT))


def main() -> None:
    daytona = Daytona(DaytonaConfig(api_key=os.environ["DAYTONA_API_KEY"]))

    # Everything the demo needs, baked at build time. python:3.13 because hexgate
    # requires >=3.13; Node 20 + pnpm 9 to build the dashboard (matches release.yml).
    image = (
        Image.base("python:3.13-slim-bookworm")
        .run_commands(
            "apt-get update && apt-get install -y --no-install-recommends "
            "git curl ca-certificates gnupg",
            "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - "
            "&& apt-get install -y nodejs",
            "npm install -g pnpm@9",
            "pip install --no-cache-dir uv",
            f"git clone --depth 1 --branch {REF} {REPO} /app",
            # API venv also brings the `hexgate` CLI (path dep); + marimo.
            "cd /app/platform/api && uv sync",
            "uv pip install --python /app/platform/api/.venv marimo",
            # Build the dashboard so the API serves it same-origin from dist/.
            "cd /app/platform/dashboard && pnpm install --frozen-lockfile && pnpm build",
        )
        .workdir("/app")
    )

    def _create() -> None:
        print("Building + registering snapshot (a few minutes; logs stream below)…\n")
        daytona.snapshot.create(
            CreateSnapshotParams(
                name=SNAPSHOT,
                image=image,
                # Small per-sandbox footprint so many demos run concurrently
                # within the Daytona account quota (~5× at 2 GB vs 8 GB). 2 GB
                # leaves headroom over the ~0.76 GB idle peak for a live LLM turn
                # (uvicorn + marimo kernel + ChatOpenAI) and the dashboard build.
                # Drop to 1 to pack more in if runs stay light; raise `disk` if
                # the image doesn't fit at build time.
                resources=Resources(cpu=1, memory=2, disk=5),
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
            print("   Run with --force to delete + rebuild after code changes.")
            return
        print(f"\nSnapshot '{SNAPSHOT}' exists — deleting + rebuilding (--force)…")
        _delete_snapshot(daytona)
        # Deletion is async — retry create until the old snapshot clears.
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
            raise SystemExit(
                f"'{SNAPSHOT}' still present ~60s after delete — remove it in the "
                "Daytona dashboard and re-run."
            )

    print(f"\n\n✅ snapshot '{SNAPSHOT}' ready. Next: python deploy/daytona_spawn.py")


if __name__ == "__main__":
    main()
