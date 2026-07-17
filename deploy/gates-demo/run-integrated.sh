#!/usr/bin/env bash
# Bring up the WHOLE gates demo in one container: hexgate platform + marimo
# (this notebook) + hexkit (the "different app" running the same gated agent).
#
# Assumes both repos are checked out and set up in the container (the combined
# Daytona snapshot does this — see deploy/daytona_full_snapshot.py):
#   HEXGATE_DIR  the hexgate repo (platform + SDK + this notebook)   default /app
#   HEXKIT_DIR  the hexkit repo (gdocs backend + proxy + front-app) default /hexkit
#
# Public URLs (signed preview links in Daytona) are passed IN by the spawner:
#   HEXGATE_DASH_URL    dashboard/platform origin (for the notebook + login)
#   HEXGATE_HEXKIT_URL  hexkit front-app origin (the notebook links to it)
# Locally you can omit them; the notebook shows its "running locally" note.
#
# Ports: platform :8000, marimo :3000, hexkit front-app :8873,
#        hexkit proxy :8800 -> gdocs backend :8880 (the agent server).

set -euo pipefail

HEXGATE_DIR="${HEXGATE_DIR:-/app}"
HEXKIT_DIR="${HEXKIT_DIR:-/hexkit}"
HEXGATE_VENV="${HEXGATE_VENV:-$HEXGATE_DIR/platform/api/.venv/bin}"
SERVE_KEY_FILE="${HEXGATE_SERVE_KEY_FILE:-/tmp/hexgate_serve_key}"
# Single source of truth for the gdocs backend's port: the backend binds it, the
# proxy proxies it, and the notebook (via boot.py's env) posts the BYOK key to it.
GDOCS_PORT="${GDOCS_PORT:-8880}"
GDOCS_URL="http://127.0.0.1:$GDOCS_PORT"

echo "== gates demo: booting the one-box stack =="

# 1. hexgate platform (:8000) + marimo gates notebook (:3000). boot.py seeds the
#    docs_agent policy (provision.py) and mints the serve key file the hexkit
#    backend adopts. HEXGATE_NOTEBOOK points marimo at the gates notebook;
#    HEXGATE_GDOCS_BACKEND_URL tells the notebook where to POST the BYOK key.
(
  cd "$HEXGATE_DIR"
  PATH="$HEXGATE_VENV:$PATH" \
  HEXGATE_DEMO=1 HEXGATE_COOKIE_SECURE="${HEXGATE_COOKIE_SECURE:-1}" \
  HEXGATE_MARIMO_PORT="${HEXGATE_MARIMO_PORT:-3000}" \
  HEXGATE_NOTEBOOK="$HEXGATE_DIR/deploy/gates-demo/notebook.py" \
  HEXGATE_GDOCS_BACKEND_URL="$GDOCS_URL" \
  HEXGATE_DASH_URL="${HEXGATE_DASH_URL:-}" \
  HEXGATE_HEXKIT_URL="${HEXGATE_HEXKIT_URL:-}" \
  "$HEXGATE_VENV/python" deploy/boot.py
) > /tmp/gates-hexgate.log 2>&1 &

# Wait for the platform to seed + mint the serve key (the backend needs it to
# bind the docs_agent policy).
echo "waiting for the platform to mint the serve key…"
for _ in $(seq 1 120); do [ -s "$SERVE_KEY_FILE" ] && break; sleep 1; done
[ -s "$SERVE_KEY_FILE" ] || { echo "serve key never appeared; see /tmp/gates-hexgate.log"; exit 1; }

# 2. hexkit gdocs backend (agent server). Binds the docs_agent policy from the
#    platform using the minted key (adopted from SERVE_KEY_FILE).
(
  cd "$HEXKIT_DIR"
  PYTHONPATH=demo/gdocs-agent/src \
  AGENT_HOST=0.0.0.0 AGENT_PORT="$GDOCS_PORT" \
  HEXGATE_API_URL=http://127.0.0.1:8000 \
  HEXGATE_SERVE_KEY_FILE="$SERVE_KEY_FILE" \
  demo/gdocs-agent/.venv/bin/python -m gdocs_agent
) > /tmp/gates-agent.log 2>&1 &

# Wait for the backend to finish startup (its lifespan connects the MCP server
# before it serves /agents) so the proxy's first roster fetch doesn't race it.
echo "waiting for the gdocs backend on :$GDOCS_PORT…"
agent_ready=""
for _ in $(seq 1 60); do
  if curl -sf -o /dev/null "$GDOCS_URL/agents"; then agent_ready=1; break; fi
  sleep 1
done
# Non-fatal (the notebook + dashboard still come up), but say so loudly — a
# silently dead backend just looks like a broken chat UI otherwise.
[ -n "$agent_ready" ] || echo "⚠ gdocs backend never answered on :$GDOCS_PORT — hexkit chat will be broken; see /tmp/gates-agent.log" >&2

# 3. hexkit proxy (:8800) -> the gdocs backend, with the gdocs demo users.
(
  cd "$HEXKIT_DIR"
  PLATFORM_DATABASE_URL="${PLATFORM_DATABASE_URL:-sqlite+aiosqlite:////tmp/hexa_dev.sqlite}" \
  PLATFORM_AGENT_BACKEND_URL="$GDOCS_URL" \
  PLATFORM_DEMO_USERS_FILE="$HEXKIT_DIR/demo/gdocs-agent/demo-users.yaml" \
  PYTHONPATH=proxy-server/src:packages/hexa-events/src \
  proxy-server/.venv/bin/python -m platform_backend
) > /tmp/gates-proxy.log 2>&1 &

# 4. hexkit front-app (:8873). --host so the preview proxy can reach it.
(
  cd "$HEXKIT_DIR/front-app"
  npm run dev -- --host 0.0.0.0 --port 8873
) > /tmp/gates-frontend.log 2>&1 &

echo "== all four services launched =="
echo "   platform :8000   marimo :3000   proxy :8800 -> agent :8880   front-app :8873"
echo "   logs: /tmp/gates-*.log"
wait
