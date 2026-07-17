#!/bin/bash
# PostToolUse hook (Edit|Write): formats the single file that was just
# touched, using each project's own toolchain — mirrors `make fmt` /
# `make dashboard-fmt` but scoped to one file so every edit doesn't
# trigger a full-repo reformat. Reads the hook payload from stdin.
#
# `uv run --no-sync` (not `--active`) deliberately avoids syncing the
# project venv against whatever's active in the caller's shell, which
# can otherwise churn packages or rewrite uv.lock as a side effect.

warn() { echo "format-on-edit: $*" >&2; }

if ! command -v jq >/dev/null 2>&1; then
  warn "jq not found, skipping format"
  exit 0
fi

f=$(jq -r '.tool_input.file_path // empty')
[ -z "$f" ] && exit 0

case "$f" in
  */platform/api/*.py)
    command -v uv >/dev/null 2>&1 || { warn "uv not found, skipping format for $f"; exit 0; }
    (cd platform/api && uv run --no-sync ruff format "$f") || warn "ruff format failed for $f"
    ;;
  *.py)
    command -v uv >/dev/null 2>&1 || { warn "uv not found, skipping format for $f"; exit 0; }
    uv run --no-sync ruff format "$f" || warn "ruff format failed for $f"
    ;;
  */platform/dashboard/src/*.ts | */platform/dashboard/src/*.tsx | */platform/dashboard/src/*.js | */platform/dashboard/src/*.jsx | */platform/dashboard/src/*.css | */platform/dashboard/src/*.json)
    command -v pnpm >/dev/null 2>&1 || { warn "pnpm not found, skipping format for $f"; exit 0; }
    (cd platform/dashboard && pnpm exec prettier --write "$f") || warn "prettier failed for $f"
    ;;
esac

exit 0
