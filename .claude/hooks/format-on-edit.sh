#!/bin/bash
# PostToolUse hook (Edit|Write): formats the single file that was just
# touched, using each project's own toolchain — mirrors `make fmt` /
# `make dashboard-fmt` but scoped to one file so every edit doesn't
# trigger a full-repo reformat. Reads the hook payload from stdin.
#
# `uv run --no-sync` (not `--active`) deliberately avoids syncing the
# project venv against whatever's active in the caller's shell, which
# can otherwise churn packages or rewrite uv.lock as a side effect.

f=$(jq -r '.tool_input.file_path // empty')
[ -z "$f" ] && exit 0

case "$f" in
  */platform/api/*.py)
    (cd platform/api && uv run --no-sync ruff format "$f")
    ;;
  *.py)
    uv run --no-sync ruff format "$f"
    ;;
  */platform/dashboard/src/*.ts | */platform/dashboard/src/*.tsx | */platform/dashboard/src/*.js | */platform/dashboard/src/*.jsx | */platform/dashboard/src/*.css | */platform/dashboard/src/*.json)
    (cd platform/dashboard && pnpm exec prettier --write "$f")
    ;;
esac
