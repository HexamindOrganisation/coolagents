"""CLI tests for `hexgate policy check`."""

from __future__ import annotations

import sys
from pathlib import Path

from hexgate.cli import run


def _write(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _run(*argv: str) -> int:
    """Invoke the CLI and return its exit code (run() calls sys.exit)."""
    saved = sys.argv
    sys.argv = ["hexgate", *argv]
    try:
        run()
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    finally:
        sys.argv = saved


def test_check_clean_bundle_exits_zero(tmp_path):
    _write(
        tmp_path,
        "policies/boundaries/org.yaml",
        "default_policy: { mode: allow }\ntools:\n  refund: { mode: allow }\n",
    )
    _write(
        tmp_path,
        "policies/capabilities/pay.yaml",
        "tools:\n  refund: { mode: allow }\n",
    )
    assert _run("policy", "check", "--dir", str(tmp_path)) == 0


def test_check_dead_grant_is_a_warning_below_default_threshold(tmp_path):
    # ceiling boundary lists only refund; the capability also grants send_email,
    # which the ceiling excludes -> dead-grant (warning).
    _write(
        tmp_path,
        "policies/boundaries/org.yaml",
        "default_policy: { mode: deny }\ntools:\n  refund: { mode: allow }\n",
    )
    _write(
        tmp_path,
        "policies/capabilities/pay.yaml",
        "tools:\n  refund: { mode: allow }\n  send_email: { mode: allow }\n",
    )
    # default --max-severity is error, so a warning does not fail the run.
    assert _run("policy", "check", "--dir", str(tmp_path)) == 0
    # but gating on warning does.
    assert (
        _run("policy", "check", "--dir", str(tmp_path), "--max-severity", "warning")
        == 1
    )


def test_check_link_error_exits_one(tmp_path):
    _write(
        tmp_path,
        "policies/capabilities/bad.yaml",
        "tools:\n  refund: { mode: deny }\n",  # capabilities may not deny
    )
    assert _run("policy", "check", "--dir", str(tmp_path)) == 1
