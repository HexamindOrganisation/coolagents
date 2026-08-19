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


# --- roles: resolve/check over a multi-role project ------------------------


def _multi_role_project(root: Path) -> None:
    _write(
        root,
        "policies/boundaries/org.yaml",
        "default_policy: { mode: allow }\n"
        'tools:\n  refund: { mode: allow, constraints: ["args.amount <= 100"] }\n',
    )
    _write(
        root,
        "policies/capabilities/read_only.yaml",
        "tools:\n  view: { mode: allow }\n",
    )
    _write(
        root,
        "policies/capabilities/payments.yaml",
        "tools:\n  refund: { mode: allow }\n",
    )
    _write(
        root,
        "roles.yaml",
        "version: 1\nroles:\n  default: [read_only]\n  billing: [read_only, payments]\n",
    )


def test_resolve_multi_role_exits_zero(tmp_path):
    _multi_role_project(tmp_path)
    assert _run("policy", "resolve", "--dir", str(tmp_path)) == 0
    assert _run("policy", "resolve", "--dir", str(tmp_path), "--role", "billing") == 0


def test_resolve_unknown_role_exits_one(tmp_path):
    _multi_role_project(tmp_path)
    assert _run("policy", "resolve", "--dir", str(tmp_path), "--role", "ghost") == 1


def test_check_multi_role_exits_zero(tmp_path):
    _multi_role_project(tmp_path)
    assert _run("policy", "check", "--dir", str(tmp_path)) == 0


def test_check_unknown_role_exits_one(tmp_path):
    _multi_role_project(tmp_path)
    assert _run("policy", "check", "--dir", str(tmp_path), "--role", "ghost") == 1


def test_resolve_no_roles_backcompat_exits_zero(tmp_path):
    # No roles.yaml: single default importing every capability, as before.
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
    assert _run("policy", "resolve", "--dir", str(tmp_path)) == 0


def test_check_unknown_role_no_roles_exits_one(tmp_path):
    # No roles.yaml: only the synthesised `default` role exists. A typo'd role
    # must error, not silently pass and hide every lint.
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
    assert _run("policy", "check", "--dir", str(tmp_path), "--role", "ghost") == 1
    assert _run("policy", "check", "--dir", str(tmp_path), "--role", "default") == 0


def test_check_and_resolve_accept_synthesised_default(tmp_path):
    # roles.yaml omits `default`; both subcommands still accept --role default
    # (resolve synthesises it, so check must too).
    _write(
        tmp_path,
        "policies/capabilities/read_only.yaml",
        "tools:\n  view: { mode: allow }\n",
    )
    _write(tmp_path, "roles.yaml", "version: 1\nroles:\n  billing: [read_only]\n")
    assert _run("policy", "resolve", "--dir", str(tmp_path), "--role", "default") == 0
    assert _run("policy", "check", "--dir", str(tmp_path), "--role", "default") == 0


def test_resolve_output_roundtrips_through_policy_set(tmp_path):
    # A multi-role `resolve -o` must emit a `roles:` document that
    # load_policy_set_from_dict (and `policy build`) reads back with tools
    # intact, not a bare role mapping that flattens to a deny-everything policy.
    import yaml

    from hexgate.security import load_policy_set_from_dict

    _multi_role_project(tmp_path)
    out = tmp_path / "eff.yaml"
    assert _run("policy", "resolve", "--dir", str(tmp_path), "-o", str(out)) == 0

    payload = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert "roles" in payload  # wrapped, not a bare top-level role mapping

    ps = load_policy_set_from_dict(payload)
    billing = ps.policy_for("billing")
    assert "view" in billing.tools and "refund" in billing.tools  # survived


def test_typo_in_roles_key_is_an_error_not_silent_all_compose(tmp_path):
    # `role:` (typo of `roles:`) must fail loudly, not resolve to every capability.
    _write(
        tmp_path,
        "policies/capabilities/read_only.yaml",
        "tools:\n  view: { mode: allow }\n",
    )
    _write(tmp_path, "roles.yaml", "role:\n  default: [read_only]\n")
    assert _run("policy", "resolve", "--dir", str(tmp_path)) == 1
    assert _run("policy", "check", "--dir", str(tmp_path)) == 1
