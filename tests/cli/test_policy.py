"""Tests for the ``hexgate policy`` CLI subcommand (M2 phase 2).

Each subcommand has its own ``main`` function that takes a parsed
``argparse.Namespace`` and returns an exit code. Tests build the
namespace directly (skipping the top-level parser) and inspect exit
codes + stdout/stderr capture.

A small in-memory YAML fixture exercises the role-aware shape from
the support_bot demo so the parity tests stay aligned with what the
runtime sees.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest

from hexgate.cli.policy.main import (
    _main_build,
    _main_keygen,
    _main_show_rego,
    _main_test,
    _main_validate,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(
    not _OPA_AVAILABLE,
    reason="opa not on PATH — install via `brew install opa` to run these tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_DEMO_POLICY = """\
version: 1
roles:
  read_only:
    is_mixin: true
    tools:
      web_search: { mode: allow }
  default:
    inherits: [read_only]
    tools:
      refund_order: { mode: deny }
  billing:
    inherits: [read_only]
    tools:
      refund_order:
        mode: allow
        constraints:
          - args.amount <= 500
          - args.currency in ["USD", "EUR"]
"""


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    """A scratch policy.yaml with the support_bot demo shape."""
    p = tmp_path / "billing.yaml"
    p.write_text(_DEMO_POLICY, encoding="utf-8")
    return p


def _ns(**kwargs) -> argparse.Namespace:
    """Convenience for building an argparse.Namespace with sane defaults."""
    return argparse.Namespace(**kwargs)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_passes_on_clean_policy(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A well-formed policy.yaml exits 0 with a success line on stdout."""
    rc = _main_validate(_ns(source=str(policy_file)))
    out = capsys.readouterr()
    assert rc == 0
    assert "parses cleanly" in out.out


def test_validate_reports_constraint_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unsupported operator surfaces as a constraint error with role+tool."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    tools:\n"
        "      refund:\n"
        "        mode: allow\n"
        "        constraints:\n"
        "          - args.amount ~~ 50\n",
        encoding="utf-8",
    )
    rc = _main_validate(_ns(source=str(bad)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "default → refund" in err
    assert "no recognised operator" in err


def test_validate_reports_constraint_error_in_default_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bad constraint in a role's default_policy gets the friendly role→tool
    message too, not a raw schema ValidationError."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    default_policy:\n"
        "      mode: deny\n"
        "      constraints:\n"
        "        - args.amount ~~ 50\n",
        encoding="utf-8",
    )
    rc = _main_validate(_ns(source=str(bad)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "default → <default>" in err
    assert "no recognised operator" in err


def test_validate_handles_missing_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A missing source path exits 1 with a clear error message."""
    rc = _main_validate(_ns(source=str(tmp_path / "nope.yaml")))
    err = capsys.readouterr().err
    assert rc == 1
    assert "no such file" in err


def test_validate_handles_malformed_yaml(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A YAML lex error surfaces with the offending line number."""
    p = tmp_path / "broken.yaml"
    p.write_text("tools: [bad: unclosed\n", encoding="utf-8")
    rc = _main_validate(_ns(source=str(p)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "YAML parse error" in err
    assert "line" in err.lower()


# ---------------------------------------------------------------------------
# show-rego
# ---------------------------------------------------------------------------


def test_show_rego_emits_module_to_stdout(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The compiled Rego goes to stdout, exit 0."""
    rc = _main_show_rego(_ns(source=str(policy_file)))
    out = capsys.readouterr().out
    assert rc == 0
    assert "package hexgate.policy" in out
    assert "default allow := false" in out
    # Demo's billing rule should be visible
    assert 'input.role == "billing"' in out
    assert "input.args.amount <= 500" in out


def test_show_rego_filters_mixin(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Mixin roles never surface as `input.role == "<mixin>"`."""
    _main_show_rego(_ns(source=str(policy_file)))
    out = capsys.readouterr().out
    assert 'input.role == "read_only"' not in out


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def test_build_writes_bundle_files(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """build --no-wasm produces {stem}.yaml + {stem}.rego + {stem}.bundle.json."""
    out_dir = tmp_path / "build"
    rc = _main_build(_ns(source=str(policy_file), out=str(out_dir), no_wasm=True))
    capsys.readouterr()  # drain
    assert rc == 0
    assert (out_dir / "billing.yaml").exists()
    assert (out_dir / "billing.rego").exists()
    assert (out_dir / "billing.bundle.json").exists()
    # --no-wasm should leave the wasm artifact absent.
    assert not (out_dir / "billing.wasm").exists()


def test_build_no_wasm_manifest_carries_only_yaml_and_rego_hashes(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With --no-wasm the manifest records source + rego hashes; wasm_hash is None."""
    out_dir = tmp_path / "build"
    _main_build(_ns(source=str(policy_file), out=str(out_dir), no_wasm=True))
    capsys.readouterr()
    bundle = json.loads((out_dir / "billing.bundle.json").read_text())
    assert bundle["version"] == 1
    assert bundle["source"] == "billing.yaml"
    assert len(bundle["source_hash"]) == 64
    assert len(bundle["rego_hash"]) == 64
    assert bundle["wasm_hash"] is None


def test_build_defaults_output_to_source_dir(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --out, artifacts land next to the source file."""
    rc = _main_build(_ns(source=str(policy_file), out=None, no_wasm=True))
    capsys.readouterr()
    assert rc == 0
    assert (policy_file.parent / "billing.rego").exists()
    assert (policy_file.parent / "billing.bundle.json").exists()


def test_build_accepts_relative_out_dir(
    policy_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A relative --out resolves cleanly — regression for the relative_to()
    crash where the under-cwd check resolved paths but the display didn't."""
    monkeypatch.chdir(tmp_path)
    rc = _main_build(_ns(source=str(policy_file), out="rel-bundle", no_wasm=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert (tmp_path / "rel-bundle" / "billing.rego").exists()
    # Output renders the path relative to cwd, not a crash.
    assert "rel-bundle/billing.rego" in out


def test_build_rejects_unparseable_constraint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Bad constraint → compile error → exit 1, no files written."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\nroles:\n  default:\n    tools:\n      r:\n        mode: allow\n"
        "        constraints: [args.amount ~~ 50]\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "build"
    rc = _main_build(_ns(source=str(bad), out=str(out_dir), no_wasm=True))
    err = capsys.readouterr().err
    assert rc == 1
    assert "compile error" in err
    # Nothing should have been written into the output dir.
    assert not out_dir.exists() or not list(out_dir.iterdir())


@needs_opa
def test_build_writes_wasm_when_opa_available(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Default build path (no --no-wasm) drops a {stem}.wasm next to the rego."""
    out_dir = tmp_path / "build"
    rc = _main_build(_ns(source=str(policy_file), out=str(out_dir), no_wasm=False))
    capsys.readouterr()
    assert rc == 0
    wasm_path = out_dir / "billing.wasm"
    assert wasm_path.exists()
    # Magic header sanity check — full validation lives in test_rego_wasm.
    assert wasm_path.read_bytes().startswith(b"\x00asm")


@needs_opa
def test_build_with_wasm_records_wasm_hash(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The bundle.json's wasm_hash matches sha256(billing.wasm)."""
    import hashlib

    out_dir = tmp_path / "build"
    _main_build(_ns(source=str(policy_file), out=str(out_dir), no_wasm=False))
    capsys.readouterr()
    bundle = json.loads((out_dir / "billing.bundle.json").read_text())
    expected = hashlib.sha256((out_dir / "billing.wasm").read_bytes()).hexdigest()
    assert bundle["wasm_hash"] == expected


# ---------------------------------------------------------------------------
# keygen + build --sign-key
# ---------------------------------------------------------------------------


def test_keygen_writes_key_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """keygen writes a .private + .public, private is 0600."""
    import stat

    prefix = tmp_path / "keys" / "devkey"
    rc = _main_keygen(_ns(out=str(prefix), force=False))
    capsys.readouterr()
    assert rc == 0
    priv = tmp_path / "keys" / "devkey.private"
    pub = tmp_path / "keys" / "devkey.public"
    assert priv.is_file() and pub.is_file()
    # Private key is mode 0600 — it's a signing secret.
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600


def test_keygen_refuses_overwrite_without_force(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prefix = tmp_path / "devkey"
    _main_keygen(_ns(out=str(prefix), force=False))
    capsys.readouterr()
    rc = _main_keygen(_ns(out=str(prefix), force=False))
    err = capsys.readouterr().err
    assert rc == 1
    assert "already exists" in err


def test_keygen_keys_roundtrip_for_signing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The emitted keys actually work as a sign/verify pair."""
    from hexgate.security import decode_key, sign_bytes, verify_bytes

    prefix = tmp_path / "devkey"
    _main_keygen(_ns(out=str(prefix), force=False))
    capsys.readouterr()
    priv = decode_key((tmp_path / "devkey.private").read_text().strip())
    pub = decode_key((tmp_path / "devkey.public").read_text().strip())
    sig = sign_bytes(b"payload", priv)
    verify_bytes(b"payload", sig, pub)  # no raise == pass


@needs_opa
def test_build_sign_key_emits_verifiable_signature(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """build --sign-key writes a .sig that verifies under the public key."""
    from hexgate.security import PolicyBundle, decode_key

    key_prefix = tmp_path / "k"
    _main_keygen(_ns(out=str(key_prefix), force=False))
    capsys.readouterr()

    out_dir = tmp_path / "build"
    rc = _main_build(
        _ns(
            source=str(policy_file),
            out=str(out_dir),
            no_wasm=False,
            sign_key=str(tmp_path / "k.private"),
        )
    )
    capsys.readouterr()
    assert rc == 0
    assert (out_dir / "billing.bundle.json.sig").exists()

    bundle = PolicyBundle.from_disk(out_dir)
    assert bundle.is_signed
    pub = decode_key((tmp_path / "k.public").read_text().strip())
    bundle.verify_signature(pub)  # no raise == pass


def test_build_sign_key_rejects_bad_key(
    policy_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A malformed --sign-key fails before any files are written."""
    bad_key = tmp_path / "bad.private"
    bad_key.write_text("not-a-real-key", encoding="utf-8")
    out_dir = tmp_path / "build"
    rc = _main_build(
        _ns(
            source=str(policy_file),
            out=str(out_dir),
            no_wasm=True,
            sign_key=str(bad_key),
        )
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "--sign-key" in err
    # Nothing written — fail-fast before touching the output dir.
    assert not out_dir.exists() or not list(out_dir.iterdir())


# ---------------------------------------------------------------------------
# test (dry-run)
# ---------------------------------------------------------------------------


def test_test_allows_when_constraints_pass(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """billing/refund_order with amount=200 USD → ALLOW (exit 0)."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args='{"amount": 200, "currency": "USD"}',
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out


def test_test_denies_when_constraint_fails(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """billing/refund_order with amount=700 → DENY, exit 1, reason surfaced."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args='{"amount": 700, "currency": "USD"}',
        )
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "DENY" in out
    assert "args.amount <= 500" in out


def test_test_denies_when_mode_is_deny(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """default/refund_order is mode: deny — exits 1 regardless of args."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="default",
            tool="refund_order",
            args="{}",
        )
    )
    assert rc == 1
    assert "DENY" in capsys.readouterr().out


def test_test_pydantic_denial_surfaces_file_scope_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pydantic engine now renders the structured file-scope hint —
    a detail the old exception-only path couldn't reach."""
    policy = tmp_path / "scoped.yaml"
    policy.write_text(
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    tools:\n"
        "      read_file:\n"
        "        mode: allow\n"
        "        file_scope:\n"
        "          allowed_paths: ['docs/**']\n",
        encoding="utf-8",
    )
    rc = _main_test(
        _ns(
            source=str(policy),
            role="default",
            tool="read_file",
            args='{"file_path": "secrets/key.pem"}',
        )
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "DENY" in out
    assert "hint" in out
    assert "docs/**" in out


def test_test_rejects_unknown_role(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unknown role exits 1 with the list of known roles."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="nope",
            tool="refund_order",
            args="{}",
        )
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert 'role "nope"' in err
    assert "billing" in err


def test_test_rejects_invalid_args_json(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--args must be valid JSON; clear error when it isn't."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args="{not json",
        )
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "not valid JSON" in err


def test_test_rejects_non_object_args(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--args must be a JSON object — lists and scalars rejected."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args="[1, 2, 3]",
        )
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "JSON object" in err


# --- engine=wasm path -------------------------------------------------------


@needs_opa
def test_test_engine_wasm_allows(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--engine wasm` compiles + evaluates against wasm — same allow verdict."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args='{"amount": 200, "currency": "USD"}',
            engine="wasm",
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out


@needs_opa
def test_test_engine_wasm_surfaces_violations(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """On deny, the wasm path prints the actual violated constraint strings."""
    rc = _main_test(
        _ns(
            source=str(policy_file),
            role="billing",
            tool="refund_order",
            args='{"amount": 700, "currency": "GBP"}',
            engine="wasm",
        )
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "DENY" in out
    assert "args.amount <= 500" in out
    assert 'args.currency in ["USD", "EUR"]' in out


# ---------------------------------------------------------------------------
# Wiring — confirm hexgate policy reaches our subcommand handlers
# ---------------------------------------------------------------------------


def test_top_level_dispatch_routes_to_policy(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The top-level `hexgate` parser routes `policy validate <file>` here."""
    from hexgate.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["policy", "validate", str(policy_file)])
    rc = args.func(args)
    assert rc == 0
    assert "parses cleanly" in capsys.readouterr().out


def test_top_level_dispatch_routes_to_show_rego(
    policy_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`hexgate policy show-rego` routes through and emits Rego on stdout."""
    from hexgate.cli import _build_parser

    parser = _build_parser()
    args = parser.parse_args(["policy", "show-rego", str(policy_file)])
    rc = args.func(args)
    assert rc == 0
    assert "package hexgate.policy" in capsys.readouterr().out
