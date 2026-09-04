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

from hexgate.security import analyzer
from hexgate.security.analyzer import PolicyLint

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


def test_validate_reports_constraint_error_at_the_policy_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A policy-level constraint has no tool of its own, so it is reported
    under ``<policy>`` rather than as a raw schema ValidationError."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\nroles:\n  default:\n    constraints:\n      - args.amount ~~ 50\n",
        encoding="utf-8",
    )
    rc = _main_validate(_ns(source=str(bad)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "default → <policy>" in err
    assert "no recognised operator" in err


def test_validate_catches_undefined_const_like_build(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """validate is a subset of build: an undefined const ref fails validate too,
    not just at platform build time."""
    p = tmp_path / "c.yaml"
    p.write_text(
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    consts: {cap: 500}\n"
        "    tools:\n"
        "      t: {mode: allow, constraints: ['args.x <= consts.missing']}\n",
        encoding="utf-8",
    )
    rc = _main_validate(_ns(source=str(p)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "undefined constant" in err


def test_validate_catches_file_scope_in_wasm_like_build(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """file_scope on a non-deny tool is a build-time rejection; validate must
    surface it rather than printing "parses cleanly"."""
    p = tmp_path / "fs.yaml"
    p.write_text(
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    tools:\n"
        "      read_file:\n"
        "        mode: allow\n"
        "        file_scope: {allowed_paths: ['/srv/*']}\n",
        encoding="utf-8",
    )
    rc = _main_validate(_ns(source=str(p)))
    err = capsys.readouterr().err
    assert rc == 1
    assert "file_scope" in err


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


_ROLE_GATED_POLICY = """\
version: 1
roles:
  default:
    tools:
      deploy:
        mode: allow
        constraints:
          - role == "admin"
  admin:
    tools:
      deploy:
        mode: allow
        constraints:
          - role == "admin"
"""


def test_test_pydantic_forwards_role(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`policy test --engine pydantic --role admin` on a role-scoped constraint
    must ALLOW — the pydantic path forwards role like wasm/production do."""
    p = tmp_path / "roles.yaml"
    p.write_text(_ROLE_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="admin",
            tool="deploy",
            args="{}",
            engine="pydantic",
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out


def test_test_pydantic_role_denies_non_admin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "roles.yaml"
    p.write_text(_ROLE_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="deploy",
            args="{}",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "DENY" in capsys.readouterr().out


_CTX_GATED_POLICY = """\
version: 1
roles:
  default:
    default_policy:
      mode: deny
    tools:
      refund:
        mode: allow
        constraints:
          - ctx.department == "finance"
          - ctx.clearance_level >= 3
"""


def test_test_pydantic_forwards_attributes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`policy test --attributes` threads the ABAC bag so ctx.* decides the
    same as production — without it the simulator would spuriously DENY."""
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes='{"department": "finance", "clearance_level": 3}',
            engine="pydantic",
        )
    )
    assert rc == 0
    assert "ALLOW" in capsys.readouterr().out


def test_test_missing_attributes_denies_ctx_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No --attributes → ctx.* refs miss and fail closed (exit 1)."""
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(source=str(p), role="default", tool="refund", args="{}", engine="pydantic")
    )
    assert rc == 1
    assert "DENY" in capsys.readouterr().out


def test_test_rejects_non_json_attributes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes="not json",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--attributes is not valid JSON" in capsys.readouterr().err


@pytest.mark.parametrize(
    "attributes",
    [
        '{"clearance_level": 3.5}',  # float — no ContextAttributeValue arm accepts it
        '{"scope": {"nested": 1}}',  # nested object
        '{"tags": [1, 2]}',  # list of non-strings
        '{"department": null}',  # null
    ],
)
def test_test_rejects_attributes_outside_attrvalue_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], attributes: str
) -> None:
    """Shapes ``HexgateContext.attributes`` can never hold must not reach the
    engines — the simulator would otherwise decide on a bag production can't
    produce, defeating the point of the flag."""
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes=attributes,
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--attributes values must be str | int | bool | list[str]" in (
        capsys.readouterr().err
    )


def test_test_rejects_non_object_attributes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes="[1, 2]",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--attributes must be a JSON object (dict)" in capsys.readouterr().err


def test_test_accepts_attributes_hexgate_context_would_coerce(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Validation must not over-reject: HexgateContext coerces a whole float
    (``3.0`` -> ``3``) rather than raising, so the simulator has to accept it
    too — only shapes production can't hold are rejected."""
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    rc = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes='{"department": "finance", "clearance_level": 3.0}',
            engine="pydantic",
        )
    )
    assert rc == 0
    assert "ALLOW" in capsys.readouterr().out


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
def test_test_engine_wasm_forwards_attributes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The wasm path threads --attributes into input.ctx, so a ctx.* policy
    decides identically to the pydantic path (no simulator/runtime drift)."""
    p = tmp_path / "ctx.yaml"
    p.write_text(_CTX_GATED_POLICY, encoding="utf-8")
    allow = _main_test(
        _ns(
            source=str(p),
            role="default",
            tool="refund",
            args="{}",
            attributes='{"department": "finance", "clearance_level": 3}',
            engine="wasm",
        )
    )
    assert allow == 0
    assert "ALLOW" in capsys.readouterr().out
    # Missing bag → fail closed on wasm too.
    deny = _main_test(
        _ns(source=str(p), role="default", tool="refund", args="{}", engine="wasm")
    )
    assert deny == 1
    assert "DENY" in capsys.readouterr().out


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


# ---------------------------------------------------------------------------
# test --roles: dry-run the permissive union
# ---------------------------------------------------------------------------

_MULTI_ROLE_POLICY = """\
version: 1
roles:
  default:
    default_policy:
      mode: deny
  support:
    default_policy:
      mode: deny
    tools:
      read_file:
        mode: allow
  billing:
    default_policy:
      mode: deny
    tools:
      refund:
        mode: allow
"""


def _multi_role_file(tmp_path: Path) -> Path:
    p = tmp_path / "multi.yaml"
    p.write_text(_MULTI_ROLE_POLICY, encoding="utf-8")
    return p


@pytest.mark.parametrize("engine", ["pydantic", "wasm"])
def test_test_roles_allows_when_any_role_grants(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], engine: str
) -> None:
    """Mirrors the enforcer on both engines: any role granting wins, and the
    granting role is named."""
    if engine == "wasm" and shutil.which("opa") is None:
        pytest.skip("opa not on PATH")
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles="support,billing",
            tool="refund",
            args="{}",
            engine=engine,
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out
    assert "granted by: billing" in out


def test_test_roles_denies_when_no_role_grants(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles="support,billing",
            tool="deploy",
            args="{}",
            engine="pydantic",
        )
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "DENY" in out
    assert "granted by" not in out  # nothing granted it


def test_test_roles_warns_on_an_undefined_role_but_still_evaluates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An undefined name falls back to ``default`` at runtime, so the dry-run
    warns rather than failing."""
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles="support,not_a_role",
            tool="read_file",
            args="{}",
            engine="pydantic",
        )
    )
    captured = capsys.readouterr()
    assert rc == 0
    assert "ALLOW" in captured.out
    assert 'warning: role "not_a_role" not in policy' in captured.err


def test_test_empty_roles_fails_instead_of_dry_running_the_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CI suite whose ``$ROLES`` failed to expand must not pass green while
    asserting nothing — the old behaviour silently evaluated ``default``."""
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles="",
            tool="read_file",
            args="{}",
            engine="pydantic",
        )
    )
    captured = capsys.readouterr()
    assert rc == 1
    assert "--roles is empty" in captured.err
    assert "ALLOW" not in captured.out


def test_test_blank_roles_entries_fail_the_same_way(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Commas and spaces alone name no roles either."""
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles=" , , ",
            tool="read_file",
            args="{}",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--roles is empty" in capsys.readouterr().err


def test_test_single_role_still_fails_on_a_typo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--role`` keeps its hard error: one undefined role is a typo."""
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            role="nope",
            tool="read_file",
            args="{}",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "not in policy" in capsys.readouterr().err


def test_test_roles_dedups_and_labels_the_set(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=str(_multi_role_file(tmp_path)),
            roles="support, support ,billing",
            tool="read_file",
            args="{}",
            engine="pydantic",
        )
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "[support, billing]" in out


# ---------------------------------------------------------------------------
# validate: the permissive-default warning + its CI gate
# ---------------------------------------------------------------------------

_PERMISSIVE_DEFAULT_POLICY = """\
version: 1
roles:
  default:
    tools:
      deploy:
        mode: allow
  support:
    default_policy:
      mode: deny
    tools:
      read_file:
        mode: allow
"""


def test_validate_warns_on_a_permissive_default_without_failing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A permissive `default` is legal (a flat policy.yaml is one), so validate
    still passes — but reports the exposure."""
    p = tmp_path / "exposed.yaml"
    p.write_text(_PERMISSIVE_DEFAULT_POLICY, encoding="utf-8")

    rc = _main_validate(_ns(source=str(p), max_severity="error"))

    captured = capsys.readouterr()
    assert rc == 0
    assert "permissive-default" in captured.err
    assert "deploy" in captured.err
    assert "Policy parses cleanly" in captured.out


def test_validate_gates_on_the_permissive_default_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """How CI refuses a default role granting what no named role grants."""
    p = tmp_path / "exposed.yaml"
    p.write_text(_PERMISSIVE_DEFAULT_POLICY, encoding="utf-8")

    rc = _main_validate(_ns(source=str(p), max_severity="warning"))

    captured = capsys.readouterr()
    assert rc == 1
    assert "permissive-default" in captured.err
    # A gated run must not also claim success — a CI log saying "parses cleanly"
    # next to a non-zero exit sends the reader hunting for a phantom failure.
    assert "Policy parses cleanly" not in captured.out
    assert "at or above --max-severity warning" in captured.err


def _lint_of_severity(severity: str) -> list[PolicyLint]:
    return [PolicyLint(code="stub-lint", severity=severity, message="stub")]


@pytest.mark.parametrize(
    ("severity", "expected_rc"),
    [("error", 1), ("warning", 0), ("info", 0)],
)
def test_validate_gates_on_each_lint_severity_not_a_hardcoded_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    severity: str,
    expected_rc: int,
) -> None:
    """The default threshold gates on the lint's own severity.

    Only ``check_default_role_exposure``'s warnings exist today, so an
    ``error``-severity lint slipping through the default threshold would be
    invisible until the first one is written.
    """
    p = tmp_path / "clean.yaml"
    p.write_text(_MULTI_ROLE_POLICY, encoding="utf-8")
    monkeypatch.setattr(
        analyzer, "check_default_role_exposure", lambda _: _lint_of_severity(severity)
    )

    assert _main_validate(_ns(source=str(p), max_severity="error")) == expected_rc


def test_validate_clean_role_policy_has_no_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "clean.yaml"
    p.write_text(_MULTI_ROLE_POLICY, encoding="utf-8")

    rc = _main_validate(_ns(source=str(p), max_severity="warning"))

    assert rc == 0
    assert "permissive-default" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# `policy test --run-facts` — dry-running a circuit breaker at its threshold
# ---------------------------------------------------------------------------


_RUN_GATED_POLICY = """\
version: 1
tools:
  search:
    mode: allow
    constraints:
      - run.elapsed_seconds < 300
"""


def _run_gated(tmp_path: Path) -> str:
    p = tmp_path / "run.yaml"
    p.write_text(_RUN_GATED_POLICY, encoding="utf-8")
    return str(p)


def test_test_defaults_to_a_started_run_rather_than_a_missing_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No --run-facts must not deny closed like a missing namespace would."""
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            engine="pydantic",
        )
    )
    assert rc == 0
    assert "ALLOW" in capsys.readouterr().out


def test_test_run_facts_fires_the_cap(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            run_facts='{"elapsed_seconds": 400}',
            engine="pydantic",
        )
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "DENY" in out
    assert "run.elapsed_seconds < 300" in out


@needs_opa
def test_test_run_facts_agrees_across_engines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = _run_gated(tmp_path)
    codes = [
        _main_test(
            _ns(
                source=source,
                role="default",
                tool="search",
                args="{}",
                run_facts='{"elapsed_seconds": 400}',
                engine=engine,
            )
        )
        for engine in ("pydantic", "wasm")
    ]
    assert codes == [1, 1]


def test_test_rejects_non_json_run_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            run_facts="not json",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--run-facts is not valid JSON" in capsys.readouterr().err


def test_test_rejects_non_object_run_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            run_facts="[1, 2]",
            engine="pydantic",
        )
    )
    assert rc == 1
    assert "--run-facts must be a JSON object (dict)" in capsys.readouterr().err


def test_test_rejects_unknown_run_fact_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            run_facts='{"elapsed_secondz": 400}',
            engine="pydantic",
        )
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "unknown run.* path(s) ['elapsed_secondz']" in err
    assert "elapsed_seconds" in err  # the registry, so the fix is visible


@pytest.mark.parametrize("raw", ['{"elapsed_seconds": "400"}', '{"tool_calls": true}'])
def test_test_rejects_a_wrong_typed_run_fact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: str
) -> None:
    """A wrong-typed value used to fail the comparison closed and print the same
    '✗ DENY … constraint failed' line as a real threshold trip."""
    rc = _main_test(
        _ns(
            source=_run_gated(tmp_path),
            role="default",
            tool="search",
            args="{}",
            run_facts=raw,
            engine="pydantic",
        )
    )
    out, err = capsys.readouterr()
    assert rc == 1
    assert "--run-facts has a wrong-typed value" in err
    assert "DENY" not in out


def test_test_reports_an_unknown_run_path_in_the_policy_itself(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The load-time linter reaches the CLI, not just direct PolicySet use."""
    p = tmp_path / "typo.yaml"
    p.write_text(
        _RUN_GATED_POLICY.replace("run.elapsed_seconds", "run.elapsed_secondz"),
        encoding="utf-8",
    )
    rc = _main_test(
        _ns(source=str(p), role="default", tool="search", args="{}", engine="pydantic")
    )
    assert rc == 1
    assert "unknown run.* path 'elapsed_secondz'" in capsys.readouterr().err
