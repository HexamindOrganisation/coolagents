"""End-to-end tests for the ``HEXGATE_LOCAL_POLICY`` env override.

When the env var points at a valid bundle, loaders must:

  * verify the bundle's integrity,
  * attach it to the constructed agent's tools (in place of whatever
    policy.yaml the agent definition would have used),
  * leave a loud stderr trail so the dev knows the override is active.

Bad overrides (missing dir, hash mismatch, no wasm) must raise at load
time — silent fallback to the original policy would be a security
footgun. These tests build real bundles via ``opa`` and are skipped
when opa isn't available.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from hexgate.agents import loader
from hexgate.security import (
    compile_to_rego,
    compile_to_wasm,
    encode_key,
    generate_keypair,
    sign_bytes,
)


_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(
    not _OPA_AVAILABLE,
    reason="opa not on PATH — install via `brew install opa` to run these tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_OVERRIDE_YAML = """\
version: 1
roles:
  default:
    tools:
      web_search: { mode: allow }
"""


def _build_bundle_dir(directory: Path) -> Path:
    """Build a real bundle on disk inside ``directory`` and return that path."""
    directory.mkdir(parents=True, exist_ok=True)
    yaml_path = directory / "policy.yaml"
    yaml_path.write_text(_OVERRIDE_YAML, encoding="utf-8")
    source_hash = hashlib.sha256(_OVERRIDE_YAML.encode("utf-8")).hexdigest()

    rego = compile_to_rego(
        {
            "version": 1,
            "roles": {
                "default": {
                    "tools": {"web_search": {"mode": "allow"}},
                }
            },
        },
        source_hash=source_hash,
    )
    wasm = compile_to_wasm(rego).wasm

    (directory / "policy.rego").write_text(rego, encoding="utf-8")
    (directory / "policy.wasm").write_bytes(wasm)
    manifest = {
        "version": 1,
        "source": "policy.yaml",
        "source_hash": source_hash,
        "rego_hash": hashlib.sha256(rego.encode("utf-8")).hexdigest(),
        "wasm_hash": hashlib.sha256(wasm).hexdigest(),
    }
    (directory / "policy.bundle.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return directory


def _sign_bundle_dir(directory: Path, private_key_raw: bytes) -> None:
    """Write a detached signature over the manifest bytes in ``directory``."""
    manifest_bytes = (directory / "policy.bundle.json").read_bytes()
    sig = sign_bytes(manifest_bytes, private_key_raw)
    (directory / "policy.bundle.json.sig").write_bytes(sig)


def _write_pubkey(path: Path, public_key_raw: bytes) -> Path:
    """Write a base64url public key file (HEXGATE_BUNDLE_PUBKEY_PATH format)."""
    path.write_text(encode_key(public_key_raw) + "\n", encoding="utf-8")
    return path


def _clear_signature_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HEXGATE_BUNDLE_PUBKEY_PATH", raising=False)
    monkeypatch.delenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", raising=False)


# ---------------------------------------------------------------------------
# _local_policy_override (unit-level)
# ---------------------------------------------------------------------------


def test_override_returns_none_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No env var → no override. Pure pydantic path keeps running."""
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    assert loader._local_policy_override() is None


@needs_opa
def test_override_loads_bundle_when_env_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Env var pointing at a fresh bundle yields (bundle, source).

    Phase 8b returns both halves: the initial PolicyBundle for
    enforce_policy and the PolicySource for per-run refresh.
    """
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))

    out = loader._local_policy_override()
    assert out is not None
    bundle, source = out
    assert bundle is not None
    assert hasattr(source, "fetch")  # PolicySource protocol
    # The override prints a loud announcement to stderr.
    err = capsys.readouterr().err
    assert "HEXGATE_LOCAL_POLICY active" in err


def test_override_raises_for_missing_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pointing at a non-existent path fails loudly, not silently."""
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(tmp_path / "nope"))
    with pytest.raises(RuntimeError, match="expected a bundle"):
        loader._local_policy_override()


@needs_opa
def test_override_raises_for_tampered_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bundle whose hashes don't match its manifest is rejected at load time."""
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    # Tamper with the rego file after build — manifest still records the
    # original hash, so verify_integrity should reject this.
    (bundle_dir / "policy.rego").write_text(
        "package hexgate.policy\n# tampered\n", encoding="utf-8"
    )
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))
    with pytest.raises(RuntimeError, match="hash mismatch"):
        loader._local_policy_override()


def _write_local_agent_dir(agent_dir: Path, *, name: str) -> None:
    """Create a minimal local agent directory for loader integration tests."""
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "agent.yaml").write_text(
        "\n".join(
            [
                f"name: {name}",
                "model: gpt-5.4",
                "system_prompt: system.md",
                "tools:",
                "  - read_file",
                "policy: policy.yaml",
            ]
        ),
        encoding="utf-8",
    )
    (agent_dir / "policy.yaml").write_text(
        "\n".join(
            [
                "version: 1",
                "default_policy:",
                "  mode: deny",
                "tools:",
                "  read_file:",
                "    mode: allow",
            ]
        ),
        encoding="utf-8",
    )
    (agent_dir / "system.md").write_text(
        "You are a local test agent.", encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Integration with the agent loaders
# ---------------------------------------------------------------------------


@needs_opa
def test_load_local_agent_picks_up_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``load_local_agent`` forwards the bundle to ``enforce_policy`` when
    the env var is set, replacing the agent's own policy.yaml, AND attaches
    the local PolicySource so per-run refresh picks up later edits."""
    import types
    from typing import Any

    from hexgate.security import PolicyBundle

    _write_local_agent_dir(tmp_path / "example_agent", name="example_agent")
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))

    captured: dict[str, Any] = {}

    def fake_create_agent(**kwargs: Any) -> tuple[Any, str]:
        return types.SimpleNamespace(name="agent"), "handler"

    def fake_enforce_policy(
        _agent: Any,
        policy: Any,
        *,
        approval_handler: Any = None,
        source: Any = None,
        decision_observer: Any = None,
    ) -> Any:
        captured["policy"] = policy
        captured["source"] = source
        return _agent

    monkeypatch.setattr(loader, "create_agent", fake_create_agent)
    monkeypatch.setattr(loader, "enforce_policy", fake_enforce_policy)

    loader.load_local_agent("example_agent", base_dir=tmp_path)
    assert isinstance(captured["policy"], PolicyBundle), (
        "load_local_agent should have substituted the env-var bundle "
        f"for the on-disk policy.yaml; got {type(captured['policy'])}"
    )
    # The override source was threaded into enforce_policy so refresh_policy()
    # has something to call into on the next run.
    assert hasattr(captured["source"], "fetch")


@needs_opa
def test_load_local_agent_threads_decision_observer_under_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When ``HEXGATE_LOCAL_POLICY`` is set, the override path must still
    forward ``decision_observer`` to ``enforce_policy`` — otherwise the
    chat decision panel renders nothing once the env var is in play.

    Regression for the silent-drop bug in ``_apply_local_override`` where
    the override branch swallowed the observer kwarg while the
    no-override branch forwarded it.
    """
    import types
    from typing import Any

    _write_local_agent_dir(tmp_path / "example_agent", name="example_agent")
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))

    captured: dict[str, Any] = {}

    def fake_create_agent(**kwargs: Any) -> tuple[Any, str]:
        return types.SimpleNamespace(name="agent"), "handler"

    def fake_enforce_policy(
        _agent: Any,
        policy: Any,
        *,
        approval_handler: Any = None,
        source: Any = None,
        decision_observer: Any = None,
    ) -> Any:
        captured["decision_observer"] = decision_observer
        return _agent

    monkeypatch.setattr(loader, "create_agent", fake_create_agent)
    monkeypatch.setattr(loader, "enforce_policy", fake_enforce_policy)

    sentinel = lambda _event: None  # noqa: E731 — sentinel callable for identity check
    loader.load_local_agent(
        "example_agent", base_dir=tmp_path, decision_observer=sentinel
    )
    assert captured["decision_observer"] is sentinel, (
        "load_local_agent should forward decision_observer to enforce_policy "
        "even when HEXGATE_LOCAL_POLICY is set; got "
        f"{captured.get('decision_observer')!r}"
    )


@needs_opa
def test_load_local_agent_uses_original_policy_without_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sanity check: without the env var, the agent's own policy.yaml
    is used (not a PolicyBundle). Guards against my own dispatcher
    silently always preferring wasm."""
    from typing import Any
    from hexgate.security import AgentPolicy, PolicyBundle

    _write_local_agent_dir(tmp_path / "example_agent", name="example_agent")
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    captured: dict[str, Any] = {}

    def fake_create_agent(**kwargs: Any) -> tuple[str, str]:
        return "agent", "handler"

    def fake_enforce_policy(
        _agent: Any,
        policy: Any,
        *,
        approval_handler: Any = None,
        decision_observer: Any = None,
    ) -> Any:
        captured["policy"] = policy
        return _agent

    monkeypatch.setattr(loader, "create_agent", fake_create_agent)
    monkeypatch.setattr(loader, "enforce_policy", fake_enforce_policy)

    loader.load_local_agent("example_agent", base_dir=tmp_path)
    assert isinstance(captured["policy"], AgentPolicy)
    assert not isinstance(captured["policy"], PolicyBundle)


# ---------------------------------------------------------------------------
# Signature enforcement (HEXGATE_BUNDLE_PUBKEY_PATH / REQUIRE_SIGNATURE)
# ---------------------------------------------------------------------------


@needs_opa
def test_unsigned_bundle_loads_with_warning_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Default (no REQUIRE): an unsigned bundle loads but warns on stderr."""
    _clear_signature_env(monkeypatch)
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))

    bundle = loader._local_policy_override()
    assert bundle is not None
    err = capsys.readouterr().err
    assert "unsigned" in err


@needs_opa
def test_unsigned_bundle_refused_when_signature_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQUIRE_SIGNATURE=true rejects an unsigned bundle at load time.

    Phase 8b moved the check earlier: without a pubkey configured we
    can't verify ANYTHING, so the loader refuses at construction time
    with the pubkey-is-unset message rather than waiting to inspect
    the (always-missing) signature on the bundle.
    """
    _clear_signature_env(monkeypatch)
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "true")

    with pytest.raises(RuntimeError, match="no key to verify"):
        loader._local_policy_override()


@needs_opa
def test_signed_bundle_verifies_against_pubkey(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A signed bundle + matching pubkey loads cleanly, even with REQUIRE on."""
    _clear_signature_env(monkeypatch)
    private_raw, public_raw = generate_keypair()
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    _sign_bundle_dir(bundle_dir, private_raw)
    pubkey_path = _write_pubkey(tmp_path / "key.public", public_raw)

    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))
    monkeypatch.setenv("HEXGATE_BUNDLE_PUBKEY_PATH", str(pubkey_path))
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "true")

    out = loader._local_policy_override()
    assert out is not None
    bundle, _source = out
    assert bundle.is_signed
    err = capsys.readouterr().err
    assert "signed" in err


@needs_opa
def test_signed_bundle_wrong_pubkey_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A signature that doesn't match the configured pubkey is refused."""
    _clear_signature_env(monkeypatch)
    signer_priv, _ = generate_keypair()
    _, stranger_pub = generate_keypair()
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    _sign_bundle_dir(bundle_dir, signer_priv)
    pubkey_path = _write_pubkey(tmp_path / "key.public", stranger_pub)

    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))
    monkeypatch.setenv("HEXGATE_BUNDLE_PUBKEY_PATH", str(pubkey_path))

    with pytest.raises(RuntimeError, match="failed signature verification"):
        loader._local_policy_override()


@needs_opa
def test_signed_bundle_no_pubkey_required_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signed bundle + REQUIRE on + no pubkey configured → refuse (no key to check)."""
    _clear_signature_env(monkeypatch)
    private_raw, _ = generate_keypair()
    bundle_dir = _build_bundle_dir(tmp_path / "bundle")
    _sign_bundle_dir(bundle_dir, private_raw)

    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", str(bundle_dir))
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "true")

    with pytest.raises(RuntimeError, match="is unset"):
        loader._local_policy_override()
