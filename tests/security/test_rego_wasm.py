"""Tests for the Rego → WASM compile step (M2 phase 3).

These tests shell out to a real ``opa`` binary; they're skipped if opa
isn't on PATH so the suite still passes in environments without it.
The bytes-level assertions confirm we end up with a valid wasm module
(magic header + non-trivial size), and the manifest assertions confirm
both entrypoints survived the round-trip into the bundle.
"""

from __future__ import annotations

import hashlib
import shutil

import pytest

from hexgate.security import compile_to_rego
from hexgate.security.rego_wasm import (
    DEFAULT_ENTRYPOINTS,
    OpaNotFoundError,
    WasmCompileError,
    _parse_opa_version,
    compile_to_wasm,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(
    not _OPA_AVAILABLE,
    reason="opa not on PATH — install via `brew install opa` to run these tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_DEMO_POLICY: dict = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "refund_order": {
                    "mode": "allow",
                    "constraints": ["args.amount <= 500"],
                }
            }
        }
    },
}


@pytest.fixture
def demo_rego() -> str:
    """Real Rego output from the phase 1 compiler — the input we care about."""
    return compile_to_rego(_DEMO_POLICY)


# ---------------------------------------------------------------------------
# compile_to_wasm
# ---------------------------------------------------------------------------


@needs_opa
def test_compile_to_wasm_returns_valid_module(demo_rego: str) -> None:
    """Bytes start with the WebAssembly magic header and are non-trivial."""
    artifact = compile_to_wasm(demo_rego)
    assert artifact.wasm.startswith(b"\x00asm")
    # A "real" compiled module is many KB — anything under 1KB means
    # opa wrote a stub or we lost most of the payload.
    assert len(artifact.wasm) > 1024


@needs_opa
def test_compile_to_wasm_is_deterministic(demo_rego: str) -> None:
    """Same Rego in → same WASM bytes out (lets us trust wasm_hash)."""
    a = compile_to_wasm(demo_rego)
    b = compile_to_wasm(demo_rego)
    assert hashlib.sha256(a.wasm).hexdigest() == hashlib.sha256(b.wasm).hexdigest()


@needs_opa
def test_compile_to_wasm_manifest_lists_decision_entrypoint(demo_rego: str) -> None:
    """Bundle manifest records the single structured-decision entrypoint."""
    artifact = compile_to_wasm(demo_rego)
    entries = [e["entrypoint"] for e in artifact.manifest.get("wasm", [])]
    assert set(DEFAULT_ENTRYPOINTS) <= set(entries)
    # And no stale legacy entrypoints leaked through from prior phases.
    assert "hexgate/policy/allow" not in entries
    assert "hexgate/policy/requires_approval" not in entries


@needs_opa
def test_compile_to_wasm_rejects_invalid_rego() -> None:
    """A syntactically broken Rego module surfaces opa's diagnostic."""
    with pytest.raises(WasmCompileError) as excinfo:
        compile_to_wasm("this is not rego")
    assert "opa build failed" in str(excinfo.value)


@needs_opa
def test_compile_to_wasm_requires_at_least_one_entrypoint(demo_rego: str) -> None:
    """An empty entrypoint tuple is a programmer error — fail fast."""
    with pytest.raises(ValueError, match="at least one entrypoint"):
        compile_to_wasm(demo_rego, entrypoints=())


# ---------------------------------------------------------------------------
# OPA discovery
# ---------------------------------------------------------------------------


def test_compile_to_wasm_complains_when_opa_missing(
    demo_rego: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mask opa from PATH and confirm we raise with an install hint."""
    monkeypatch.setenv("PATH", "/nonexistent")
    monkeypatch.delenv("HEXGATE_OPA_BIN", raising=False)
    with pytest.raises(OpaNotFoundError) as excinfo:
        compile_to_wasm(demo_rego)
    msg = str(excinfo.value)
    assert "opa not found" in msg
    assert "HEXGATE_OPA_BIN" in msg


def test_hexgate_opa_bin_pointing_at_missing_file_raises(
    demo_rego: str, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HEXGATE_OPA_BIN that doesn't exist gets a clear error (not a silent fall-through)."""
    monkeypatch.setenv("HEXGATE_OPA_BIN", str(tmp_path / "nope"))
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(OpaNotFoundError, match="does not exist"):
        compile_to_wasm(demo_rego)


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "stdout, expected",
    [
        ("Version: 1.16.2\nBuild Commit: x\n", (1, 16, 2)),
        ("Version: 0.60.0\n", (0, 60, 0)),
        ("Version: v1.16.2\n", (1, 16, 2)),
        ("Version: 1.16.2-rc1\n", (1, 16, 2)),
        ("garbage\n", None),
        ("Version: 1.0\n", None),  # not enough components
    ],
)
def test_parse_opa_version_handles_release_lines(stdout, expected) -> None:
    assert _parse_opa_version(stdout) == expected
