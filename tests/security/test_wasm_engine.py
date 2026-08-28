"""Tests for the wasmtime-py policy evaluator (M2 phase 4).

These tests need a real ``opa`` binary on PATH so we can compile fresh
WASM bundles from YAML fixtures. They're skipped automatically in
environments without opa. The compiler step itself is exercised in
``test_rego_wasm`` — these tests focus on the evaluator's behaviour.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from hexgate.security import (
    RegoVerdict,
    WasmEvalError,
    WasmPolicy,
    compile_to_rego,
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


_DEMO_POLICY: dict[str, Any] = {
    "version": 1,
    "roles": {
        "billing": {
            "tools": {
                "refund_order": {
                    "mode": "allow",
                    "constraints": [
                        "args.amount <= 500",
                        'args.currency in ["USD", "EUR"]',
                    ],
                },
                "web_search": {"mode": "allow"},
            }
        },
        "support": {
            "tools": {
                "issue_credit": {
                    "mode": "approval_required",
                    "constraints": ["args.amount <= 100"],
                },
            }
        },
    },
}


@pytest.fixture(scope="module")
def demo_wasm() -> bytes:
    """Real compiled bundle — built once and reused across tests."""
    if not _OPA_AVAILABLE:
        pytest.skip("opa not on PATH")
    rego = compile_to_rego(_DEMO_POLICY)
    return compile_to_wasm(rego).wasm


@pytest.fixture
def policy(demo_wasm: bytes) -> WasmPolicy:
    """A fresh WasmPolicy per test — wasmtime stores aren't shareable."""
    return WasmPolicy.from_bytes(demo_wasm)


# ---------------------------------------------------------------------------
# decide() — happy paths
# ---------------------------------------------------------------------------


@needs_opa
def test_allow_when_all_constraints_satisfied(policy: WasmPolicy) -> None:
    d = policy.decide(
        role="billing", tool="refund_order", args={"amount": 200, "currency": "USD"}
    )
    assert d == RegoVerdict(allow=True, requires_approval=False, violations=[])


@needs_opa
def test_allow_constraint_free_tool(policy: WasmPolicy) -> None:
    """Tools with no constraints allow on any args."""
    d = policy.decide(role="billing", tool="web_search", args={})
    assert d.allow is True
    assert d.violations == []


# ---------------------------------------------------------------------------
# decide() — deny paths
# ---------------------------------------------------------------------------


@needs_opa
def test_deny_one_constraint_violated(policy: WasmPolicy) -> None:
    d = policy.decide(
        role="billing", tool="refund_order", args={"amount": 700, "currency": "USD"}
    )
    assert d.allow is False
    assert d.violations == ["args.amount <= 500"]


@needs_opa
def test_deny_multiple_constraints_violated(policy: WasmPolicy) -> None:
    """When several constraints fail, all show up in violations."""
    d = policy.decide(
        role="billing", tool="refund_order", args={"amount": 700, "currency": "GBP"}
    )
    assert d.allow is False
    assert set(d.violations) == {
        "args.amount <= 500",
        'args.currency in ["USD", "EUR"]',
    }


@needs_opa
def test_deny_by_absence_of_allow_rule(policy: WasmPolicy) -> None:
    """Unknown role/tool combos get a clean deny with empty violations —
    the policy never had a rule for them, so there's nothing to violate."""
    d = policy.decide(role="billing", tool="not_a_tool", args={})
    assert d == RegoVerdict(allow=False, requires_approval=False, violations=[])


# ---------------------------------------------------------------------------
# decide() — approval_required
# ---------------------------------------------------------------------------


@needs_opa
def test_approval_required_when_constraints_pass(policy: WasmPolicy) -> None:
    """approval_required is its own boolean — allow stays false."""
    d = policy.decide(role="support", tool="issue_credit", args={"amount": 50})
    assert d.allow is False
    assert d.requires_approval is True
    assert d.violations == []


@needs_opa
def test_approval_required_with_failed_constraint_falls_to_deny(
    policy: WasmPolicy,
) -> None:
    """When the approval-gated tool's constraints fail, the rule never fires,
    so approval stays false and violations carries the failed constraint."""
    d = policy.decide(role="support", tool="issue_credit", args={"amount": 500})
    assert d.allow is False
    assert d.requires_approval is False
    assert d.violations == ["args.amount <= 100"]


# ---------------------------------------------------------------------------
# Heap discipline across multiple decisions
# ---------------------------------------------------------------------------


@needs_opa
def test_repeated_decisions_are_deterministic(policy: WasmPolicy) -> None:
    """Heap reset between calls — same input → same output every time."""
    args = {"amount": 700, "currency": "USD"}
    first = policy.decide(role="billing", tool="refund_order", args=args)
    for _ in range(10):
        again = policy.decide(role="billing", tool="refund_order", args=args)
        assert again == first


@needs_opa
def test_decisions_do_not_leak_state(policy: WasmPolicy) -> None:
    """A deny followed by an allow returns the allow correctly —
    no residue from the prior decision's violations."""
    bad = policy.decide(
        role="billing", tool="refund_order", args={"amount": 700, "currency": "USD"}
    )
    good = policy.decide(
        role="billing", tool="refund_order", args={"amount": 200, "currency": "USD"}
    )
    assert bad.allow is False and bad.violations
    assert good.allow is True and good.violations == []


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_from_bytes_rejects_non_wasm() -> None:
    with pytest.raises(WasmEvalError, match="not a WebAssembly module"):
        WasmPolicy.from_bytes(b"this is not wasm")


@needs_opa
def test_from_bundle_path_loads_from_directory(
    demo_wasm: bytes, tmp_path: Path
) -> None:
    """A directory containing exactly one .wasm gets auto-resolved."""
    (tmp_path / "policy.wasm").write_bytes(demo_wasm)
    p = WasmPolicy.from_bundle_path(tmp_path)
    d = p.decide(role="billing", tool="web_search", args={})
    assert d.allow is True


@needs_opa
def test_from_bundle_path_loads_from_explicit_file(
    demo_wasm: bytes, tmp_path: Path
) -> None:
    """A direct .wasm path works too — no auto-glob, no guessing."""
    f = tmp_path / "explicit.wasm"
    f.write_bytes(demo_wasm)
    p = WasmPolicy.from_bundle_path(f)
    assert p.decide(role="billing", tool="web_search", args={}).allow is True


def test_from_bundle_path_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(WasmEvalError, match="no such file"):
        WasmPolicy.from_bundle_path(tmp_path / "missing.wasm")


def test_from_bundle_path_rejects_empty_directory(tmp_path: Path) -> None:
    with pytest.raises(WasmEvalError, match="no .wasm file"):
        WasmPolicy.from_bundle_path(tmp_path)


@needs_opa
def test_from_bundle_path_rejects_ambiguous_directory(
    demo_wasm: bytes, tmp_path: Path
) -> None:
    """Two .wasm files in one dir → fail rather than guess."""
    (tmp_path / "a.wasm").write_bytes(demo_wasm)
    (tmp_path / "b.wasm").write_bytes(demo_wasm)
    with pytest.raises(WasmEvalError, match="multiple .wasm files"):
        WasmPolicy.from_bundle_path(tmp_path)


@needs_opa
def test_unknown_entrypoint_raises_with_helpful_listing(demo_wasm: bytes) -> None:
    with pytest.raises(WasmEvalError, match="entrypoint .* not in bundle") as exc:
        WasmPolicy.from_bytes(demo_wasm, entrypoint="hexgate/policy/no_such_rule")
    # The error names what *is* available so the caller can self-correct.
    assert "hexgate/policy/decision" in str(exc.value)


# ---------------------------------------------------------------------------
# from_bytes_cached — content-addressed cache by wasm_hash (Phase 8a)
# ---------------------------------------------------------------------------


@needs_opa
def test_from_bytes_cached_reuses_instance_on_same_hash(demo_wasm: bytes) -> None:
    """Two loads of the same hash reuse one wasmtime store — the whole point.

    Without this, every policy refresh would re-instantiate wasmtime even
    when the bundle hadn't actually changed.
    """
    import hashlib

    from hexgate.security.wasm_engine import _wasm_policy_cache

    _wasm_policy_cache.clear()
    h = hashlib.sha256(demo_wasm).hexdigest()
    a = WasmPolicy.from_bytes_cached(demo_wasm, h)
    b = WasmPolicy.from_bytes_cached(demo_wasm, h)
    assert a is b
    # And the cached instance still evaluates correctly.
    assert a.decide(role="billing", tool="web_search", args={}).allow is True


@needs_opa
def test_from_bytes_cached_distinguishes_hashes(demo_wasm: bytes) -> None:
    """Different hash → different cached instance (no false collisions)."""
    import hashlib

    from hexgate.security import compile_to_rego, compile_to_wasm
    from hexgate.security.wasm_engine import _wasm_policy_cache

    _wasm_policy_cache.clear()
    other_rego = compile_to_rego(
        {"version": 1, "roles": {"default": {"tools": {"fetch": {"mode": "allow"}}}}}
    )
    other_wasm = compile_to_wasm(other_rego).wasm

    h1 = hashlib.sha256(demo_wasm).hexdigest()
    h2 = hashlib.sha256(other_wasm).hexdigest()
    p1 = WasmPolicy.from_bytes_cached(demo_wasm, h1)
    p2 = WasmPolicy.from_bytes_cached(other_wasm, h2)
    assert p1 is not p2
    assert h1 != h2
