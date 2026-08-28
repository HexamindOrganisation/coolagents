"""Parity tests for :func:`authorize_tool_call_wasm` vs the pydantic engine.

The WASM-backed authorizer must raise the same exceptions on the same
inputs as the pydantic-backed one — otherwise the upcoming enforcement
cutover (M2 phase 6) would silently change agent behaviour.
"""

from __future__ import annotations

import hashlib
import shutil

import pytest
import yaml

from hexgate.security import (
    ApprovalRequiredError,
    PolicyBundle,
    PolicyDeniedError,
    authorize_tool_call,
    authorize_tool_call_wasm,
    compile_to_rego,
    compile_to_wasm,
    load_policy_set_from_dict,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(
    not _OPA_AVAILABLE,
    reason="opa not on PATH — install via `brew install opa` to run these tests",
)


_DEMO_POLICY_YAML = """\
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
      issue_credit:
        mode: approval_required
        constraints:
          - args.amount <= 100
"""

_PAYLOAD = yaml.safe_load(_DEMO_POLICY_YAML)


@pytest.fixture(scope="module")
def bundle(tmp_path_factory: pytest.TempPathFactory) -> PolicyBundle:
    """Build a real bundle once and reuse it across the table."""
    if not _OPA_AVAILABLE:
        pytest.skip("opa not on PATH")
    tmp = tmp_path_factory.mktemp("authorize_wasm")
    yaml_path = tmp / "policy.yaml"
    yaml_path.write_text(_DEMO_POLICY_YAML, encoding="utf-8")
    source_hash = hashlib.sha256(_DEMO_POLICY_YAML.encode("utf-8")).hexdigest()
    rego = compile_to_rego(_PAYLOAD, source_hash=source_hash)
    wasm = compile_to_wasm(rego).wasm
    # Assemble the dataclass directly — we don't need the manifest for these tests.
    return PolicyBundle(
        source_path=yaml_path,
        rego_text=rego,
        wasm_bytes=wasm,
        manifest={"wasm_hash": hashlib.sha256(wasm).hexdigest()},
    )


# Each row: (role, tool, args, expected_exception_type_or_None)
_CASES: list[tuple[str, str, dict, type | None]] = [
    # allow paths
    ("billing", "refund_order", {"amount": 200}, None),
    ("billing", "web_search", {}, None),
    ("default", "web_search", {}, None),
    # constraint-fail denies
    ("billing", "refund_order", {"amount": 700}, PolicyDeniedError),
    # deny by mode
    ("default", "refund_order", {"amount": 5}, PolicyDeniedError),
    # approval_required
    ("billing", "issue_credit", {"amount": 50}, ApprovalRequiredError),
    # approval_required with failed constraint → deny (no rule fires)
    ("billing", "issue_credit", {"amount": 500}, PolicyDeniedError),
]


@needs_opa
@pytest.mark.parametrize(("role", "tool", "args", "expected_exc"), _CASES)
def test_wasm_authorizer_matches_pydantic(
    bundle: PolicyBundle,
    role: str,
    tool: str,
    args: dict,
    expected_exc: type | None,
) -> None:
    """Same input → same outcome from both engines."""
    # Pydantic side
    ps = load_policy_set_from_dict(_PAYLOAD)
    py_policy = ps.policy_for(role)
    py_exc: type | None = None
    try:
        authorize_tool_call(py_policy, tool, args)
    except (PolicyDeniedError, ApprovalRequiredError) as e:
        py_exc = type(e)
    assert py_exc is expected_exc, (
        f"pydantic disagrees for {role}/{tool}/{args}: {py_exc}"
    )

    # WASM side
    wasm_exc: type | None = None
    try:
        authorize_tool_call_wasm(bundle, role, tool, args)
    except (PolicyDeniedError, ApprovalRequiredError) as e:
        wasm_exc = type(e)
    assert wasm_exc is expected_exc, (
        f"wasm disagrees for {role}/{tool}/{args}: {wasm_exc}"
    )


@needs_opa
def test_wasm_deny_message_surfaces_violations(bundle: PolicyBundle) -> None:
    """On constraint failure, the error string carries the violated constraint."""
    with pytest.raises(PolicyDeniedError) as excinfo:
        authorize_tool_call_wasm(bundle, "billing", "refund_order", {"amount": 700})
    assert "args.amount <= 500" in str(excinfo.value)


@needs_opa
def test_wasm_deny_by_absence_explains_no_rule(bundle: PolicyBundle) -> None:
    """When deny is by no-matching-rule, the message is helpful, not empty."""
    with pytest.raises(PolicyDeniedError) as excinfo:
        authorize_tool_call_wasm(bundle, "default", "refund_order", {"amount": 5})
    assert "no allow rule matched" in str(excinfo.value)
