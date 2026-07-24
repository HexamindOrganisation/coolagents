"""Tests for the local-files module loader (the SDK / dev seam)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexgate.security import load_local_modules


def _write(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_loads_guardrails_and_capabilities_with_correct_kinds(tmp_path):
    _write(
        tmp_path,
        "policies/guardrails/org.yaml",
        "default_policy: { mode: deny }\ntools:\n  delete_database: { mode: deny }\n",
    )
    _write(
        tmp_path,
        "policies/capabilities/payments.yaml",
        "tools:\n  refund_order: { mode: allow }\n",
    )

    guardrails, capabilities = load_local_modules(tmp_path)

    assert [g.name for g in guardrails] == ["org"]
    assert guardrails[0].kind == "guardrail"
    assert [c.name for c in capabilities] == ["payments"]
    assert capabilities[0].kind == "capability"
    assert "delete_database" in guardrails[0].policy.tools


def test_content_hash_is_stable_and_distinct(tmp_path):
    _write(tmp_path, "policies/capabilities/a.yaml", "tools:\n  x: { mode: allow }\n")
    _write(tmp_path, "policies/capabilities/b.yaml", "tools:\n  y: { mode: allow }\n")

    first = load_local_modules(tmp_path)[1]
    second = load_local_modules(tmp_path)[1]

    by_name = {m.name: m.content_hash for m in first}
    assert by_name == {m.name: m.content_hash for m in second}  # stable across runs
    assert by_name["a"] != by_name["b"]  # distinct content → distinct hash


def test_missing_directories_return_empty(tmp_path):
    guardrails, capabilities = load_local_modules(tmp_path)
    assert guardrails == []
    assert capabilities == []


def test_only_one_tier_present(tmp_path):
    _write(tmp_path, "policies/guardrails/g.yaml", "tools:\n  t: { mode: deny }\n")
    guardrails, capabilities = load_local_modules(tmp_path)
    assert len(guardrails) == 1
    assert capabilities == []


def test_invalid_module_names_the_offending_file(tmp_path):
    _write(
        tmp_path,
        "policies/capabilities/broken.yaml",
        "tools:\n  refund: { mode: allow, constraints: ['args.amount =< 1'] }\n",
    )
    with pytest.raises(ValueError, match="broken.yaml"):
        load_local_modules(tmp_path)
