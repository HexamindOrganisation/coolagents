"""Tests for the local-files module loader (the SDK / dev seam)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexgate.security import load_local_modules


def _write(root: Path, rel: str, body: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_loads_boundaries_and_capabilities_with_correct_kinds(tmp_path):
    _write(
        tmp_path,
        "policies/boundaries/org.yaml",
        "default_policy: { mode: deny }\ntools:\n  delete_database: { mode: deny }\n",
    )
    _write(
        tmp_path,
        "policies/capabilities/payments.yaml",
        "tools:\n  refund_order: { mode: allow }\n",
    )

    boundaries, capabilities = load_local_modules(tmp_path)

    assert [g.name for g in boundaries] == ["org"]
    assert boundaries[0].kind == "boundary"
    assert [c.name for c in capabilities] == ["payments"]
    assert capabilities[0].kind == "capability"
    assert "delete_database" in boundaries[0].policy.tools


def test_content_hash_is_stable_and_distinct(tmp_path):
    _write(tmp_path, "policies/capabilities/a.yaml", "tools:\n  x: { mode: allow }\n")
    _write(tmp_path, "policies/capabilities/b.yaml", "tools:\n  y: { mode: allow }\n")

    first = load_local_modules(tmp_path)[1]
    second = load_local_modules(tmp_path)[1]

    by_name = {m.name: m.content_hash for m in first}
    assert by_name == {m.name: m.content_hash for m in second}  # stable across runs
    assert by_name["a"] != by_name["b"]  # distinct content → distinct hash


def test_missing_directories_return_empty(tmp_path):
    boundaries, capabilities = load_local_modules(tmp_path)
    assert boundaries == []
    assert capabilities == []


def test_only_one_tier_present(tmp_path):
    _write(tmp_path, "policies/boundaries/g.yaml", "tools:\n  t: { mode: deny }\n")
    boundaries, capabilities = load_local_modules(tmp_path)
    assert len(boundaries) == 1
    assert capabilities == []


def test_invalid_module_names_the_offending_file(tmp_path):
    _write(
        tmp_path,
        "policies/capabilities/broken.yaml",
        "tools:\n  refund: { mode: allow, constraints: ['args.amount =< 1'] }\n",
    )
    with pytest.raises(ValueError, match="broken.yaml"):
        load_local_modules(tmp_path)


def test_malformed_yaml_names_the_offending_file(tmp_path):
    _write(tmp_path, "policies/capabilities/bad.yaml", "tools: [unclosed\n")
    with pytest.raises(ValueError, match="bad.yaml"):
        load_local_modules(tmp_path)


def test_yml_extension_is_loaded(tmp_path):
    _write(tmp_path, "policies/boundaries/org.yml", "tools:\n  t: { mode: deny }\n")
    boundaries, _ = load_local_modules(tmp_path)
    assert [g.name for g in boundaries] == ["org"]


def test_unquoted_yaml_date_does_not_crash_hashing(tmp_path):
    """A YAML date scalar becomes datetime.date; hashing it must not raise."""
    _write(
        tmp_path,
        "policies/capabilities/dated.yaml",
        "consts: { window_start: 2026-01-01 }\ntools:\n  t: { mode: allow }\n",
    )
    _, capabilities = load_local_modules(tmp_path)
    assert len(capabilities) == 1
    assert capabilities[0].content_hash  # computed, no TypeError


def test_nested_same_stem_modules_stay_distinct(tmp_path):
    _write(
        tmp_path,
        "policies/capabilities/team_a/refunds.yaml",
        "tools:\n  r: { mode: allow }\n",
    )
    _write(
        tmp_path,
        "policies/capabilities/team_b/refunds.yaml",
        "tools:\n  s: { mode: allow }\n",
    )
    _, capabilities = load_local_modules(tmp_path)
    assert sorted(c.name for c in capabilities) == ["team_a/refunds", "team_b/refunds"]
