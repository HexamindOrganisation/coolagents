"""Tests for the local-files module loader (the SDK / dev seam)."""

from __future__ import annotations

from pathlib import Path

import pytest

from hexgate.security import load_local_modules, load_roles


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


# --- load_roles: the role-binding file (outside policies/) -----------------


def test_load_roles_reads_bindings(tmp_path):
    _write(
        tmp_path,
        "roles.yaml",
        "version: 1\nroles:\n  default: [read_only]\n  billing: [read_only, payments]\n",
    )
    assert load_roles(tmp_path) == {
        "default": ["read_only"],
        "billing": ["read_only", "payments"],
    }


def test_load_roles_missing_file_is_none(tmp_path):
    # No roles.yaml -> None (the all-compose signal), distinct from an empty
    # binding, and not an error.
    assert load_roles(tmp_path) is None


def test_load_roles_lives_outside_policies(tmp_path):
    # A roles.yaml placed under policies/ is NOT the binding file — discovery
    # only looks at the repo root, so this reads as "absent" (None).
    _write(tmp_path, "policies/roles.yaml", "roles:\n  default: [x]\n")
    assert load_roles(tmp_path) is None


def test_load_roles_present_but_empty_is_a_dict_not_none(tmp_path):
    # File exists but binds nothing -> {} (fail-closed), NOT None (all-compose).
    # A one-character typo must not silently widen access.
    _write(tmp_path, "roles.yaml", "version: 1\nroles: {}\n")
    assert load_roles(tmp_path) == {}


def test_load_roles_rejects_unknown_top_level_key(tmp_path):
    # A typo'd `role:` (instead of `roles:`) is a loud error, not a silent empty.
    _write(tmp_path, "roles.yaml", "role:\n  default: [x]\n")
    with pytest.raises(ValueError, match="unknown top-level key"):
        load_roles(tmp_path)


def test_load_roles_rejects_non_mapping_document(tmp_path):
    _write(tmp_path, "roles.yaml", "- default\n- billing\n")
    with pytest.raises(ValueError, match="top level must be a mapping"):
        load_roles(tmp_path)


def test_load_roles_rejects_non_list_value(tmp_path):
    _write(tmp_path, "roles.yaml", "roles:\n  default: read_only\n")
    with pytest.raises(ValueError, match="list of capability names"):
        load_roles(tmp_path)


def test_duplicate_module_name_across_extensions_is_rejected(tmp_path):
    # dup.yaml + dup.yml both resolve to name "dup" -> one would silently shadow
    # the other and drop its grants. Reject at load instead.
    _write(
        tmp_path, "policies/capabilities/dup.yaml", "tools:\n  view: { mode: allow }\n"
    )
    _write(
        tmp_path, "policies/capabilities/dup.yml", "tools:\n  refund: { mode: allow }\n"
    )
    with pytest.raises(ValueError, match="duplicate module name 'dup'"):
        load_local_modules(tmp_path)
