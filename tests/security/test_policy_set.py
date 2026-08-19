"""Tests for the role-aware policy bundle loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    PolicySet,
    PolicySetError,
    load_policy_map,
    load_policy_set,
)


# ---------------------------------------------------------------------------
# Construction from already-built models
# ---------------------------------------------------------------------------


def test_policy_set_requires_default_role() -> None:
    """A PolicySet without ``default`` is malformed."""
    with pytest.raises(PolicySetError, match="missing required 'default'"):
        PolicySet({"support": AgentPolicy()})


def test_policy_set_rejects_undefined_const_ref() -> None:
    """A constraint referencing an undefined constant is rejected at construction
    — the pydantic load path now agrees with the Rego compiler on validity,
    instead of loading cleanly then denying at runtime."""
    pol = AgentPolicy(
        consts={"cap": 500},
        tools={
            "t": BaseToolPolicy(mode="allow", constraints=["args.x == consts.gone"])
        },
    )
    with pytest.raises(PolicySetError, match="undefined constant consts.gone"):
        PolicySet({"default": pol})


def test_policy_set_accepts_defined_const_ref() -> None:
    pol = AgentPolicy(
        consts={"cap": 500},
        tools={"t": BaseToolPolicy(mode="allow", constraints=["args.x <= consts.cap"])},
    )
    PolicySet({"default": pol})  # no raise


def test_load_policy_set_from_agent_policy_wraps_in_default() -> None:
    """An :class:`AgentPolicy` becomes the single ``default`` role."""
    ap = AgentPolicy(tools={"refund": BaseToolPolicy(mode="allow")})
    ps = load_policy_set(ap)
    assert ps.roles == ["default"]
    assert ps.policy_for(None).tools["refund"].mode == "allow"


def test_load_policy_set_none_returns_deny_default() -> None:
    """``None`` yields a deny-by-default fallback role."""
    ps = load_policy_set(None)
    assert ps.policy_for(None).tools == {}


def test_load_policy_set_unknown_role_falls_back_to_default() -> None:
    """``policy_for("nope")`` returns the default policy."""
    ap = AgentPolicy(tools={"refund": BaseToolPolicy(mode="deny")})
    ps = load_policy_set(ap)
    assert ps.policy_for("nope").tools["refund"].mode == "deny"


# ---------------------------------------------------------------------------
# Directory loading + inheritance
# ---------------------------------------------------------------------------


def _write_policy(root: Path, name: str, body: str) -> None:
    (root / f"{name}.yaml").write_text(body)


def test_load_policy_set_from_directory(tmp_path: Path) -> None:
    """Each ``*.yaml`` in the directory becomes one role keyed by file stem."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(
        root,
        "default",
        "tools:\n  refund:\n    mode: deny\n",
    )
    _write_policy(
        root,
        "billing",
        "tools:\n  refund:\n    mode: allow\n    constraints:\n      - args.amount <= 500\n",
    )
    ps = load_policy_set(root)
    assert sorted(ps.roles) == ["billing", "default"]
    assert ps.policy_for("billing").tools["refund"].mode == "allow"
    assert ps.policy_for("billing").tools["refund"].constraints == [
        "args.amount <= 500"
    ]
    assert ps.policy_for("default").tools["refund"].mode == "deny"


def test_load_policy_set_resolves_inheritance(tmp_path: Path) -> None:
    """``inherits: [read_only]`` merges parent ``tools`` into the child."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(
        root,
        "read_only",
        "is_mixin: true\ntools:\n  view_orders:\n    mode: allow\n",
    )
    _write_policy(
        root,
        "default",
        "inherits: [read_only]\n",
    )
    _write_policy(
        root,
        "billing",
        "inherits: [read_only]\n"
        "tools:\n"
        "  refund:\n"
        "    mode: allow\n"
        "    constraints:\n"
        "      - args.amount <= 500\n",
    )
    ps = load_policy_set(root)
    # mixins don't surface as concrete roles
    assert "read_only" not in ps.roles
    # but their tools flow into children
    assert ps.policy_for("billing").tools["view_orders"].mode == "allow"
    assert ps.policy_for("billing").tools["refund"].mode == "allow"
    # default inherits read_only too
    assert ps.policy_for(None).tools["view_orders"].mode == "allow"


def test_load_policy_set_child_overrides_parent(tmp_path: Path) -> None:
    """A child role's own ``tools`` entries override the inherited ones."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(
        root,
        "read_only",
        "is_mixin: true\ntools:\n  refund:\n    mode: deny\n",
    )
    _write_policy(
        root,
        "default",
        "inherits: [read_only]\ntools:\n  refund:\n    mode: allow\n",
    )
    ps = load_policy_set(root)
    assert ps.policy_for(None).tools["refund"].mode == "allow"


def test_load_policy_set_child_explicit_deny_default_overrides_allow_parent(
    tmp_path: Path,
) -> None:
    """Explicit ``default_policy: { mode: deny }`` on a child must override a
    permissive parent default — equality against ``BaseToolPolicy()`` would
    silently fall through and yield ``allow`` (fail-open)."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(
        root,
        "open_base",
        "is_mixin: true\ndefault_policy:\n  mode: allow\n",
    )
    _write_policy(
        root,
        "default",
        "inherits: [open_base]\ndefault_policy:\n  mode: deny\n",
    )
    ps = load_policy_set(root)
    assert ps.policy_for(None).default_policy.mode == "deny"


def test_load_policy_set_detects_cyclic_inheritance(tmp_path: Path) -> None:
    """A cycle (A inherits B, B inherits A) raises with the chain spelled out."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(root, "default", "inherits: [a]\n")
    _write_policy(root, "a", "inherits: [b]\n")
    _write_policy(root, "b", "inherits: [a]\n")
    with pytest.raises(PolicySetError, match="cyclic inheritance"):
        load_policy_set(root)


def test_load_policy_set_rejects_inherit_from_unknown(tmp_path: Path) -> None:
    """Inheriting from a missing role is a clear error at load."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(root, "default", "inherits: [nope]\n")
    with pytest.raises(PolicySetError, match="not found"):
        load_policy_set(root)


def test_load_policy_set_empty_directory_raises(tmp_path: Path) -> None:
    """An empty ``policies/`` dir is a malformed agent."""
    root = tmp_path / "policies"
    root.mkdir()
    with pytest.raises(PolicySetError, match="no policy files found"):
        load_policy_set(root)


def test_load_policy_set_all_mixin_raises(tmp_path: Path) -> None:
    """A directory of only mixins has no concrete role to pick."""
    root = tmp_path / "policies"
    root.mkdir()
    _write_policy(
        root,
        "read_only",
        "is_mixin: true\ntools:\n  view_orders:\n    mode: allow\n",
    )
    with pytest.raises(PolicySetError, match="every policy.*is a mixin"):
        load_policy_set(root)


# ---------------------------------------------------------------------------
# load_policy_map — for cloud-fetched policies
# ---------------------------------------------------------------------------


def test_load_policy_map_aliases_to_default() -> None:
    """If the map has no ``default``, the chosen ``default=`` is aliased in."""
    ap = AgentPolicy(tools={"refund": BaseToolPolicy(mode="allow")})
    ps = load_policy_map({"billing": ap})
    # No 'default' in the source map but ps still satisfies the invariant
    assert "default" in ps.roles
    assert ps.policy_for(None).tools["refund"].mode == "allow"


def test_load_policy_map_drops_mixins() -> None:
    """Mixin policies in the map are dropped from the concrete role set."""
    mixin = AgentPolicy(
        is_mixin=True, tools={"view_orders": BaseToolPolicy(mode="allow")}
    )
    concrete = AgentPolicy(tools={"refund": BaseToolPolicy(mode="allow")})
    ps = load_policy_map({"read_only": mixin, "default": concrete})
    assert "read_only" not in ps.roles


def test_load_policy_map_empty_raises() -> None:
    with pytest.raises(PolicySetError, match="at least one role"):
        load_policy_map({})


def test_load_policy_map_only_mixins_raises() -> None:
    mixin = AgentPolicy(is_mixin=True, tools={"view": BaseToolPolicy(mode="allow")})
    with pytest.raises(PolicySetError, match="only mixins"):
        load_policy_map({"read_only": mixin})


def test_inferred_default_matches_across_load_paths(tmp_path: Path) -> None:
    """The same role set must resolve undefined names to the same policy whether
    it came from a directory or an inline dict — the pick is alphabetical in both."""
    roles = {
        "support": {"tools": {"lookup": {"mode": "allow"}}},
        "billing": {"tools": {"refund": {"mode": "allow"}}},
    }
    policies = tmp_path / "policies"
    policies.mkdir()
    for name, spec in roles.items():
        (policies / f"{name}.yaml").write_text(yaml.safe_dump(spec), encoding="utf-8")

    from_dir = load_policy_set(policies)
    # ``support`` first, so insertion order would have picked it over ``billing``.
    from_map = load_policy_map(
        {name: AgentPolicy.model_validate(spec) for name, spec in roles.items()}
    )

    assert from_dir.aliased_default == from_map.aliased_default == "billing"
    assert (
        from_dir.policy_for("undefined").tools.keys()
        == from_map.policy_for("undefined").tools.keys()
    )


def test_inferred_default_is_alphabetical_not_insertion_order() -> None:
    ps = load_policy_map(
        {
            "support": AgentPolicy.model_validate({"tools": {"a": {"mode": "allow"}}}),
            "billing": AgentPolicy.model_validate({"tools": {"b": {"mode": "allow"}}}),
        }
    )

    assert ps.aliased_default == "billing"
    assert "b" in ps.policy_for(None).tools


def test_explicit_default_argument_overrides_the_alphabetical_pick() -> None:
    ps = load_policy_map(
        {
            "support": AgentPolicy.model_validate({"tools": {"a": {"mode": "allow"}}}),
            "billing": AgentPolicy.model_validate({"tools": {"b": {"mode": "allow"}}}),
        },
        default="support",
    )

    assert ps.aliased_default is None  # deliberate, not inferred
    assert "a" in ps.policy_for(None).tools
