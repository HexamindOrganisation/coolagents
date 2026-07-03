"""Tests for policy-in-code: PolicyBuilder, C constructors, assert_* helpers."""

from __future__ import annotations

import pytest

from hexgate.security import (
    AgentPolicy,
    C,
    PolicyBuilder,
    PolicySet,
    RolePolicyBuilder,
    assert_allows,
    assert_denies,
    assert_needs_approval,
)
from hexgate.security.constraints import ConstraintParseError


# ---------------------------------------------------------------------------
# C — typed constraint constructors emit the grammar strings the parser accepts
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("constraint", "text"),
    [
        (C("args.amount") <= 500, "args.amount <= 500"),
        (C("args.amount") < 500, "args.amount < 500"),
        (C("args.amount") >= 0, "args.amount >= 0"),
        (C("args.amount") > 0, "args.amount > 0"),
        (C("args.currency") == "USD", 'args.currency == "USD"'),
        (C("args.currency") != "USD", 'args.currency != "USD"'),
        (C("args.tier").is_in(["gold", "silver"]), 'args.tier in ["gold", "silver"]'),
        (C("args.priority").not_in(["urgent"]), 'args.priority not in ["urgent"]'),
        (C("args.max") >= C("args.min"), "args.max >= args.min"),  # cross-field
        (C("args.items").count() <= 3, "count(args.items) <= 3"),  # count
    ],
)
def test_c_emits_expected_string(constraint: object, text: str) -> None:
    assert str(constraint) == text


def test_c_and_constraint_repr() -> None:
    assert repr(C("args.x")) == "C('args.x')"
    assert repr(C("args.x") <= 5) == "C('args.x <= 5')"


def test_c_validates_eagerly_on_construction() -> None:
    # A path that can't parse fails at the call site, not later at enforcement.
    with pytest.raises(ConstraintParseError):
        C("args.0bad") <= 5


def test_c_strings_round_trip_through_model_validate() -> None:
    policy = AgentPolicy.model_validate(
        {
            "tools": {
                "refund": {
                    "mode": "allow",
                    "constraints": [str(C("args.amount") <= 500)],
                }
            }
        }
    )
    assert policy.tools["refund"].constraints == ["args.amount <= 500"]


# ---------------------------------------------------------------------------
# PolicyBuilder — builds a validated AgentPolicy
# ---------------------------------------------------------------------------


def test_builder_produces_agent_policy() -> None:
    policy = (
        PolicyBuilder(default="deny")
        .allow("web_search")
        .allow("refund_order", when=[C("args.amount") <= 500])
        .approve("edit_file")
        .deny("delete_all")
        .build()
    )
    assert isinstance(policy, AgentPolicy)
    assert policy.default_policy.mode == "deny"
    assert policy.tools["web_search"].mode == "allow"
    assert policy.tools["refund_order"].constraints == ["args.amount <= 500"]
    assert policy.tools["edit_file"].mode == "approval_required"
    assert policy.tools["delete_all"].mode == "deny"


def test_builder_when_accepts_single_constraint() -> None:
    policy = PolicyBuilder().allow("t", when=C("args.n") <= 1).build()
    assert policy.tools["t"].constraints == ["args.n <= 1"]


def test_builder_files_sets_file_scope() -> None:
    policy = (
        PolicyBuilder().files("read_file", allow=["src/**"], deny=["**/*.env"]).build()
    )
    tp = policy.tools["read_file"]
    assert tp.file_scope is not None
    assert tp.file_scope.allowed_paths == ["src/**"]
    assert tp.file_scope.denied_paths == ["**/*.env"]


def test_builder_rejects_bad_constraint_at_build() -> None:
    # A raw bad string (bypassing C) still fails via the model validator.
    with pytest.raises(Exception):
        PolicyBuilder().allow("t", when=["args.x =< 1"]).build()


# ---------------------------------------------------------------------------
# RolePolicyBuilder — builds a PolicySet
# ---------------------------------------------------------------------------


def test_role_builder_produces_policy_set() -> None:
    ps = (
        RolePolicyBuilder()
        .role("default", PolicyBuilder().allow("web_search"))
        .role("billing", PolicyBuilder().allow("refund_order"))
        .build()
    )
    assert isinstance(ps, PolicySet)
    assert ps.policy_for("billing").tools["refund_order"].mode == "allow"
    assert ps.policy_for("default").tools["web_search"].mode == "allow"


def test_role_builder_inheritance() -> None:
    ps = (
        RolePolicyBuilder()
        .role("base", PolicyBuilder().allow("read_file"), mixin=True)
        .role("default", PolicyBuilder().allow("web_search"), inherits=["base"])
        .build()
    )
    # default inherits read_file from the base mixin
    assert ps.policy_for("default").tools["read_file"].mode == "allow"


# ---------------------------------------------------------------------------
# assert_* helpers
# ---------------------------------------------------------------------------


def test_assert_helpers_on_agent_policy() -> None:
    policy = (
        PolicyBuilder()
        .allow("refund", when=[C("args.amount") <= 500])
        .approve("edit_file")
        .build()
    )
    assert_allows(policy, "refund", {"amount": 100})
    assert_denies(policy, "refund", {"amount": 999})
    assert_denies(policy, "unlisted_tool")
    assert_needs_approval(policy, "edit_file")


def test_assert_helpers_on_policy_set_with_role() -> None:
    ps = (
        RolePolicyBuilder()
        .role("default", PolicyBuilder().deny("refund_order"))
        .role("billing", PolicyBuilder().allow("refund_order"))
        .build()
    )
    assert_allows(ps, "refund_order", role="billing")
    assert_denies(ps, "refund_order", role="default")


def test_assert_allows_raises_on_wrong_outcome() -> None:
    policy = PolicyBuilder().deny("x").build()
    with pytest.raises(AssertionError, match="expected allow"):
        assert_allows(policy, "x")
