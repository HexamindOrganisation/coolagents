"""Cross-engine parity for policy *structure* features (not just constraints).

The pydantic engine (dev / fallback) and the compiled WASM engine (production
bundle) must decide identically for every input, or a policy tested in
``hexgate chat`` behaves differently once shipped as a signed bundle.

This suite asserts the full three-way outcome (``allow`` / ``deny`` /
``needs_approval``) matches — pydantic vs real ``opa``→``wasmtime`` — across:

  * ``default_policy`` (the catch-all for unlisted tools) — regression: the
    Rego compiler used to drop it, so ``default_policy: allow`` allowed on
    pydantic but denied on WASM.
  * ``approval_required`` mode, including the constraint-fails-→-deny path.
  * inheritance + mixins (the *resolved* policy must compile + evaluate the
    same on both engines).

opa is required; the module skips cleanly without it.
"""

from __future__ import annotations

import functools
import shutil

import pytest

from hexgate.security import WasmPolicy, compile_to_wasm, load_policy_set_from_dict
from hexgate.security.policy import evaluate_tool_call
from hexgate.security.rego import compile_to_rego

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")


def _py_outcome(policy: dict, role: str | None, tool: str, args: dict) -> str:
    ps = load_policy_set_from_dict(policy)
    return evaluate_tool_call(ps.policy_for(role), tool, args).outcome.value


@functools.lru_cache(maxsize=None)
def _wasm_bytes(rego: str) -> bytes:
    return compile_to_wasm(rego).wasm


def _wasm_outcome(policy: dict, role: str | None, tool: str, args: dict) -> str:
    wasm = _wasm_bytes(compile_to_rego(policy))
    d = WasmPolicy.from_bytes(wasm).decide(role=role, tool=tool, args=args)
    if d.allow:
        return "allow"
    if d.requires_approval:
        return "needs_approval"
    return "deny"


def _assert_parity(
    policy: dict, role: str | None, tool: str, args: dict, expect: str
) -> None:
    py = _py_outcome(policy, role, tool, args)
    wasm = _wasm_outcome(policy, role, tool, args)
    assert py == wasm, f"engine divergence {role}/{tool}/{args}: py={py} wasm={wasm}"
    assert py == expect, f"wrong outcome {role}/{tool}/{args}: {py} (want {expect})"


# ---------------------------------------------------------------------------
# default_policy — the catch-all for tools not explicitly listed
# ---------------------------------------------------------------------------

_DEFAULT_ALLOW = {
    "version": 1,
    "roles": {
        "default": {
            "default_policy": {"mode": "allow"},
            "tools": {
                "blocked": {"mode": "deny"},
                "gated": {"mode": "approval_required"},
                "checked": {"mode": "allow", "constraints": ["args.n <= 10"]},
            },
        }
    },
}

_DEFAULT_ALLOW_CONSTRAINED = {
    "version": 1,
    "roles": {
        "default": {
            "default_policy": {"mode": "allow", "constraints": ['args.env == "dev"']},
            "tools": {"listed": {"mode": "deny"}},
        }
    },
}

_DEFAULT_APPROVAL = {
    "version": 1,
    "roles": {
        "default": {"default_policy": {"mode": "approval_required"}, "tools": {}}
    },
}


@pytest.mark.parametrize(
    ("policy", "tool", "args", "expect"),
    [
        # default_policy: allow → unlisted tools inherit allow on BOTH engines
        (_DEFAULT_ALLOW, "totally_unknown", {}, "allow"),
        (_DEFAULT_ALLOW, "another_unknown", {"x": 1}, "allow"),
        # explicitly-listed tools keep their own policy, not the default
        (_DEFAULT_ALLOW, "blocked", {}, "deny"),
        (_DEFAULT_ALLOW, "gated", {}, "needs_approval"),
        (_DEFAULT_ALLOW, "checked", {"n": 5}, "allow"),
        (_DEFAULT_ALLOW, "checked", {"n": 50}, "deny"),
        # default_policy: allow WITH constraints, applied to unlisted tools
        (_DEFAULT_ALLOW_CONSTRAINED, "unlisted", {"env": "dev"}, "allow"),
        (_DEFAULT_ALLOW_CONSTRAINED, "unlisted", {"env": "prod"}, "deny"),
        (_DEFAULT_ALLOW_CONSTRAINED, "unlisted", {}, "deny"),  # missing → fail closed
        (
            _DEFAULT_ALLOW_CONSTRAINED,
            "listed",
            {"env": "dev"},
            "deny",
        ),  # listed deny wins
        # default_policy: approval_required → unlisted tools require approval
        (_DEFAULT_APPROVAL, "anything", {}, "needs_approval"),
    ],
)
def test_default_policy_parity(
    policy: dict, tool: str, args: dict, expect: str
) -> None:
    _assert_parity(policy, "default", tool, args, expect)


def test_implicit_default_deny_parity() -> None:
    """No default_policy set → deny-by-default for unlisted tools, both engines."""
    policy = {"version": 1, "roles": {"default": {"tools": {"a": {"mode": "allow"}}}}}
    _assert_parity(policy, "default", "a", {}, "allow")
    _assert_parity(policy, "default", "unlisted", {}, "deny")


# ---------------------------------------------------------------------------
# approval_required — full three-way outcome (constraint-fail must be DENY)
# ---------------------------------------------------------------------------

_APPROVAL = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "plain": {"mode": "approval_required"},
                "credit": {
                    "mode": "approval_required",
                    "constraints": ["args.amount <= 500"],
                },
            }
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("plain", {}, "needs_approval"),
        ("credit", {"amount": 100}, "needs_approval"),  # constraint passes → approval
        ("credit", {"amount": 999}, "deny"),  # constraint FAILS → deny, not approval
        ("credit", {}, "deny"),  # missing arg → deny
    ],
)
def test_approval_outcome_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_APPROVAL, "default", tool, args, expect)


# ---------------------------------------------------------------------------
# Inheritance + mixins — the *resolved* policy must agree across engines
# ---------------------------------------------------------------------------

_INHERITED = {
    "version": 1,
    "roles": {
        "read_only": {  # mixin — never a concrete role
            "is_mixin": True,
            "tools": {
                "read_file": {"mode": "allow"},
                "web_search": {"mode": "allow"},
            },
        },
        "default": {
            "inherits": ["read_only"],
            "tools": {"read_file": {"mode": "deny"}},  # override the mixin's allow
        },
        "billing": {
            "inherits": ["read_only"],
            "tools": {
                "refund": {"mode": "allow", "constraints": ["args.amount <= 500"]},
                "web_search": {"mode": "approval_required"},  # override allow→approval
            },
        },
    },
}


@pytest.mark.parametrize(
    ("role", "tool", "args", "expect"),
    [
        # inherited tool present on both engines
        ("billing", "read_file", {}, "allow"),  # from mixin, not overridden
        # child override wins over the inherited mixin entry
        ("default", "read_file", {}, "deny"),
        ("default", "web_search", {}, "allow"),  # inherited, not overridden
        ("billing", "web_search", {}, "needs_approval"),  # overridden to approval
        # role-specific tool with constraint
        ("billing", "refund", {"amount": 100}, "allow"),
        ("billing", "refund", {"amount": 999}, "deny"),
        # unknown role falls back to the `default` role's policy on BOTH engines
        # (compiler-side role fallback — see hexgate/security/rego._role_guard)
        ("typo_role", "web_search", {}, "allow"),  # default allows web_search
        ("typo_role", "read_file", {}, "deny"),  # default denies read_file
        ("another_unknown", "web_search", {}, "allow"),
    ],
)
def test_inheritance_parity(role: str, tool: str, args: dict, expect: str) -> None:
    _assert_parity(_INHERITED, role, tool, args, expect)


def test_none_role_falls_back_to_default_both_engines() -> None:
    """A null caller role resolves to the default policy on both engines."""
    _assert_parity(_INHERITED, None, "web_search", {}, "allow")
    _assert_parity(_INHERITED, None, "read_file", {}, "deny")


# ---------------------------------------------------------------------------
# Cross-field refs (2a) + count() (2d) — parity through real opa->wasmtime
# ---------------------------------------------------------------------------

_OPERAND_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "range": {"mode": "allow", "constraints": ["args.max >= args.min"]},
                "batch": {"mode": "allow", "constraints": ["count(args.items) <= 3"]},
                "combo": {
                    "mode": "allow",
                    "constraints": ["args.hi >= args.lo", "count(args.tags) <= 2"],
                },
            }
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        # cross-field comparison
        ("range", {"max": 10, "min": 5}, "allow"),
        ("range", {"max": 5, "min": 5}, "allow"),  # equal
        ("range", {"max": 3, "min": 5}, "deny"),
        ("range", {"max": 10}, "deny"),  # right ref missing → fail closed
        ("range", {"min": 5}, "deny"),  # left ref missing
        ("range", {}, "deny"),
        # count()
        ("batch", {"items": [1, 2, 3]}, "allow"),
        ("batch", {"items": [1, 2, 3, 4]}, "deny"),
        ("batch", {"items": []}, "allow"),  # empty → 0
        ("batch", {}, "deny"),  # missing → fail closed
        # both together (AND)
        ("combo", {"hi": 9, "lo": 1, "tags": ["a"]}, "allow"),
        ("combo", {"hi": 1, "lo": 9, "tags": ["a"]}, "deny"),  # first fails
        ("combo", {"hi": 9, "lo": 1, "tags": ["a", "b", "c"]}, "deny"),  # second fails
    ],
)
def test_operand_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_OPERAND_POLICY, "default", tool, args, expect)


# ---------------------------------------------------------------------------
# String functions (2b) — parity incl. the re.search vs regex.match hazard
# ---------------------------------------------------------------------------

_FUNC_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "sw": {"mode": "allow", "constraints": ['startswith(args.id, "inv_")']},
                "ew": {"mode": "allow", "constraints": ['endswith(args.f, ".md")']},
                "ct": {"mode": "allow", "constraints": ['contains(args.s, "ab")']},
                "rx": {"mode": "allow", "constraints": ['matches(args.v, "[0-9]+")']},
                "rxa": {
                    "mode": "allow",
                    "constraints": ['matches(args.v, "^inv_[0-9]+$")'],
                },
            }
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("sw", {"id": "inv_9"}, "allow"),
        ("sw", {"id": "x"}, "deny"),
        ("sw", {"id": 9}, "deny"),  # non-string
        ("sw", {}, "deny"),  # missing
        ("ew", {"f": "a.md"}, "allow"),
        ("ew", {"f": "a.txt"}, "deny"),
        ("ct", {"s": "xabx"}, "allow"),
        ("ct", {"s": "xyz"}, "deny"),
        # the hazard: matches is unanchored on BOTH engines (search, not fullmatch)
        ("rx", {"v": "abc123"}, "allow"),
        ("rx", {"v": "abc"}, "deny"),
        ("rxa", {"v": "inv_9"}, "allow"),
        ("rxa", {"v": "xinv_9"}, "deny"),  # anchors respected identically
    ],
)
def test_function_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_FUNC_POLICY, "default", tool, args, expect)
