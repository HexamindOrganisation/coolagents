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
from hexgate.security.rego import compile_to_rego

pytestmark = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")


def _py_outcome(policy: dict, role: str | None, tool: str, args: dict) -> str:
    ps = load_policy_set_from_dict(policy)
    # Route through PolicySet.evaluate (the real engine entry) so role/tool are
    # threaded into the constraint context, matching what the runtime does.
    return ps.evaluate(role=role, tool=tool, args=args).outcome.value


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
                "litleft": {"mode": "allow", "constraints": ['"USD" == args.currency']},
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
        # string literal on the left of the comparison
        ("litleft", {"currency": "USD"}, "allow"),
        ("litleft", {"currency": "EUR"}, "deny"),
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


# ---------------------------------------------------------------------------
# Quantifiers (2e) — every / any over list args, incl. nesting, via real opa
# ---------------------------------------------------------------------------

_QUANT_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "ev": {
                    "mode": "allow",
                    "constraints": ['every(args.files, startswith(., "/tmp/"))'],
                },
                "an": {
                    "mode": "allow",
                    "constraints": ['any(args.roles, . == "admin")'],
                },
                "sf": {
                    "mode": "allow",
                    "constraints": ["every(args.items, .price <= 100)"],
                },
                "ne": {
                    "mode": "allow",
                    "constraints": ['every(args.groups, any(.members, . == "admin"))'],
                },
            }
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("ev", {"files": ["/tmp/a", "/tmp/b"]}, "allow"),
        ("ev", {"files": ["/tmp/a", "/etc/b"]}, "deny"),
        ("ev", {"files": []}, "allow"),  # every over [] is vacuously true
        ("ev", {"files": "notalist"}, "deny"),  # non-list fails closed
        ("ev", {}, "deny"),  # missing collection
        ("an", {"roles": ["user", "admin"]}, "allow"),
        ("an", {"roles": ["user"]}, "deny"),
        ("an", {"roles": []}, "deny"),  # any over [] is false
        ("sf", {"items": [{"price": 50}, {"price": 80}]}, "allow"),
        ("sf", {"items": [{"price": 200}]}, "deny"),
        ("sf", {"items": [{"name": "x"}]}, "deny"),  # element sub-field missing
        (
            "ne",
            {"groups": [{"members": ["a", "admin"]}, {"members": ["admin"]}]},
            "allow",
        ),
        ("ne", {"groups": [{"members": ["a"]}, {"members": ["admin"]}]}, "deny"),
    ],
)
def test_quantifier_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_QUANT_POLICY, "default", tool, args, expect)


# ---------------------------------------------------------------------------
# role / tool facts in constraints (2g) — parity with Rego input.role/input.tool
# ---------------------------------------------------------------------------

_CTX_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "t": {"mode": "allow", "constraints": ['role == "admin"']},
                "r": {"mode": "allow", "constraints": ['tool == "r"']},
            }
        },
        "admin": {
            "tools": {"t": {"mode": "allow", "constraints": ['role == "admin"']}}
        },
    },
}


@pytest.mark.parametrize(
    ("role", "tool", "args", "expect"),
    [
        ("admin", "t", {}, "allow"),  # role == "admin" holds
        ("default", "t", {}, "deny"),  # role != "admin"
        (None, "t", {}, "deny"),  # null role
        ("default", "r", {}, "allow"),  # tool == "r" holds (tool from the call)
    ],
)
def test_role_tool_fact_parity(role: str, tool: str, args: dict, expect: str) -> None:
    _assert_parity(_CTX_POLICY, role, tool, args, expect)


# ---------------------------------------------------------------------------
# Named constants (2f) — consts.<name>, incl. shared via a mixin
# ---------------------------------------------------------------------------

_CONST_POLICY = {
    "version": 1,
    "roles": {
        # shared constants live in a mixin and are inherited (the DRY pattern)
        "base": {
            "is_mixin": True,
            "consts": {
                "max_refund": 500,
                "prod_env": "production",
                "repos": ["a", "b"],
            },
        },
        "default": {
            "inherits": ["base"],
            "tools": {
                "refund": {
                    "mode": "allow",
                    "constraints": ["args.amount <= consts.max_refund"],
                },
                "deploy": {
                    "mode": "allow",
                    "constraints": ["args.env == consts.prod_env"],
                },
                "pr": {"mode": "allow", "constraints": ["args.repo in consts.repos"]},
            },
        },
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("refund", {"amount": 100}, "allow"),
        ("refund", {"amount": 999}, "deny"),
        ("deploy", {"env": "production"}, "allow"),
        ("deploy", {"env": "dev"}, "deny"),
        ("pr", {"repo": "a"}, "allow"),
        ("pr", {"repo": "z"}, "deny"),
    ],
)
def test_const_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_CONST_POLICY, "default", tool, args, expect)
