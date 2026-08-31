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


def _py_outcome(
    policy: dict,
    role: str | None,
    tool: str,
    args: dict,
    attributes: dict | None,
    run: dict | None = None,
) -> str:
    ps = load_policy_set_from_dict(policy)
    # Route through PolicySet.evaluate (the real engine entry) so role/tool are
    # threaded into the constraint context, matching what the runtime does.
    return ps.evaluate(
        role=role, tool=tool, args=args, attributes=attributes, run=run
    ).outcome.value


@functools.lru_cache(maxsize=None)
def _wasm_bytes(rego: str) -> bytes:
    return compile_to_wasm(rego).wasm


def _wasm_outcome(
    policy: dict,
    role: str | None,
    tool: str,
    args: dict,
    attributes: dict | None,
    run: dict | None = None,
) -> str:
    wasm = _wasm_bytes(compile_to_rego(policy))
    d = WasmPolicy.from_bytes(wasm).decide(
        role=role, tool=tool, args=args, ctx=attributes, run=run
    )
    if d.allow:
        return "allow"
    if d.requires_approval:
        return "needs_approval"
    return "deny"


def _assert_parity(
    policy: dict,
    role: str | None,
    tool: str,
    args: dict,
    expect: str,
    *,
    attributes: dict | None = None,
    run: dict | None = None,
) -> None:
    py = _py_outcome(policy, role, tool, args, attributes, run)
    wasm = _wasm_outcome(policy, role, tool, args, attributes, run)
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
# ctx.* — ABAC attribute filtering. Every operator + the missing-attribute
# fail-closed case must decide identically on pydantic and opa->wasmtime.
# ---------------------------------------------------------------------------

_ATTR_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "default_policy": {"mode": "deny"},
            "tools": {
                "eq": {
                    "mode": "allow",
                    "constraints": ['ctx.department == "finance"'],
                },
                "in_list": {
                    "mode": "allow",
                    "constraints": ['ctx.region in ["EU", "UK"]'],
                },
                "not_in_list": {
                    "mode": "allow",
                    "constraints": ['ctx.region not in ["US"]'],
                },
                "ordered": {
                    "mode": "allow",
                    "constraints": ["ctx.clearance_level >= 3"],
                },
                "boolean": {
                    "mode": "allow",
                    "constraints": ["ctx.confirmed == true"],
                },
            },
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "attributes", "expect"),
    [
        # string equality
        ("eq", {"department": "finance"}, "allow"),
        ("eq", {"department": "sales"}, "deny"),
        ("eq", {}, "deny"),  # missing attr → fail closed on BOTH engines
        # membership against a literal list
        ("in_list", {"region": "EU"}, "allow"),
        ("in_list", {"region": "US"}, "deny"),
        ("in_list", {}, "deny"),  # missing → fail closed
        # negated membership
        ("not_in_list", {"region": "EU"}, "allow"),
        ("not_in_list", {"region": "US"}, "deny"),
        # missing → pydantic resolves _MISSING to False; Rego's inline
        # `not <undefined> in [...]` is undefined, so `allow` never fires.
        # Both deny — the case a change to negated-membership rendering
        # would silently break.
        ("not_in_list", {}, "deny"),
        # ordered comparison + cross-type guard
        ("ordered", {"clearance_level": 3}, "allow"),
        ("ordered", {"clearance_level": 2}, "deny"),
        ("ordered", {"clearance_level": "3"}, "deny"),  # str vs num → fail closed
        ("ordered", {}, "deny"),  # missing → fail closed
        # boolean equality
        ("boolean", {"confirmed": True}, "allow"),
        ("boolean", {"confirmed": False}, "deny"),
    ],
)
def test_ctx_attribute_parity(tool: str, attributes: dict, expect: str) -> None:
    _assert_parity(_ATTR_POLICY, "default", tool, {}, expect, attributes=attributes)


def test_ctx_none_bag_fails_closed_both_engines() -> None:
    """No attributes at all → every ctx.* ref misses and denies, both engines."""
    _assert_parity(_ATTR_POLICY, "default", "eq", {}, "deny", attributes=None)


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


# ---------------------------------------------------------------------------
# Boolean composition (2c) — or / and / not / grouping, via real opa
# ---------------------------------------------------------------------------

_BOOL_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "oo": {"mode": "allow", "constraints": ["args.a == 1 or args.b == 2"]},
                "aa": {"mode": "allow", "constraints": ["args.a == 1 and args.b == 2"]},
                "grp": {
                    "mode": "allow",
                    "constraints": ["(args.a == 1 or args.b == 2) and args.c == 3"],
                },
                "nn": {
                    "mode": "allow",
                    "constraints": ["not (args.a == 1 or args.b == 2)"],
                },
                "ni": {"mode": "allow", "constraints": ["not args.x in [1, 2]"]},
            }
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("oo", {"a": 1, "b": 9}, "allow"),
        ("oo", {"a": 9, "b": 2}, "allow"),
        ("oo", {"a": 9, "b": 9}, "deny"),
        ("aa", {"a": 1, "b": 2}, "allow"),
        ("aa", {"a": 1, "b": 9}, "deny"),
        ("grp", {"a": 1, "b": 9, "c": 3}, "allow"),
        ("grp", {"a": 1, "b": 9, "c": 9}, "deny"),  # group ok but c fails
        ("grp", {"a": 9, "b": 9, "c": 3}, "deny"),  # group fails
        ("nn", {"a": 9, "b": 9}, "allow"),  # not(or) — De Morgan
        ("nn", {"a": 1, "b": 9}, "deny"),
        ("ni", {"x": 5}, "allow"),
        ("ni", {"x": 1}, "deny"),
    ],
)
def test_boolean_parity(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_BOOL_POLICY, "default", tool, args, expect)


# ---------------------------------------------------------------------------
# Regression: specific divergences the generative fuzzer (test_dsl_fuzz) found.
# Kept as named, deterministic cases documenting each fix.
# ---------------------------------------------------------------------------

_REGRESSION_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "consts": {"cl": [1, 2, 3]},
            "tools": {
                # #1 not-of-missing: pydantic missing→false→not→allow; Rego inline
                # `not (undefined < 1)` used to deny.
                "notmiss": {"mode": "allow", "constraints": ["not (args.f < 1)"]},
                # #2 type error inside a quantifier body: Rego `every` used to treat
                # an undefined element body as satisfied (fail-open).
                "qtype": {
                    "mode": "allow",
                    "constraints": ['every(args.items, .price < "x")'],
                },
                # #3 cross-type ordered comparison: `"evil" > 10` is true in Rego's
                # total order (fail-open) but a TypeError→false in pydantic.
                "ordtype": {"mode": "allow", "constraints": ["args.f > 10"]},
                # bool vs number equality / membership (Python bool is int; Rego not).
                "booleq": {"mode": "allow", "constraints": ["args.f == 1"]},
                "boolin": {"mode": "allow", "constraints": ["args.f in consts.cl"]},
                # `not in` must use the same bool≠number rule as `in`: True is not
                # a member of a numeric list on either engine (fail-open guard).
                "boolnotin": {
                    "mode": "allow",
                    "constraints": ["args.f not in consts.cl"],
                },
                # regex \d must be ASCII on both engines (Python re defaults to
                # Unicode; Rego's RE2 is ASCII). A Unicode-digit arg must not
                # satisfy an ASCII \d gate on the pydantic engine.
                "redigit": {
                    "mode": "allow",
                    "constraints": ['matches(args.id, "^\\\\d+$")'],
                },
            },
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "expect"),
    [
        ("notmiss", {}, "allow"),  # f missing
        ("notmiss", {"f": 0}, "deny"),  # 0 < 1 → not → deny
        ("qtype", {"items": [{"price": 10}]}, "deny"),  # int < "x" → element false
        (
            "ordtype",
            {"f": "evil"},
            "deny",
        ),  # wrong-typed arg must NOT pass a numeric gate
        ("ordtype", {"f": 50}, "allow"),  # well-typed still works
        ("booleq", {"f": True}, "deny"),  # True != 1
        ("booleq", {"f": 1}, "allow"),
        ("boolin", {"f": True}, "deny"),  # True not in [1,2,3]
        ("boolin", {"f": 1}, "allow"),
        ("boolnotin", {"f": True}, "allow"),  # True not a member → not in → allow
        ("boolnotin", {"f": 1}, "deny"),  # 1 is a member → not in false → deny
        ("redigit", {"id": "123"}, "allow"),  # ASCII digits match \d
        (
            "redigit",
            {"id": "١٢٣"},
            "deny",
        ),  # Arabic-Indic digits: ASCII \d must not match
    ],
)
def test_fuzzer_found_divergences(tool: str, args: dict, expect: str) -> None:
    _assert_parity(_REGRESSION_POLICY, "default", tool, args, expect)


# ---------------------------------------------------------------------------
# Enforcement-seam parity — PolicyEnforcer.decide() (what adapters call) over
# BOTH engines, with a HexgateContext role scope and complex constraints. The other
# tests hit the engines directly; this exercises decide() + role resolution
# from the HexgateContext contextvar + Decision lifting.
# ---------------------------------------------------------------------------

_ENFORCE_POLICY = {
    "version": 1,
    "roles": {
        "base": {
            "is_mixin": True,
            "consts": {"max_files": 3, "roots": ["/tmp", "/srv"]},
        },
        "default": {
            "inherits": ["base"],
            "tools": {
                "write_batch": {
                    "mode": "allow",
                    "constraints": [
                        "count(args.paths) <= consts.max_files",
                        'every(args.paths, startswith(., "/tmp/"))',
                    ],
                },
                "refund": {
                    "mode": "approval_required",
                    "constraints": ['args.amount <= 500 or role == "admin"'],
                },
            },
        },
        "admin": {
            "inherits": ["base"],
            "tools": {"refund": {"mode": "allow", "constraints": ['role == "admin"']}},
        },
    },
}


class _WasmEngine:
    """PolicyEngine over compiled WASM — mirrors PolicyBundle.evaluate()."""

    def __init__(self, wasm_bytes: bytes) -> None:
        self._w = WasmPolicy.from_bytes(wasm_bytes)

    def evaluate(self, *, role, tool, args, attributes=None, run=None):
        from hexgate.security.policy import verdict_from_rego

        role_ = role or "default"
        return verdict_from_rego(
            self._w.decide(
                role=role_,
                tool=tool,
                args=dict(args),
                ctx=dict(attributes or {}),
                run=dict(run or {}),
            ),
            tool_name=tool,
            role=role_,
        )


@pytest.mark.parametrize(
    ("role", "tool", "args", "expect"),
    [
        ("default", "write_batch", {"paths": ["/tmp/a", "/tmp/b"]}, "allow"),
        ("default", "write_batch", {"paths": ["/tmp/a", "/etc/b"]}, "deny"),  # not /tmp
        (
            "default",
            "write_batch",
            {"paths": ["/tmp/1", "/tmp/2", "/tmp/3", "/tmp/4"]},
            "deny",
        ),  # >max
        ("default", "refund", {"amount": 100}, "needs_approval"),
        ("default", "refund", {"amount": 999}, "deny"),  # over cap, not admin
        ("admin", "refund", {"amount": 999}, "allow"),  # admin bypasses via role fact
    ],
)
def test_enforcer_parity_complex(role: str, tool: str, args: dict, expect: str) -> None:
    from hexgate.runtime import HexgateContext
    from hexgate.security.enforcer import PolicyEnforcer

    ps = load_policy_set_from_dict(_ENFORCE_POLICY)
    wasm = _WasmEngine(_wasm_bytes(compile_to_rego(_ENFORCE_POLICY)))

    py_enforcer = PolicyEnforcer(ps, agent_name="a")
    wasm_enforcer = PolicyEnforcer(wasm, agent_name="a")

    with HexgateContext(user_id="u", user_roles=[role]).sync_scope():
        py = py_enforcer.decide(tool, args).outcome.value
        wf = wasm_enforcer.decide(tool, args).outcome.value

    assert py == wf, f"enforcer divergence {role}/{tool}/{args}: py={py} wasm={wf}"
    assert py == expect


# ---------------------------------------------------------------------------
# Multi-role permissive union — the acceptance gate. The same role set through
# the same fold over two different engines must agree on outcome AND deciding
# role.
# ---------------------------------------------------------------------------

_MULTI_ROLE_POLICY = {
    "version": 1,
    "roles": {
        # Least-privilege default: unrecognised role names contribute nothing.
        "default": {"default_policy": {"mode": "deny"}},
        "support": {
            "default_policy": {"mode": "deny"},
            "tools": {"read_file": {"mode": "allow"}},
        },
        "billing": {
            "default_policy": {"mode": "deny"},
            "tools": {
                "refund": {"mode": "allow", "constraints": ['role == "billing"']},
                "read_file": {"mode": "approval_required"},
            },
        },
        "auditor": {
            "default_policy": {"mode": "deny"},
            "tools": {"refund": {"mode": "approval_required"}},
        },
    },
}


@pytest.mark.parametrize(
    ("roles", "tool", "args", "expect", "deciding"),
    [
        # The union grants what no single role would.
        (["support", "billing"], "refund", {"amount": 1}, "allow", "billing"),
        (["billing", "support"], "refund", {"amount": 1}, "allow", "billing"),
        # Nobody grants it -> deny, no credited role.
        (["support", "auditor"], "write_file", {}, "deny", None),
        # ALLOW beats NEEDS_APPROVAL regardless of order (D2).
        (["billing", "support"], "read_file", {}, "allow", "support"),
        (["support", "billing"], "read_file", {}, "allow", "support"),
        # Approval only when no role allows outright.
        (["auditor"], "refund", {"amount": 1}, "needs_approval", "auditor"),
        (["support", "auditor"], "refund", {"amount": 1}, "needs_approval", "auditor"),
        # The role fact binds per role, so it still grants inside a union.
        (["auditor", "billing"], "refund", {"amount": 1}, "allow", "billing"),
        # Unrecognised names resolve to the least-privilege default (D13).
        (["zzz", "support"], "read_file", {}, "allow", "support"),
        (["zzz", "yyy"], "read_file", {}, "deny", None),
        # No roles -> the default policy.
        ([], "read_file", {}, "deny", None),
    ],
)
def test_multi_role_union_parity(
    roles: list[str], tool: str, args: dict, expect: str, deciding: str | None
) -> None:
    from hexgate.runtime import HexgateContext
    from hexgate.security.enforcer import PolicyEnforcer

    ps = load_policy_set_from_dict(_MULTI_ROLE_POLICY)
    wasm = _WasmEngine(_wasm_bytes(compile_to_rego(_MULTI_ROLE_POLICY)))

    py_enforcer = PolicyEnforcer(ps, agent_name="a")
    wasm_enforcer = PolicyEnforcer(wasm, agent_name="a")

    with HexgateContext(user_id="u", user_roles=roles).sync_scope():
        py = py_enforcer.decide(tool, args)
        wf = wasm_enforcer.decide(tool, args)

    assert py.outcome.value == wf.outcome.value, (
        f"union divergence {roles}/{tool}/{args}: "
        f"py={py.outcome.value} wasm={wf.outcome.value}"
    )
    assert py.deciding_role == wf.deciding_role, (
        f"deciding-role divergence {roles}/{tool}/{args}: "
        f"py={py.deciding_role} wasm={wf.deciding_role}"
    )
    assert py.outcome.value == expect
    assert py.deciding_role == deciding


@pytest.mark.parametrize("role", ["support", "billing", "zzz"])
def test_single_role_union_matches_direct_evaluation_on_both_engines(
    role: str,
) -> None:
    """D12 across engines: wrapping one role in the union changes nothing."""
    from hexgate.runtime import HexgateContext
    from hexgate.security.enforcer import PolicyEnforcer

    ps = load_policy_set_from_dict(_MULTI_ROLE_POLICY)
    wasm = _WasmEngine(_wasm_bytes(compile_to_rego(_MULTI_ROLE_POLICY)))

    for engine in (ps, wasm):
        direct = engine.evaluate(role=role, tool="read_file", args={})
        with HexgateContext(user_id="u", user_roles=[role]).sync_scope():
            through_union = PolicyEnforcer(engine, agent_name="a").decide(
                "read_file", {}
            )
        assert through_union.outcome is direct.outcome
        assert through_union.reason == direct.reason
        assert through_union.violations == direct.violations
        assert through_union.hint == direct.hint


# ---------------------------------------------------------------------------
# run.* — the invocation's own fact record
# ---------------------------------------------------------------------------

_RUN_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "identity": {
                    "mode": "allow",
                    "constraints": ['run.agent == "billing"'],
                },
                "elapsed": {
                    "mode": "allow",
                    "constraints": ["run.elapsed_seconds < 300"],
                },
            },
        }
    },
}


@pytest.mark.parametrize(
    ("tool", "run", "expect"),
    [
        # identity
        ("identity", {"agent": "billing"}, "allow"),
        ("identity", {"agent": "support"}, "deny"),
        ("identity", {}, "deny"),  # missing → fail closed on BOTH engines
        # the time budget, and its cross-type guard
        ("elapsed", {"elapsed_seconds": 12.5}, "allow"),
        ("elapsed", {"elapsed_seconds": 400.0}, "deny"),
        ("elapsed", {"elapsed_seconds": 300}, "deny"),  # the boundary is exclusive
        ("elapsed", {"elapsed_seconds": "12"}, "deny"),  # str vs num → fail closed
        ("elapsed", {}, "deny"),
    ],
)
def test_run_fact_parity(tool: str, run: dict, expect: str) -> None:
    """Elapsed time is a float compared against an integer literal — the shape
    every time budget takes, so the numeric guard must agree across engines."""
    _assert_parity(_RUN_POLICY, "default", tool, {}, expect, run=run)


def test_run_none_namespace_fails_closed_both_engines() -> None:
    _assert_parity(_RUN_POLICY, "default", "identity", {}, "deny", run=None)


# ---------------------------------------------------------------------------
# Policy-level constraints — applied to every tool, on both engines
#
# The drift risk is structural: pydantic has one code path for every tool key,
# while the Rego compiler emits a rule per key from three call sites. The
# easiest to forget is agent.run, whose policy comes from a fallback constant.
# ---------------------------------------------------------------------------

_POLICY_LEVEL_POLICY = {
    "roles": {
        "read_only": {
            "is_mixin": True,
            "constraints": ["run.tool_calls < 3"],
        },
        "default": {
            "inherits": ["read_only"],
            "default_policy": {"mode": "allow"},
            "tools": {
                "listed": {"mode": "allow"},
                "capped": {"mode": "allow", "constraints": ["args.amount <= 50"]},
                "forbidden": {"mode": "deny"},
            },
        },
    },
}


@pytest.mark.parametrize(
    ("tool", "args", "run", "expect"),
    [
        # A listed tool, under and over the policy-level cap.
        ("listed", {}, {"tool_calls": 1}, "allow"),
        ("listed", {}, {"tool_calls": 5}, "deny"),
        # A tool falling through to default_policy.
        ("unlisted", {}, {"tool_calls": 1}, "allow"),
        ("unlisted", {}, {"tool_calls": 5}, "deny"),
        # Admission: opt-in on both engines, and gated by the same cap.
        ("agent.run", {}, {"tool_calls": 1}, "allow"),
        ("agent.run", {}, {"tool_calls": 5}, "deny"),
        # Both lists apply, in either failing direction.
        ("capped", {"amount": 10}, {"tool_calls": 1}, "allow"),
        ("capped", {"amount": 999}, {"tool_calls": 1}, "deny"),
        ("capped", {"amount": 10}, {"tool_calls": 5}, "deny"),
        # Can only narrow: a satisfied policy-level constraint never
        # resurrects a denied tool or an unlisted reach key.
        ("forbidden", {}, {"tool_calls": 0}, "deny"),
        ("agent.handoff:other", {}, {"tool_calls": 0}, "deny"),
        # Missing namespace fails closed on both.
        ("listed", {}, {}, "deny"),
    ],
)
def test_policy_level_constraint_parity(
    tool: str, args: dict, run: dict, expect: str
) -> None:
    """Inherited from a mixin, so this also covers the union merge reaching the
    Rego compiler through the resolved PolicySet."""
    _assert_parity(_POLICY_LEVEL_POLICY, None, tool, args, expect, run=run)
