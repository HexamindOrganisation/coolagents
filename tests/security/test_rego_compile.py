"""Tests for the YAML → Rego compiler (M2 phase 1).

Two kinds of checks here:

  * Structural / golden tests on the emitted Rego source — operators,
    package header, rule-head naming, deterministic ordering.

  * Parity tests: for a given role + tool + args input, the rules that
    *would* fire in Rego (as predicted by the source structure) match
    the decision today's pydantic :func:`authorize_tool_call` returns.
    These are predictive — when the wasmtime-py adapter lands in a later
    phase, the same fixtures become true end-to-end parity checks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from hexgate.security import (
    AgentPolicy,
    PolicyDeniedError,
    PolicySetError,
    authorize_tool_call,
    compile_default_only,
    compile_to_rego,
    load_policy_set_from_dict,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


_SUPPORT_BOT_POLICY = yaml.safe_load(
    """
version: 1
roles:
  read_only:
    is_mixin: true
    tools:
      web_search: { mode: allow }
      read_file:  { mode: allow }

  default:
    inherits: [read_only]
    tools:
      refund_order: { mode: deny }

  support:
    inherits: [read_only]
    tools:
      refund_order:
        mode: allow
        constraints:
          - args.amount <= 50
          - args.currency == "USD"

  billing:
    inherits: [read_only]
    tools:
      refund_order:
        mode: allow
        constraints:
          - args.amount <= 500
          - args.currency in ["USD", "EUR"]
"""
)


def _allow_rules(rego: str) -> list[str]:
    """Split the emitted Rego on the ``allow if {`` heading.

    Returns the rule bodies (the content between ``{`` and the matching
    ``}``) so tests can inspect each rule's conditions without dragging
    in a Rego parser.
    """
    out: list[str] = []
    for match in re.finditer(r"allow if \{\n(.*?)\n\}", rego, re.DOTALL):
        out.append(match.group(1))
    return out


def _approval_rules(rego: str) -> list[str]:
    out: list[str] = []
    for match in re.finditer(r"requires_approval if \{\n(.*?)\n\}", rego, re.DOTALL):
        out.append(match.group(1))
    return out


def _violation_rules(rego: str) -> list[str]:
    """Return each ``violations contains ... if { ... }`` rule's body.

    The membership value can be a backtick raw-string (which the emitter
    prefers, since it skips escape processing) or a JSON-escaped double-
    quoted string for the rare backtick-containing case. Match both
    flavours and the sentinel; let the caller filter the sentinel out.
    """
    out: list[str] = []
    pattern = re.compile(
        r"violations contains (?:`[^`]+`|\"[^\"]*\") if \{\n(.*?)\n\}",
        re.DOTALL,
    )
    for match in pattern.finditer(rego):
        out.append(match.group(1))
    return out


# ---------------------------------------------------------------------------
# Header / module structure
# ---------------------------------------------------------------------------


def test_emits_package_header_and_defaults() -> None:
    """Module starts with the package declaration + both default rules."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "package hexgate.policy" in rego
    assert "default allow := false" in rego
    assert "default requires_approval := false" in rego


def test_custom_package_name_carries_through() -> None:
    """Caller can override the package name (M3 will use this per-agent)."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY, package="hexgate.policy.support_bot")
    assert "package hexgate.policy.support_bot" in rego


def test_emits_source_hash_in_header() -> None:
    """The header records the sha256 of the source payload for traceability."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert re.search(r"sha256: [0-9a-f]{64}\b", rego), rego


def test_explicit_source_hash_is_used_verbatim() -> None:
    """Passing source_hash overrides the auto-computed one (CLI uses this)."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY, source_hash="deadbeef" * 8)
    assert "deadbeef" in rego


# ---------------------------------------------------------------------------
# Role / tool emission semantics
# ---------------------------------------------------------------------------


def test_emits_allow_rule_per_role_and_tool() -> None:
    """Each (role, tool) with mode=allow emits exactly one allow rule."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    rules = _allow_rules(rego)
    # support_bot: 3 roles (read_only is mixin, dropped) × 3 tools (web_search,
    # read_file each get an allow per role; refund_order is allow for support
    # + billing, deny for default).
    #   default  → web_search, read_file (refund_order is deny, no rule)
    #   support  → web_search, read_file, refund_order (with 2 constraints)
    #   billing  → web_search, read_file, refund_order (with 2 constraints)
    assert len(rules) == 2 + 3 + 3


def test_mixin_role_omitted_from_output() -> None:
    """Mixin roles don't surface as concrete roles in the Rego output."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert 'input.role == "read_only"' not in rego


def test_deny_tool_emits_no_rule() -> None:
    """`mode: deny` produces no rule — absence of allow IS the deny."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    # default.refund_order is deny — the default role must get no allow for it.
    assert (
        _predict_rego_allow(
            rego, "default", "refund_order", {"amount": 1, "currency": "USD"}
        )
        is False
    )


def test_role_section_comments_present() -> None:
    """Each role gets a ``# ---- role: NAME ----`` divider — readability."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "# ---- role: billing" in rego
    assert "# ---- role: default" in rego
    assert "# ---- role: support" in rego
    # mixin section never gets emitted
    assert "# ---- role: read_only" not in rego


def test_output_is_deterministic_across_runs() -> None:
    """Same input → identical bytes. Critical for content-addressing bundles."""
    a = compile_to_rego(_SUPPORT_BOT_POLICY)
    b = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert a == b


def test_roles_emitted_in_alphabetical_order() -> None:
    """Role sections sort alphabetically regardless of dict insertion order."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    billing = rego.index("# ---- role: billing")
    default = rego.index("# ---- role: default")
    support = rego.index("# ---- role: support")
    assert billing < default < support


# ---------------------------------------------------------------------------
# Constraint translation
# ---------------------------------------------------------------------------


def test_numeric_constraint_prefixes_input() -> None:
    """``args.amount <= 50`` → ``input.args.amount <= 50``."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    # support's refund_order has args.amount <= 50
    support_rules = [r for r in _allow_rules(rego) if '"support"' in r]
    refund_rule = next(r for r in support_rules if '"refund_order"' in r)
    assert "input.args.amount <= 50" in refund_rule


def test_string_equality_constraint() -> None:
    """JSON-double-quoted strings survive the translation intact."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    support_rules = [r for r in _allow_rules(rego) if '"support"' in r]
    refund_rule = next(r for r in support_rules if '"refund_order"' in r)
    assert 'input.args.currency == "USD"' in refund_rule


def test_in_list_constraint() -> None:
    """``args.X in ["a", "b"]`` translates verbatim (Rego has the same op)."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    billing_rules = [r for r in _allow_rules(rego) if '"billing"' in r]
    refund_rule = next(r for r in billing_rules if '"refund_order"' in r)
    assert 'input.args.currency in ["USD", "EUR"]' in refund_rule


def test_not_in_constraint_wraps_with_not() -> None:
    """``not in`` becomes Rego's ``not X in Y`` (semantically equivalent)."""
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "refund": {
                        "mode": "allow",
                        "constraints": ['args.priority not in ["urgent"]'],
                    }
                }
            }
        },
    }
    rego = compile_to_rego(payload)
    assert 'not input.args.priority in ["urgent"]' in rego


def test_compile_rejects_unparseable_constraint() -> None:
    """An invalid constraint surfaces at load (model grammar validator),
    which compile_to_rego triggers before ever reaching WASM eval."""
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "refund": {
                        "mode": "allow",
                        "constraints": ["args.amount ~~ 50"],
                    }
                }
            }
        },
    }
    with pytest.raises(ValidationError):
        compile_to_rego(payload)


# ---------------------------------------------------------------------------
# file_scope is pydantic-only — refuse to compile it to a fail-open bundle
# ---------------------------------------------------------------------------


def _file_scope_policy(mode: str) -> dict:
    return {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "read_file": {
                        "mode": mode,
                        "file_scope": {"allowed_paths": ["src/**"]},
                    }
                }
            }
        },
    }


@pytest.mark.parametrize("mode", ["allow", "approval_required"])
def test_compile_rejects_file_scope(mode: str) -> None:
    """Compiling a non-deny file_scope tool must fail loud, not silently drop it.

    Dropping file_scope would make the bundle FAIL OPEN (every path allowed)
    vs the pydantic engine that enforces the restriction.
    """
    with pytest.raises(PolicySetError, match="file_scope"):
        compile_to_rego(_file_scope_policy(mode))


def test_compile_allows_file_scope_on_deny_tool() -> None:
    """file_scope on a deny tool is inert (deny never consults it) → compiles."""
    rego = compile_to_rego(_file_scope_policy("deny"))
    # deny emits no allow rule for read_file; nothing to fail-open on.
    assert (
        _predict_rego_allow(rego, "default", "read_file", {"file_path": "x"}) is False
    )


# ---------------------------------------------------------------------------
# Approval-required mode
# ---------------------------------------------------------------------------


def test_approval_required_emits_separate_rule_head() -> None:
    """``mode: approval_required`` produces a ``requires_approval`` rule,
    not an ``allow`` rule — the runtime queries both and dispatches the
    approval handler when this one fires."""
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "issue_credit": {
                        "mode": "approval_required",
                        "constraints": ["args.amount <= 500"],
                    }
                }
            }
        },
    }
    rego = compile_to_rego(payload)
    assert len(_allow_rules(rego)) == 0
    [approval] = _approval_rules(rego)
    assert 'input.tool == "issue_credit"' in approval
    assert "input.args.amount <= 500" in approval


# ---------------------------------------------------------------------------
# Shape variants
# ---------------------------------------------------------------------------


def test_flat_single_policy_compiles_as_default_role() -> None:
    """Legacy flat ``policy.yaml`` (no ``roles:`` key) wraps as default."""
    payload = {
        "version": 1,
        "tools": {
            "web_search": {"mode": "allow"},
        },
    }
    rego = compile_to_rego(payload)
    [rule] = _allow_rules(rego)
    assert 'input.tool == "web_search"' in rule
    # Only the default role exists → no role guard; it applies to every caller
    # (including unknown roles, per the default-role fallback).
    assert _predict_rego_allow(rego, "default", "web_search", {}) is True
    assert _predict_rego_allow(rego, "anyone", "web_search", {}) is True


def test_compile_default_only_wraps_AgentPolicy() -> None:
    """Convenience wrapper for callers that already hold an AgentPolicy."""
    policy = AgentPolicy.model_validate({"tools": {"web_search": {"mode": "allow"}}})
    rego = compile_default_only(policy)
    assert 'input.tool == "web_search"' in rego


def test_empty_inline_roles_compiles_to_default_only() -> None:
    """A payload with ``roles:`` but no concrete roles still produces a module
    with the default rules (no allow rules, just the headers)."""
    # All-mixin policy_map raises today (load_policy_set_from_dict via
    # load_policy_map). The compiler surfaces that as the same error type.
    payload = {
        "version": 1,
        "roles": {
            "mix": {"is_mixin": True, "tools": {"web_search": {"mode": "allow"}}}
        },
    }
    with pytest.raises(PolicySetError):
        compile_to_rego(payload)


# ---------------------------------------------------------------------------
# Structured decision object (M2 phase 3.5)
# ---------------------------------------------------------------------------


def test_emits_decision_object_with_all_three_fields() -> None:
    """The module's single entrypoint is `decision := {allow, requires_approval, violations}`."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "decision := {" in rego
    assert '"allow": allow,' in rego
    assert '"requires_approval": requires_approval,' in rego
    assert '"violations": violations,' in rego


def test_emits_rego_v1_import() -> None:
    """Modern opa needs `import rego.v1` for the contains / if syntax."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "import rego.v1" in rego


def test_emits_violations_rule_per_constraint() -> None:
    """Each constraint emits its own `violations contains <raw> if {...}` rule."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    # support_bot has 4 constraints total:
    # support.refund_order: amount <= 50, currency == "USD"
    # billing.refund_order: amount <= 500, currency in ["USD","EUR"]
    assert len(_violation_rules(rego)) == 4


def test_violation_rule_uses_raw_constraint_string() -> None:
    """The membership value is the original YAML string verbatim — that's
    the dev's deny reason at runtime."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "violations contains `args.amount <= 500` if" in rego
    assert "violations contains `args.amount <= 50` if" in rego
    assert 'violations contains `args.currency in ["USD", "EUR"]` if' in rego
    assert 'violations contains `args.currency == "USD"` if' in rego


def test_violation_rule_body_negates_constraint() -> None:
    """The violation body matches role/tool and negates a positive rule-ref
    (`not _p_<hash>`) — not an inline expression — whose helper holds the
    (type-guarded) comparison."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    pattern = re.compile(
        r"violations contains `args\.amount <= 500` if \{\n(.*?)\n\}", re.DOTALL
    )
    body = next(b for b in pattern.findall(rego) if 'input.role == "billing"' in b)
    assert 'input.tool == "refund_order"' in body
    m = re.search(r"not (_p_[0-9a-f]+)", body)
    assert m, body
    helper = re.search(rf"{m.group(1)} if \{{\n(.*?)\n\}}", rego, re.DOTALL).group(1)
    assert "input.args.amount <= 500" in helper
    assert "is_number(input.args.amount)" in helper


def test_violation_value_uses_json_when_constraint_has_backtick() -> None:
    """A constraint whose text contains a backtick can't use Rego's backtick
    raw-string for the violations membership — it falls back to a JSON string."""
    raw = 'args.x == "a`b"'
    payload = {
        "version": 1,
        "roles": {"default": {"tools": {"t": {"mode": "allow", "constraints": [raw]}}}},
    }
    rego = compile_to_rego(payload)
    assert f"violations contains {json.dumps(raw)} if" in rego
    assert f"`{raw}`" not in rego  # not the backtick raw-string form


def test_quantifier_emits_helper_rule() -> None:
    """A quantifier compiles to a named helper the allow rule references and
    the violation rule negates (``not _q_…`` — not an inline ``not every``)."""
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "t": {
                        "mode": "allow",
                        "constraints": ['every(args.files, startswith(., "/tmp/"))'],
                    }
                }
            }
        },
    }
    rego = compile_to_rego(payload)
    assert re.search(r"_q_[0-9a-f]+ if \{\n\s+every __e_[0-9a-f]+ in ", rego)
    [allow_body] = _allow_rules(rego)
    assert re.search(r"_q_[0-9a-f]+", allow_body)  # allow references the helper
    assert re.search(r"not _q_[0-9a-f]+", rego)  # violation negates the helper
    assert "not every" not in rego and "not some" not in rego  # never inline-negated


def test_or_emits_same_head_disjunct_rules() -> None:
    """An `or` compiles to one helper rule per disjunct under the same head
    (Rego OR), referenced by the allow rule and negated in the violation."""
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "t": {
                        "mode": "allow",
                        "constraints": ["args.a == 1 or args.b == 2"],
                    }
                }
            }
        },
    }
    rego = compile_to_rego(payload)
    # two rules with the same _c_<hash> head (the disjuncts)
    m = re.search(r"(_c_[0-9a-f]+) if", rego)
    assert m
    name = m.group(1)
    assert rego.count(f"{name} if {{") == 2  # one per disjunct
    assert f"not {name}" in rego  # violation negates the whole disjunction
    assert "not not" not in rego


def test_quantifier_output_is_deterministic() -> None:
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "tools": {
                    "t": {"mode": "allow", "constraints": ["any(args.r, . == 1)"]}
                }
            }
        },
    }
    assert compile_to_rego(payload) == compile_to_rego(payload)


def test_consts_emitted_as_module_rules() -> None:
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "consts": {"cap": 500, "repos": ["a", "b"]},
                "tools": {
                    "t": {"mode": "allow", "constraints": ["args.n <= consts.cap"]}
                },
            }
        },
    }
    rego = compile_to_rego(payload)
    assert "cap := 500" in rego
    assert 'repos := ["a", "b"]' in rego
    assert "input.args.n <= cap" in rego  # reference uses the const name


def test_compile_rejects_unknown_const() -> None:
    payload = {
        "version": 1,
        "roles": {
            "default": {
                "consts": {"cap": 500},
                "tools": {
                    "t": {"mode": "allow", "constraints": ["args.x == consts.missing"]}
                },
            }
        },
    }
    with pytest.raises(PolicySetError, match="undefined constant"):
        compile_to_rego(payload)


def test_compile_rejects_conflicting_consts_across_roles() -> None:
    payload = {
        "version": 1,
        "roles": {
            "default": {"consts": {"cap": 500}, "tools": {}},
            "billing": {
                "consts": {"cap": 999},  # same name, different value → conflict
                "tools": {
                    "t": {"mode": "allow", "constraints": ["args.n <= consts.cap"]}
                },
            },
        },
    }
    with pytest.raises(PolicySetError, match="conflicting values"):
        compile_to_rego(payload)


def test_violations_sentinel_emitted_for_constraint_free_policy() -> None:
    """Policies with zero constraints still need `violations` defined —
    a `false`-bodied sentinel keeps the decision rule safe to build."""
    payload = {
        "version": 1,
        "roles": {
            "default": {"tools": {"web_search": {"mode": "allow"}}},
        },
    }
    rego = compile_to_rego(payload)
    assert 'violations contains "__never__" if false' in rego


def test_decision_default_includes_empty_state() -> None:
    """`default allow`/`default requires_approval` cover the fall-through;
    `violations` defaults to the empty set by construction."""
    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    assert "default allow := false" in rego
    assert "default requires_approval := false" in rego


# ---------------------------------------------------------------------------
# Parity with the pydantic engine
#
# Two parametrized tests share the same fixture table:
#
#   * The "predictive" one walks the rule structure with regex + the same
#     parse_constraint engine the SDK enforces with. Cheap, no opa needed,
#     catches emitter regressions.
#
#   * The "semantic" one compiles the rego all the way to WASM and runs it
#     through the wasm_engine. This is the load-bearing check — when this
#     matches pydantic, phase 6's enforcement cutover is a flag flip.
# ---------------------------------------------------------------------------

_PARITY_CASES: list[tuple[str, str, dict, bool]] = [
    ("billing", "refund_order", {"amount": 30, "currency": "USD"}, True),
    ("billing", "refund_order", {"amount": 600, "currency": "USD"}, False),
    ("billing", "refund_order", {"amount": 30, "currency": "JPY"}, False),
    ("support", "refund_order", {"amount": 30, "currency": "USD"}, True),
    ("support", "refund_order", {"amount": 200, "currency": "USD"}, False),
    ("support", "refund_order", {"amount": 30, "currency": "EUR"}, False),
    ("default", "refund_order", {"amount": 5, "currency": "USD"}, False),
    ("billing", "web_search", {}, True),
    ("default", "web_search", {}, True),
]


@pytest.mark.parametrize(("role", "tool", "args", "expect_allow"), _PARITY_CASES)
def test_parity_predicted_rego_vs_pydantic(
    role: str, tool: str, args: dict, expect_allow: bool
) -> None:
    """Cheap structural parity — no opa needed.

    Walks the emitted rules with regex and re-evaluates each constraint
    with the SDK's :func:`parse_constraint` engine. Catches emitter bugs
    (wrong operator, wrong path) without needing a wasm runtime.
    """
    ps = load_policy_set_from_dict(_SUPPORT_BOT_POLICY)
    policy = ps.policy_for(role)
    try:
        authorize_tool_call(policy, tool, args)
        py_allow = True
    except PolicyDeniedError:
        py_allow = False
    assert py_allow is expect_allow, (
        f"pydantic engine disagrees for {role}/{tool}/{args}"
    )

    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    rego_allow = _predict_rego_allow(rego, role, tool, args)
    assert rego_allow is expect_allow, (
        f"emitted Rego predicts the wrong decision for {role}/{tool}/{args}"
    )


# Compile the wasm once for all semantic-parity cases — opa build takes
# ~100ms, multiplied by 9 cases that's a noticeable slice of the suite.
@pytest.fixture(scope="module")
def _support_bot_wasm() -> bytes:
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa not on PATH")
    from hexgate.security import compile_to_wasm

    rego = compile_to_rego(_SUPPORT_BOT_POLICY)
    return compile_to_wasm(rego).wasm


@pytest.mark.parametrize(("role", "tool", "args", "expect_allow"), _PARITY_CASES)
def test_parity_wasm_vs_pydantic(
    role: str, tool: str, args: dict, expect_allow: bool, _support_bot_wasm: bytes
) -> None:
    """Semantic parity — what the wasm runtime would actually decide.

    This is the load-bearing check for the enforcement cutover in M2 phase
    6. If this matches pydantic for every input shape we care about, we
    can swap the enforcer with confidence.
    """
    from hexgate.security import WasmPolicy

    ps = load_policy_set_from_dict(_SUPPORT_BOT_POLICY)
    policy = ps.policy_for(role)
    try:
        authorize_tool_call(policy, tool, args)
        py_allow = True
    except PolicyDeniedError:
        py_allow = False
    assert py_allow is expect_allow, (
        f"pydantic engine disagrees for {role}/{tool}/{args}"
    )

    wasm_policy = WasmPolicy.from_bytes(_support_bot_wasm)
    decision = wasm_policy.decide(role=role, tool=tool, args=args)
    assert decision.allow is expect_allow, (
        f"wasm engine disagrees with pydantic for {role}/{tool}/{args}: "
        f"got {decision}, expected allow={expect_allow}"
    )


def _guard_matches(rule: str, kind: str, value: object) -> bool:
    """True when a rule's ``role``/``tool`` guard admits ``value``.

    Handles both guard shapes the compiler emits: exact match
    (``input.<kind> == "x"``) and exclusion (``not input.<kind> in {...}``,
    used for the default-role fallback and the default_policy catch-all).
    No guard of that kind → the rule applies to any value.
    """
    m = re.search(rf'input\.{kind} == "([^"]*)"', rule)
    if m:
        return value == m.group(1)
    m = re.search(rf"not input\.{kind} in \{{([^}}]*)\}}", rule)
    if m:
        excluded = json.loads("[" + m.group(1) + "]")
        return value not in excluded
    return True  # unguarded on this dimension → matches anything


def _predict_rego_allow(rego: str, role: str, tool: str, args: dict) -> bool:
    """Lightweight Rego eval substitute for the parity test (no opa needed).

    Scans emitted allow rules for one whose role + tool guards admit the
    input, then re-evaluates each ``input.args.*`` constraint line with the
    SDK's own :func:`parse_constraint` engine. The load-bearing check is
    :func:`test_parity_wasm_vs_pydantic`; this stub just catches emitter
    regressions when opa isn't available.
    """
    from hexgate.security.constraints import evaluate_constraint, parse_constraint

    for rule in _allow_rules(rego):
        if not _guard_matches(rule, "role", role):
            continue
        if not _guard_matches(rule, "tool", tool):
            continue
        ok = True
        for line in rule.splitlines():
            stripped = line.strip()
            # Skip guards (role/tool), type guards, and blanks — only args.*
            # comparison lines are constraints the predictor re-evaluates.
            if (
                not stripped
                or "input.role" in stripped
                or "input.tool" in stripped
                or stripped.startswith(("is_number(", "is_string("))
            ):
                continue
            # Unwrap the ``not X in Y`` shape back into our grammar.
            if stripped.startswith("not input."):
                stripped = stripped.replace("not input.", "", 1)
                stripped = stripped.replace(" in ", " not in ")
            else:
                stripped = stripped.replace("input.", "", 1)
            constraint = parse_constraint(stripped)
            if not evaluate_constraint(constraint, {"args": args}):
                ok = False
                break
        if ok:
            return True
    return False


# ---------------------------------------------------------------------------
# Golden snapshot — locks compiled Rego byte-for-byte across the AST refactor
# ---------------------------------------------------------------------------

# Exercises every construct the current grammar renders: multiple roles,
# inheritance + mixin filtering, deny (no rule), approval_required, and each
# operator (<=, ==, in, not in, bool ==, deep path). Regenerate the golden
# only on a *deliberate* codegen change:
#   python -c "from tests.security.test_rego_compile import _GOLDEN_PAYLOAD; \
#     from hexgate.security.rego import compile_to_rego; \
#     open('tests/security/golden/policy_fixture.rego','w').write(\
#       compile_to_rego(_GOLDEN_PAYLOAD, source_hash='GOLDEN_FIXED_HASH'))"
_GOLDEN_PAYLOAD = {
    "version": 1,
    "roles": {
        "read_only": {"is_mixin": True, "tools": {"read_file": {"mode": "allow"}}},
        "default": {"tools": {"web_search": {"mode": "allow"}}},
        "support": {
            "inherits": ["read_only"],
            "tools": {
                "fetch": {"mode": "allow"},
                "issue_credit": {
                    "mode": "approval_required",
                    "constraints": ["args.amount <= 500"],
                },
            },
        },
        "billing": {
            "inherits": ["read_only", "support"],
            "tools": {
                "refund_order": {
                    "mode": "allow",
                    "constraints": [
                        "args.amount <= 500",
                        'args.currency == "USD"',
                        'args.template in ["a", "b"]',
                        'args.priority not in ["urgent"]',
                        "args.confirmed == true",
                        "args.payment.amount <= 100",
                    ],
                },
                "delete_user": {"mode": "deny"},
            },
        },
    },
}

_GOLDEN_PATH = Path(__file__).parent / "golden" / "policy_fixture.rego"


def test_compiled_rego_matches_golden_snapshot() -> None:
    """The AST refactor must not change compiled output — byte-for-byte."""
    expected = _GOLDEN_PATH.read_text(encoding="utf-8")
    actual = compile_to_rego(_GOLDEN_PAYLOAD, source_hash="GOLDEN_FIXED_HASH")
    assert actual == expected


# ---------------------------------------------------------------------------
# Adversarial parity — every operator + literal type, both engines end-to-end
#
# The fixture below covers each construct the grammar can emit. The wasm
# fixture *building at all* is itself a regression guard: a `not in`
# constraint that compiled to `not not ... in ...` (invalid Rego) used to
# break opa build for the whole bundle — undetected because no wasm-parity
# fixture exercised `not in`.
# ---------------------------------------------------------------------------

_ADVERSARIAL_POLICY = {
    "version": 1,
    "roles": {
        "default": {
            "tools": {
                "num": {"mode": "allow", "constraints": ["args.amount <= 500"]},
                "ne": {"mode": "allow", "constraints": ['args.currency != "USD"']},
                "streq": {"mode": "allow", "constraints": ['args.currency == "USD"']},
                "inl": {
                    "mode": "allow",
                    "constraints": ['args.tier in ["gold", "silver"]'],
                },
                "notin": {
                    "mode": "allow",
                    "constraints": ['args.priority not in ["urgent", "critical"]'],
                },
                "boolean": {"mode": "allow", "constraints": ["args.confirmed == true"]},
                "isnull": {"mode": "allow", "constraints": ["args.note == null"]},
                "neg": {"mode": "allow", "constraints": ["args.delta >= -5"]},
                "flt": {"mode": "allow", "constraints": ["args.ratio <= 1.5"]},
                "strop": {"mode": "allow", "constraints": ['args.label == "a <= b"']},
                "deep": {
                    "mode": "allow",
                    "constraints": ["args.payment.amount <= 100"],
                },
                "multi": {
                    "mode": "allow",
                    "constraints": ["args.amount <= 500", 'args.currency == "USD"'],
                },
                "emptyin": {"mode": "allow", "constraints": ["args.x in []"]},
            }
        }
    },
}

_ADVERSARIAL_CASES: list[tuple[str, dict, bool]] = [
    ("num", {"amount": 500}, True),  # boundary
    ("num", {"amount": 501}, False),
    ("num", {}, False),  # missing → fail closed
    ("ne", {"currency": "EUR"}, True),
    ("ne", {"currency": "USD"}, False),
    ("ne", {}, False),  # missing → deny on both engines
    ("streq", {"currency": "USD"}, True),
    ("streq", {"currency": "usd"}, False),  # case sensitive
    ("inl", {"tier": "gold"}, True),
    ("inl", {"tier": "bronze"}, False),
    ("inl", {}, False),
    ("notin", {"priority": "low"}, True),
    ("notin", {"priority": "urgent"}, False),
    ("notin", {}, False),  # the case that started this: parity on missing
    ("boolean", {"confirmed": True}, True),
    ("boolean", {"confirmed": False}, False),
    ("isnull", {"note": None}, True),
    ("isnull", {"note": "x"}, False),
    ("isnull", {}, False),
    ("neg", {"delta": -5}, True),
    ("neg", {"delta": -6}, False),
    ("flt", {"ratio": 1.5}, True),
    ("flt", {"ratio": 2.0}, False),
    ("strop", {"label": "a <= b"}, True),  # operator chars inside a string literal
    ("strop", {"label": "other"}, False),
    ("deep", {"payment": {"amount": 50}}, True),
    ("deep", {"payment": {"amount": 200}}, False),
    ("deep", {"payment": {}}, False),  # nested missing
    ("deep", {}, False),
    ("multi", {"amount": 100, "currency": "USD"}, True),
    ("multi", {"amount": 100, "currency": "EUR"}, False),  # one of two fails
    ("multi", {"amount": 999, "currency": "USD"}, False),
    ("emptyin", {"x": 1}, False),  # empty set → nothing matches
]


def _pydantic_allows(policy_dict: dict, role: str, tool: str, args: dict) -> bool:
    ps = load_policy_set_from_dict(policy_dict)
    try:
        authorize_tool_call(ps.policy_for(role), tool, args)
        return True
    except PolicyDeniedError:
        return False


@pytest.mark.parametrize(("tool", "args", "expect"), _ADVERSARIAL_CASES)
def test_adversarial_pydantic(tool: str, args: dict, expect: bool) -> None:
    assert _pydantic_allows(_ADVERSARIAL_POLICY, "default", tool, args) is expect


@pytest.fixture(scope="module")
def _adversarial_wasm() -> bytes:
    import shutil

    if shutil.which("opa") is None:
        pytest.skip("opa not on PATH")
    from hexgate.security import compile_to_wasm

    # This build FAILS if any violation rule is invalid Rego (e.g. the old
    # `not not ... in ...` for `not in`) — a load-bearing regression guard.
    return compile_to_wasm(compile_to_rego(_ADVERSARIAL_POLICY)).wasm


@pytest.mark.parametrize(("tool", "args", "expect"), _ADVERSARIAL_CASES)
def test_adversarial_wasm_matches_pydantic(
    tool: str, args: dict, expect: bool, _adversarial_wasm: bytes
) -> None:
    """The compiled wasm decides identically to pydantic for every case."""
    from hexgate.security import WasmPolicy

    wasm = WasmPolicy.from_bytes(_adversarial_wasm)
    got = wasm.decide(role="default", tool=tool, args=args).allow
    py = _pydantic_allows(_ADVERSARIAL_POLICY, "default", tool, args)
    assert got is py, f"engine divergence for {tool}/{args}: wasm={got} pydantic={py}"
    assert got is expect


def test_notin_violation_rule_is_valid_rego(_adversarial_wasm: bytes) -> None:
    """Regression: a `not in` constraint must not emit `not not ... in ...`."""
    rego = compile_to_rego(_ADVERSARIAL_POLICY)
    assert "not not" not in rego
    # violation body for `not in` is the plain positive membership
    assert 'input.args.priority in ["urgent", "critical"]' in rego
