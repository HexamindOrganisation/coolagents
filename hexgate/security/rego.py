"""Compile a Hexgate ``policy.yaml`` document into a Rego policy module.

The compiler is a pure-Python transformation: parsed YAML payload →
``PolicySet`` (which flattens ``inherits:`` and drops ``is_mixin:`` entries)
→ a Rego source string suitable for ``opa build -t wasm``.

Why this lives in the SDK (not just the platform): the same compiler runs
in three places — the platform's save-time pipeline, the ``hexgate policy
build`` CLI a dev uses for local iteration, and CI/CD wrapper scripts.
Identical artifacts everywhere; the only thing the platform adds is the
Ed25519 signature on the resulting bundle.

Output structure
----------------

The module exposes a single ``decision`` entrypoint that returns the
full verdict as a structured object. The runtime evaluates one query
per tool-call and receives back ``{allow, requires_approval, violations}``:

    package hexgate.policy

    import rego.v1

    default allow := false
    default requires_approval := false

    # The single entrypoint the runtime queries.
    decision := {
        "allow": allow,
        "requires_approval": requires_approval,
        "violations": violations,
    }

    # ---- role: billing ----
    allow if {
        input.role == "billing"
        input.tool == "refund_order"
        input.args.amount <= 500
    }

    violations contains `args.amount <= 500` if {
        input.role == "billing"
        input.tool == "refund_order"
        not input.args.amount <= 500
    }

Deny is implicit — a tool with ``mode: deny`` produces no allow rule and
no violation rules, so ``allow`` stays false and the deny reason is
just "no allow rule matched" (caller's job to surface that).

The ``violations`` set carries the raw constraint string from the YAML
verbatim, so deny reasons in production match exactly what the dev
wrote in their policy file.

Constraint translation
----------------------

The grammar already mirrors Rego conditions, so translation is one step:
each ``args.<field>`` path becomes ``input.args.<field>``. We re-use
:func:`parse_constraint` for the AST so the path / operator / literal are
already structured — we don't text-substitute. Every constraint emits
*two* contributions: one positive (added to the allow rule body) and
one negative (a ``violations contains`` rule).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from hexgate.security.constraints import (
    And,
    Call,
    Cmp,
    ConstRef,
    Count,
    Elem,
    Lit,
    Node,
    Not,
    Operand,
    Or,
    Quant,
    Ref,
    parse_constraint,
)
from hexgate.security.models import (
    AGENT_REACH_PREFIXES,
    AGENT_RUN_TOOL,
    AgentPolicy,
    BaseToolPolicy,
    FileToolPolicy,
)
from hexgate.security.policy_set import (
    DEFAULT_ROLE_NAME,
    PolicySet,
    PolicySetError,
    load_policy_set_from_dict,
)


# Rego operators are mostly a superset of ours. ``not in`` needs special
# handling because Rego writes it as ``not (x in y)``; we wrap the body.
_INFIX_OPS = {"==", "!=", "<", "<=", ">", ">="}
_ORDERED_OPS = {"<", "<=", ">", ">="}  # need a cross-type guard


def compile_to_rego(
    payload: dict[str, Any],
    *,
    package: str = "hexgate.policy",
    source_hash: str | None = None,
) -> str:
    """Render a Rego policy module for ``payload``.

    ``payload`` is the parsed YAML document (the same shape
    :func:`load_policy_set_from_dict` accepts — flat single-policy or
    inline-roles). ``source_hash`` is the sha256 of the original YAML
    source; included in the file header so the artifact is traceable
    back to its source. When ``None``, the header is computed from
    ``payload`` itself.
    """
    policy_set = load_policy_set_from_dict(payload)
    if source_hash is None:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        source_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # Named constants become module-level ``name := value`` rules; collected
    # globally (they must be consistent across roles — see _collect_consts).
    # Undefined-const references are already rejected by PolicySet construction
    # (load_policy_set_from_dict above), so both engines agree on validity.
    consts = _collect_consts(policy_set)

    # Quantifiers register named helper rules here (keyed by name for dedup);
    # emitted after the role rules so the module stays self-contained.
    helpers: dict[str, list[str]] = {}

    lines: list[str] = []
    lines.extend(_header(source_hash, package))
    lines.extend(_decision_scaffold())
    lines.extend(_const_rules(consts))
    lines.extend(_role_rules(policy_set, helpers))
    for name in sorted(helpers):  # sorted → deterministic output
        lines.extend(helpers[name])
        lines.append("")
    lines.extend(_violations_sentinel())
    # Trailing newline — POSIX-friendly + a few editors complain otherwise.
    return "\n".join(lines) + "\n"


def _collect_consts(policy_set: PolicySet) -> dict[str, Any]:
    """Merge every role's constants into one global map for the module.

    Constants are module-level in Rego, so a name must map to a single value
    across roles (the intended pattern is a shared mixin). A name bound to two
    different values is a conflict — fail loud rather than pick one.
    """
    merged: dict[str, Any] = {}
    for role in policy_set.roles:
        for name, value in policy_set.policy_for(role).consts.items():
            if name in merged and merged[name] != value:
                raise PolicySetError(
                    f"constant {name!r} has conflicting values across roles "
                    f"({merged[name]!r} vs {value!r}); constants are global"
                )
            merged[name] = value
    return merged


def _const_rules(consts: dict[str, Any]) -> list[str]:
    """Emit ``name := value`` module-level rules, sorted for determinism."""
    if not consts:
        return []
    out = ["# ---- constants " + "-" * 50]
    for name in sorted(consts):
        out.append(f"{name} := {json.dumps(consts[name])}")
    out.append("")
    return out


def _header(source_hash: str, package: str) -> list[str]:
    return [
        "# Generated by hexgate policy build — do not edit by hand.",
        f"# Compiled from policy.yaml (sha256: {source_hash}).",
        "# Regenerate with: hexgate policy build <source>",
        "",
        f"package {package}",
        "",
        "import rego.v1",
        "",
    ]


def _decision_scaffold() -> list[str]:
    """The top-level decision object + default boolean rules.

    Every rendered module has exactly this scaffold; the per-role rules
    contribute to ``allow``, ``requires_approval``, and ``violations``
    via the rules emitted below.
    """
    return [
        "default allow := false",
        "default requires_approval := false",
        "",
        "# Single entrypoint — runtime queries data.hexgate.policy.decision.",
        "decision := {",
        '    "allow": allow,',
        '    "requires_approval": requires_approval,',
        '    "violations": violations,',
        "}",
        "",
    ]


def _violations_sentinel() -> list[str]:
    """Keep ``violations`` defined even for constraint-free policies.

    Without at least one ``violations contains`` rule in the module,
    opa flags the symbol as unsafe and refuses to build. The sentinel
    body is ``false`` so it never contributes — the set stays empty
    in the happy path.
    """
    return [
        "# Sentinel: keeps `violations` defined even when no constraint rules exist.",
        'violations contains "__never__" if false',
        "",
    ]


def _role_rules(policy_set: PolicySet, helpers: dict[str, list[str]]) -> list[str]:
    """Emit per-role allow / requires_approval / violations rules.

    Roles ordered alphabetically and tools within a role ordered the same
    way so the output is deterministic regardless of dict insertion order
    (Python 3.7+ preserves it, but YAML loaders may differ in edge cases).
    """
    out: list[str] = []
    role_names = sorted(role for role in policy_set.roles)
    non_default = [r for r in role_names if r != DEFAULT_ROLE_NAME]
    for role in role_names:
        policy = policy_set.policy_for(role)
        role_guard = _role_guard(role, non_default)
        rules = list(_rules_for_role(role, policy, role_guard, helpers))
        if not rules:
            # Pure deny — skip the section entirely to keep the output tight.
            continue
        out.append(f"# ---- role: {role} {'-' * (60 - len(role))}")
        out.extend(rules)
    return out


def _role_guard(role: str, non_default: list[str]) -> list[str]:
    """Body line(s) selecting which caller role a rule applies to.

    A named role matches exactly (``input.role == "billing"``). The
    ``default`` role is the *fallback*: it must fire for ``role == "default"``,
    a null/absent role, AND any role not otherwise defined — mirroring
    :meth:`PolicySet.policy_for`'s unknown-role fallback. A single exclusion
    of the other concrete roles covers all three cases at once (and an
    all-deny role, which emits no rules, still stays excluded because it's in
    the concrete-role set passed here).
    """
    if role != DEFAULT_ROLE_NAME:
        return [f'    input.role == "{_escape_string(role)}"']
    if not non_default:
        return []  # default is the only role → it applies to every caller
    members = ", ".join(json.dumps(name) for name in non_default)
    return [f"    not input.role in {{{members}}}"]


def _rules_for_role(
    role: str,
    policy: AgentPolicy,
    role_guard: list[str],
    helpers: dict[str, list[str]],
) -> list[str]:
    """Render rules for one resolved role (allow + violations per tool).

    Explicitly-listed tools each get their own ``input.tool == "X"`` rule
    (including the lowered ``agent.*`` keys in ``effective_tools``);
    ``default_policy`` (when not ``deny``) gets a catch-all for any tool *not*
    explicitly listed — mirroring the pydantic engine's
    ``effective_tools.get(tool, default_policy)`` fallback so both engines agree
    on unlisted tools.
    """
    effective = policy.effective_tools
    listed = sorted(effective)
    out: list[str] = []
    for tool_name in listed:
        tool_guard = [f'    input.tool == "{_escape_string(tool_name)}"']
        out.extend(
            _gated_rules(
                role,
                role_guard,
                tool_guard,
                effective[tool_name],
                tool_name,
                helpers,
            )
        )
    out.extend(_default_rules(role, role_guard, policy.default_policy, listed, helpers))
    return out


def _default_rules(
    role: str,
    role_guard: list[str],
    default_policy: BaseToolPolicy,
    listed: list[str],
    helpers: dict[str, list[str]],
) -> list[str]:
    """Catch-all rules for ``default_policy`` — any tool not explicitly listed.

    ``deny`` (the default) emits nothing: absence of a rule IS the deny. For
    ``allow`` / ``approval_required`` the tool guard excludes the listed tools
    so they keep using their own policy.
    """
    if default_policy.mode == "deny":
        return []
    # Agent keys are closed-world: a permissive default must not grant an unlisted
    # agent key, so exclude them from the catch-all (an unlisted agent key then
    # matches no rule and denies). Excludes exactly the reserved shapes — agent.run
    # and the reach prefixes — so an authored tool merely named "agent.foo" still
    # follows the default, matching is_agent_key in the pydantic engine (R-AGENT-002).
    tool_guard = [f"    input.tool != {json.dumps(AGENT_RUN_TOOL)}"]
    tool_guard += [
        f"    not startswith(input.tool, {json.dumps(prefix)})"
        for prefix in AGENT_REACH_PREFIXES
    ]
    if listed:
        members = ", ".join(json.dumps(name) for name in listed)
        tool_guard.append(f"    not input.tool in {{{members}}}")
    return _gated_rules(
        role, role_guard, tool_guard, default_policy, "<default>", helpers
    )


def _gated_rules(
    role: str,
    role_guard: list[str],
    tool_guard: list[str],
    tool_policy: BaseToolPolicy,
    label: str,
    helpers: dict[str, list[str]],
) -> list[str]:
    """Render the positive + per-constraint violation rules for one policy.

    ``role_guard`` / ``tool_guard`` are the body line(s) selecting which
    caller(s) and tool(s) the rule applies to. ``label`` names the tool (or
    ``<default>``) for constraint parse errors.

    ``deny`` mode emits nothing — absence of a rule IS the deny.
    """
    if tool_policy.mode == "deny":
        return []
    # file_scope is a pydantic-engine-only feature — the Rego compiler has no
    # path-glob translation yet, so silently dropping it would compile to a
    # FAIL-OPEN bundle (the path restriction lost, every path allowed). Refuse
    # to build rather than ship a bundle weaker than the source policy. Only
    # matters for non-deny modes (deny never consults file_scope on either
    # engine), so this is reached after the deny short-circuit above.
    if isinstance(tool_policy, FileToolPolicy) and tool_policy.file_scope is not None:
        raise PolicySetError(
            f"role {role!r} tool {label!r}: file_scope is not supported by the "
            "WASM/Rego engine yet — compiling would produce a fail-open bundle "
            "(the path restriction silently dropped). Enforce this policy on the "
            "pydantic engine, or remove file_scope before building a bundle."
        )
    head = "allow" if tool_policy.mode == "allow" else "requires_approval"

    # Parse all constraints up-front — surfaces bad grammar at compile time.
    parsed: list[tuple[str, Node]] = []
    for raw_constraint in tool_policy.constraints:
        try:
            parsed.append((raw_constraint, parse_constraint(raw_constraint)))
        except Exception as exc:
            raise PolicySetError(
                f"role {role!r} tool {label!r}: invalid constraint "
                f"{raw_constraint!r}: {exc}"
            ) from exc

    guard = [*role_guard, *tool_guard]
    out: list[str] = []
    out.extend(_positive_rule(guard, head, parsed, helpers))
    out.append("")
    for raw, node in parsed:
        out.extend(_violation_rule(guard, raw, node, helpers))
        out.append("")
    return out


def _positive_rule(
    guard: list[str],
    head: str,
    parsed: list[tuple[str, Node]],
    helpers: dict[str, list[str]],
) -> list[str]:
    """``allow if { <guard>; constraint1; constraint2; ... }``."""
    body = list(guard)
    for _, node in parsed:
        if isinstance(node, (Cmp, Call)):
            # may render to multiple lines (an ordered-comparison type guard)
            body.extend(f"    {line}" for line in _inline(node, None, helpers))
        else:
            body.append(f"    {_node_to_rego(node, helpers)}")
    if not body:
        # Unconditional rule (only-default role, default_policy allow, no
        # tools/constraints) — an empty ``{}`` body is invalid Rego.
        body = ["    true"]
    return [f"{head} if {{", *body, "}"]


def _violation_rule(
    guard: list[str],
    raw_constraint: str,
    node: Node,
    helpers: dict[str, list[str]],
) -> list[str]:
    """``violations contains <raw> if { <guard>; not constraint }``.

    The membership value is the original constraint string from the YAML
    so deny reasons match exactly what the dev wrote.
    """
    return [
        f"violations contains {_rego_string(raw_constraint)} if {{",
        *guard,
        f"    {_negated_node_to_rego(node, helpers)}",
        "}",
    ]


def _negated_node_to_rego(node: Node, helpers: dict[str, list[str]]) -> str:
    """Render the logical negation of a node (violation rule + ``not`` operator).

    Always negates a *rule reference*, never an inline expression. This is the
    crucial correctness point: pydantic treats a missing field as a hard False
    (``not`` of it is True), but Rego's inline ``not (undefined < 1)`` fails
    (denies). A rule ``_p if { <cond> }`` is 2-valued from the outside — it
    fails cleanly on a missing field — so ``not _p`` matches pydantic for every
    operator. It also sidesteps the invalid ``not not … in …`` for ``not in``.

    Compound nodes already register their own helper, so negate that directly.
    """
    if isinstance(node, (Cmp, Call)):
        return f"not {_register_pos_helper(node, helpers)}"
    return f"not {_node_to_rego(node, helpers)}"


def _register_pos_helper(node: Node, helpers: dict[str, list[str]]) -> str:
    """Emit ``_p_<hash> if { <positive rendering> }`` once; return the name.

    Wrapping a leaf's positive form in a rule makes it 2-valued (a missing
    field fails the rule rather than propagating ``undefined``), so callers can
    negate it with a plain ``not _p_<hash>``.
    """
    name = f"_p_{_node_hash(node)}"
    if name not in helpers:
        body = _inline(node, None, helpers)
        helpers[name] = [f"{name} if {{", *(f"    {line}" for line in body), "}"]
    return name


def _node_to_rego(node: Node, helpers: dict[str, list[str]]) -> str:
    """Render a compound node as a single Rego helper reference.

    Only compounds (Quant / And / Or / Not) go through here — each registers a
    named helper so it can be negated cleanly. Cmp / Call may render to multiple
    lines (type guards), so they go through :func:`_inline` instead.
    """
    if isinstance(node, Quant):
        return _register_quant_helper(node, helpers)
    if isinstance(node, (And, Or, Not)):
        return _register_bool_helper(node, helpers)
    # Unreachable — Cmp/Call are rendered via _inline.
    raise PolicySetError(f"cannot render node {node!r} as a single token")


def _node_hash(node: Node) -> str:
    """Stable short id for a node — deterministic helper/loop-var names."""
    return hashlib.sha256(repr(node).encode("utf-8")).hexdigest()[:10]


def _register_quant_helper(node: Quant, helpers: dict[str, list[str]]) -> str:
    """Emit ``_q_<hash> if { <quantifier> }`` once; return the rule name."""
    name = f"_q_{_node_hash(node)}"
    if name not in helpers:
        body = _inline(node, None, helpers)
        helpers[name] = [f"{name} if {{", *(f"    {line}" for line in body), "}"]
    return name


def _register_quant_body_fn(
    node: Quant, param: str, helpers: dict[str, list[str]]
) -> str:
    """Emit a parameterized predicate ``_qb_<hash>(e) if { <body> }``; return name.

    ``param`` is the loop variable the caller binds the element to; the body is
    rendered with ``.`` → ``param``. A function is 2-valued per element, so a
    type error or missing sub-field fails that element instead of leaving the
    quantifier body undefined.
    """
    name = f"_qb_{_node_hash(node)}"
    if name not in helpers:
        body = _inline(node.body, param, helpers)
        helpers[name] = [f"{name}({param}) if {{", *(f"    {b}" for b in body), "}"]
    return name


def _register_bool_helper(node: Node, helpers: dict[str, list[str]]) -> str:
    """Emit a helper rule for a boolean node; return its name.

    ``Or`` becomes one rule *per disjunct* under the same head (Rego rules with
    a shared head are OR-ed); ``And`` is a single conjunction rule; ``Not`` is
    ``not <negation-of-inner>``. The allow rule references the name and the
    violation rule negates it (``not _c_<hash>``) — the correct De Morgan.
    """
    name = f"_c_{_node_hash(node)}"
    if name in helpers:
        return name
    rules: list[str] = []
    if isinstance(node, Or):
        for part in node.parts:
            body = _inline(part, None, helpers)
            rules += [f"{name} if {{", *(f"    {b}" for b in body), "}"]
    elif isinstance(node, And):
        body = _inline(node, None, helpers)
        rules += [f"{name} if {{", *(f"    {b}" for b in body), "}"]
    else:  # Not
        cond = _negated_node_to_rego(node.inner, helpers)
        rules += [f"{name} if {{", f"    {cond}", "}"]
    helpers[name] = rules
    return name


def _inline(
    node: Node, elem_var: str | None, helpers: dict[str, list[str]]
) -> list[str]:
    """Render a node as Rego body line(s), with ``.`` bound to ``elem_var``.

    Used inside quantifier bodies and helper-rule bodies. A quantifier expands
    to an ``every``/``some`` block; ``And`` flattens to conjunction lines; an
    ``Or`` / ``Not`` can't inline, so it registers its own helper and returns a
    reference.
    """
    if isinstance(node, Cmp):
        return _cmp_to_rego(node, elem_var, helpers)
    if isinstance(node, Call):
        return [_call_to_rego(node, elem_var)]
    if isinstance(node, Quant):
        var = f"__e_{_node_hash(node)}"
        coll = _render(node.ref, elem_var)
        # The per-element predicate is a parameterized function, not an inline
        # block: a function is 2-valued (a per-element type error / missing
        # sub-field fails the element), so `every`/`some` match pydantic instead
        # of Rego treating an undefined element body as vacuously satisfied.
        fn = _register_quant_body_fn(node, var, helpers)
        if node.kind == "every":
            return [f"every {var} in {coll} {{ {fn}({var}) }}"]
        # any → existential: bind the element, then assert the predicate holds.
        return [f"some {var} in {coll}", f"{fn}({var})"]
    if isinstance(node, And):
        lines: list[str] = []
        for part in node.parts:
            lines += _inline(part, elem_var, helpers)
        return lines
    if isinstance(node, Or):
        return [_register_bool_helper(node, helpers)]
    if isinstance(node, Not):
        return [_negated_node_to_rego(node.inner, helpers)]
    raise PolicySetError(f"cannot render node {node!r}")


def _call_to_rego(node: Call, elem_var: str | None = None) -> str:
    """Render a string function as its Rego builtin call."""
    ref = _render(node.arg, elem_var)
    value = json.dumps(node.value.value)
    if node.fn == "matches":
        # Rego's regex.match takes (pattern, value) and is unanchored — same
        # as the pydantic engine's re.search.
        return f"regex.match({value}, {ref})"
    return f"{node.fn}({ref}, {value})"


def _cmp_to_rego(
    node: Cmp, elem_var: str | None, helpers: dict[str, list[str]]
) -> list[str]:
    """Render a comparison as one or more Rego condition lines.

    Path translation: ``args.amount`` → ``input.args.amount``. Ordered
    comparisons (``< <= > >=``) also emit a type guard so a cross-type pairing
    fails closed (matching the pydantic engine) — without it Rego's total order
    across types would, e.g., make ``"evil" > 10`` true and let a wrong-typed
    argument slip past a numeric gate.
    """
    lhs = _render(node.left, elem_var)
    rhs = _render(node.right, elem_var)
    op = node.op
    if op in ("==", "!="):
        return [f"{lhs} {op} {rhs}"]
    if op == "in":
        return [f"{lhs} in {rhs}"]
    if op == "not in":
        # Rego negates the whole ``in`` expression; semantically identical
        # to "not present in the set."
        return [f"not {lhs} in {rhs}"]
    if op in _ORDERED_OPS:
        return _ordered_cmp_rego(node, lhs, rhs, op, elem_var, helpers)
    # Unreachable given parse_constraint's whitelist, but defensive.
    raise PolicySetError(f"unsupported constraint operator {op!r}")


def _numstr_hint(operand: Operand) -> str | None:
    """The comparable type an operand pins ('number'/'string'), 'bad' for a
    non-comparable literal (bool/null/list), or None when unknown (a ref)."""
    if isinstance(operand, Count):
        return "number"
    if isinstance(operand, Lit):
        v = operand.value
        if isinstance(v, bool):
            return "bad"
        if isinstance(v, (int, float)):
            return "number"
        if isinstance(v, str):
            return "string"
        return "bad"
    return None


def _ordered_cmp_rego(
    node: Cmp,
    lhs: str,
    rhs: str,
    op: str,
    elem_var: str | None,
    helpers: dict[str, list[str]],
) -> list[str]:
    """Ordered comparison with a type guard so cross-type fails closed."""
    hint_l, hint_r = _numstr_hint(node.left), _numstr_hint(node.right)
    if "bad" in (hint_l, hint_r):
        # ordered comparison against a non-number/string literal never holds
        return ["false"]
    known = hint_l or hint_r
    if known is not None:
        guards = [
            f"is_{known}({rendered})"
            for operand, rendered in ((node.left, lhs), (node.right, rhs))
            if _numstr_hint(operand) is None  # a ref/const/elem of unknown type
        ]
        return [*guards, f"{lhs} {op} {rhs}"]
    # Both sides unknown-typed (cross-field): require the same comparable type.
    # Only reachable at the top level (quant bodies compare against a literal).
    if elem_var is not None:
        raise PolicySetError(
            "cross-field ordered comparison inside a quantifier body is not supported"
        )
    name = f"_ord_{_node_hash(node)}"
    if name not in helpers:
        helpers[name] = [
            f"{name} if {{ is_number({lhs}); is_number({rhs}); {lhs} {op} {rhs} }}",
            f"{name} if {{ is_string({lhs}); is_string({rhs}); {lhs} {op} {rhs} }}",
        ]
    return [name]


def _render(operand: Operand, elem_var: str | None = None) -> str:
    """Render an operand as Rego source.

    A ``Ref`` becomes an ``input.``-prefixed accessor; an ``Elem`` becomes the
    enclosing quantifier's loop variable (optionally with a sub-field); a
    ``Lit`` becomes a JSON literal (Rego's literal grammar is a superset of
    JSON for the shapes we accept).
    """
    if isinstance(operand, Ref):
        return "input." + ".".join(operand.path)
    if isinstance(operand, Count):
        return f"count(input.{'.'.join(operand.ref.path)})"
    if isinstance(operand, Elem):
        if elem_var is None:  # guarded by parse-time element-scope check
            raise PolicySetError("element reference outside a quantifier")
        return elem_var if not operand.path else elem_var + "." + ".".join(operand.path)
    if isinstance(operand, ConstRef):
        # References a module-level ``<name> := <value>`` rule (validated +
        # emitted by compile_to_rego).
        return operand.name
    if isinstance(operand, Lit):
        return json.dumps(operand.value)
    raise PolicySetError(f"cannot render operand {operand!r}")


def _escape_string(value: str) -> str:
    """Escape a Python string for safe embedding inside Rego ``"..."``.

    Same rules as JSON: backslashes and double-quotes need escaping. We
    use json.dumps + slice to share the implementation.
    """
    return json.dumps(value)[1:-1]


def _rego_string(value: str) -> str:
    """Render a string as a Rego literal — backticks when safe, else JSON.

    Backticks are Rego's raw-string syntax: no escape processing inside.
    That's perfect for constraint strings like ``args.currency in ["USD"]``
    where double-quote escaping would be noisy. The fallback to JSON
    handles the rare case where the constraint itself contains a backtick.
    """
    if "`" not in value:
        return f"`{value}`"
    return json.dumps(value)


def compile_default_only(
    policy: AgentPolicy, *, package: str = "hexgate.policy"
) -> str:
    """Compile a flat single-policy ``AgentPolicy`` as a one-role module.

    Convenience for callers that already have an ``AgentPolicy`` model in
    hand (e.g. legacy single-policy agents). Wraps it as the ``default``
    role and delegates to :func:`compile_to_rego`.
    """
    payload = {
        "version": policy.version,
        "roles": {DEFAULT_ROLE_NAME: policy.model_dump(exclude_defaults=False)},
    }
    return compile_to_rego(payload, package=package)
