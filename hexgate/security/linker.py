"""The linker — compose a bundle of policy modules into one effective policy.

The intermediate step between *many policy files* and *one signed WASM bundle*:

    [modules]  --link()-->  one AgentPolicy  --compile_to_rego-->  rego  -->  wasm

Composition lives here, at the model layer. The output is an ordinary
:class:`~hexgate.security.models.AgentPolicy` whose ``constraints`` are the same
strings the DSL already parses, so the pydantic-vs-WASM **parity gate applies to
the resolved policy for free** — the engines never see the stack.

Rules (see ``policy-modules-plan.md``): **fences intersect, grants union, denies
win.** Per ``(tool, args)`` the most restrictive layer wins:
``deny > approval_required > allow > implicit-deny``.

- **Guardrail** — caps + hard denies. An unconditional deny is absolute. A
  ``default_policy: deny`` guardrail is a *ceiling*: a tool it doesn't list is
  ineligible. Its ``allow`` entries are ceilings (permit up to a constraint),
  not grants.
- **Capability** — grants only (``allow`` / ``approval_required``). A capability
  ``deny`` is a :class:`LinkError`. Multiple capabilities granting one tool
  *union* (either condition suffices).

Constraint algebra reuses the existing DSL nodes: intersection is list
concatenation (``constraints: list[str]`` is implicit-AND), union is a top-level
``or`` expression, and a conditional guardrail deny subtracts via ``and not(…)``.
Every assembled expression is re-parsed with :func:`parse_constraint` to validate
against the live grammar.
"""

from __future__ import annotations

from hexgate.security.constraints import parse_constraint
from hexgate.security.models import (
    AgentPolicy,
    BaseToolPolicy,
    FileToolPolicy,
    ToolPolicy,
)
from hexgate.security.modules import (
    LinkError,
    LinkResult,
    ModuleContent,
    Provenance,
    RuleTrace,
)
from hexgate.security.policy_set import DEFAULT_ROLE_NAME, PolicySet

_GRANT_MODES = ("allow", "approval_required")


def link_policy_set(
    guardrails: list[ModuleContent], capabilities: list[ModuleContent]
) -> LinkResult:
    """Fold a bundle into one effective :class:`PolicySet` + provenance.

    ``guardrails`` are the scope-inherited layers (caps/denies); ``capabilities``
    are the imported packs + the agent's inline leaf, in resolution order. This
    iteration folds into the single ``default`` role; per-role scoping is a
    follow-up.
    """
    effective, trace = link(guardrails, capabilities)
    policy_set = PolicySet({DEFAULT_ROLE_NAME: effective})
    layers = [_prov(m) for m in (*guardrails, *capabilities)]
    return LinkResult(
        policy_set=policy_set,
        effective={DEFAULT_ROLE_NAME: effective},
        layers=layers,
        trace=trace,
    )


def link(
    guardrails: list[ModuleContent], capabilities: list[ModuleContent]
) -> tuple[AgentPolicy, RuleTrace]:
    """Fold one role's layers into a single :class:`AgentPolicy`. Pure; no I/O."""
    _reject_file_scope(guardrails, capabilities)
    consts = _merge_consts(guardrails, capabilities)

    trace = RuleTrace()
    tools: dict[str, ToolPolicy] = {}
    for name in _tool_names(guardrails, capabilities):
        rule = _fold_tool(name, guardrails, capabilities, trace)
        if rule is not None:
            tools[name] = rule

    # Effective default is fail-closed: a tool no layer grants is denied.
    effective = AgentPolicy(
        default_policy=BaseToolPolicy(mode="deny"), tools=tools, consts=consts
    )
    return effective, trace


def _merge_consts(
    guardrails: list[ModuleContent], capabilities: list[ModuleContent]
) -> dict[str, object]:
    """Merge consts across layers, **guardrails win**.

    A capability may not redefine a guardrail's constant to a different value —
    that would let a lower-authority layer loosen a guardrail cap expressed as
    ``args.amount <= consts.max`` by shadowing ``max``. Such a collision is a
    hard :class:`LinkError`; a capability-only const is merged normally.
    """
    guard_consts: dict[str, object] = {}
    for module in guardrails:
        guard_consts.update(module.policy.consts)
    merged = dict(guard_consts)
    for cap in capabilities:
        for name, value in cap.policy.consts.items():
            if name in guard_consts and guard_consts[name] != value:
                raise LinkError(
                    f"capability {cap.name!r} redefines guardrail constant "
                    f"consts.{name} ({value!r} vs guardrail {guard_consts[name]!r}); "
                    f"capabilities may not override guardrail constants ({cap.source})"
                )
            merged[name] = value
    return merged


def _reject_file_scope(
    guardrails: list[ModuleContent], capabilities: list[ModuleContent]
) -> None:
    """Reject ``file_scope`` in a module — composing it isn't supported yet.

    Silently dropping it in the fold would erase a path fence (``file_scope`` is
    enforced by the pydantic engine), so fail loud instead. Keep file-scoped
    tools in a single-file policy until module composition supports them.
    """
    for module in (*guardrails, *capabilities):
        for tool_name, tp in module.policy.tools.items():
            if isinstance(tp, FileToolPolicy) and tp.file_scope is not None:
                raise LinkError(
                    f"module {module.name!r} tool {tool_name!r} uses file_scope, "
                    f"which module composition does not support yet — keep it in a "
                    f"single-file policy or drop file_scope ({module.source})"
                )


def _fold_tool(
    tool: str,
    guardrails: list[ModuleContent],
    capabilities: list[ModuleContent],
    trace: RuleTrace,
) -> ToolPolicy | None:
    """Resolve one tool across all layers. ``None`` means implicit-deny (omit)."""
    # Capabilities may only grant. A capability deny is a config error.
    for cap in capabilities:
        tp = cap.policy.tools.get(tool)
        if tp is not None and tp.mode == "deny":
            raise LinkError(
                f"capability {cap.name!r} denies {tool!r}; capabilities may only "
                f"grant — move the deny to a guardrail ({cap.source})"
            )

    # 1. Unconditional guardrail deny wins absolutely. A *conditional* deny
    #    (has constraints) instead subtracts its region from the grant (step 5).
    conditional_denies: list[tuple[ModuleContent, list[str]]] = []
    for g in guardrails:
        tp = g.policy.tools.get(tool)
        if tp is not None and tp.mode == "deny":
            if tp.constraints:
                conditional_denies.append((g, list(tp.constraints)))
            else:
                trace.record(tool, [_prov(g)])
                return BaseToolPolicy(mode="deny")

    # 2. Ceiling eligibility + ceiling constraints. A ceiling guardrail
    #    (default_policy: deny) that doesn't list the tool makes it ineligible.
    contributors: list[Provenance] = []
    ceiling_constraints: list[str] = []
    for g in guardrails:
        tp = g.policy.tools.get(tool)
        is_ceiling = g.policy.default_policy.mode == "deny"
        if tp is not None and tp.mode in _GRANT_MODES:
            ceiling_constraints.extend(tp.constraints)  # fences intersect (AND)
            contributors.append(_prov(g))
        elif tp is None and is_ceiling:
            trace.shadow(tool, _prov(g))
            return None

    # 3+4. Capability grants. No grant → eligible but ungranted → implicit deny.
    grants: list[tuple[ModuleContent, ToolPolicy]] = []
    for cap in capabilities:
        tp = cap.policy.tools.get(tool)
        if tp is not None and tp.mode in _GRANT_MODES:
            grants.append((cap, tp))
    if not grants:
        return None
    contributors.extend(_prov(cap) for cap, _ in grants)

    mode = (
        "approval_required"
        if _any_approval([tp for _, tp in grants], guardrails, tool)
        else "allow"
    )

    # 5. effective = ceiling(AND) ∧ union(grants) ∧ not(conditional denies)
    constraints: list[str] = list(ceiling_constraints)
    union = _union([tp for _, tp in grants])
    if union is not None:
        constraints.append(union)
    for g, region in conditional_denies:
        constraints.append(f"not ({_and_expr(region)})")
        contributors.append(_prov(g))

    for expr in constraints:  # validate the assembled grammar on both engines
        parse_constraint(expr)
    trace.record(tool, contributors)
    return BaseToolPolicy(mode=mode, constraints=constraints)


def _union(grants: list[ToolPolicy]) -> str | None:
    """OR the capability grants into one expression.

    Returns ``None`` when any grant is unconditional (empty constraints) — an
    unconditional grant makes the whole union unconditional, so no constraint is
    emitted for it.
    """
    exprs: list[str] = []
    for tp in grants:
        if not tp.constraints:
            return None
        exprs.append(_and_expr(tp.constraints))
    # One grant needs no OR wrapper; multiple are parenthesised and OR-joined.
    joined = exprs[0] if len(exprs) == 1 else " or ".join(f"({e})" for e in exprs)
    parse_constraint(joined)  # fail loud on assembled grammar we can't parse
    return joined


def _and_expr(constraints: list[str]) -> str:
    """A tool's constraint list → one parenthesised AND-expression."""
    return " and ".join(f"({c})" for c in constraints)


def _any_approval(
    grants: list[ToolPolicy], guardrails: list[ModuleContent], tool: str
) -> bool:
    """Approval is stricter than allow: any approval among grants/ceilings wins."""
    if any(tp.mode == "approval_required" for tp in grants):
        return True
    return any(
        (tp := g.policy.tools.get(tool)) is not None and tp.mode == "approval_required"
        for g in guardrails
    )


def _tool_names(*groups: list[ModuleContent]) -> list[str]:
    names: set[str] = set()
    for group in groups:
        for module in group:
            names.update(module.policy.tools)
    return sorted(names)


def _prov(module: ModuleContent) -> Provenance:
    return Provenance(
        module=module.name,
        kind=module.kind,
        source=module.source,
        content_hash=module.content_hash,
    )
