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

- **Boundary** — caps + hard denies. An unconditional deny is absolute. A
  ``default_policy: deny`` boundary is a *ceiling*: a tool it doesn't list is
  ineligible. Its ``allow`` entries are ceilings (permit up to a constraint),
  not grants.
- **Capability** — grants only (``allow`` / ``approval_required``). A capability
  ``deny`` is a :class:`LinkError`. Multiple capabilities granting one tool
  *union* (either condition suffices).

Constraint algebra reuses the existing DSL nodes: intersection is list
concatenation (``constraints: list[str]`` is implicit-AND), union is a top-level
``or`` expression, and a conditional boundary deny subtracts via ``and not(…)``.
Every assembled expression is re-parsed with :func:`parse_constraint` to validate
against the live grammar.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from hexgate.security.constraints import parse_constraint
from hexgate.security.models import (
    AgentPolicy,
    BaseToolPolicy,
    FileToolPolicy,
    ToolPolicy,
    is_agent_key,
)
from hexgate.security.modules import (
    DEFAULT_AGENT,
    GRANT_MODES,
    LinkError,
    LinkResult,
    ModuleContent,
    ProjectLinkResult,
    Provenance,
    RoleMatrix,
    RuleTrace,
)
from hexgate.security.policy_set import DEFAULT_ROLE_NAME, PolicySet


def link_policy_set(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> LinkResult:
    """Fold a bundle into one effective :class:`PolicySet` + provenance.

    ``boundaries`` are the scope-inherited layers (caps/denies); ``capabilities``
    are the imported packs + the agent's inline leaf, in resolution order. This
    iteration folds into the single ``default`` role; per-role scoping is a
    follow-up.
    """
    effective, trace = link(boundaries, capabilities)
    policy_set = PolicySet({DEFAULT_ROLE_NAME: effective})
    layers = [_prov(m) for m in (*boundaries, *capabilities)]
    return LinkResult(
        policy_set=policy_set,
        effective={DEFAULT_ROLE_NAME: effective},
        layers=layers,
        trace=trace,
    )


def resolve_role_map(
    roles: RoleMatrix | Mapping[str, Sequence[str]] | None,
    library: list[ModuleContent],
    agent: str = DEFAULT_AGENT,
) -> dict[str, list[ModuleContent]]:
    """Expand a role binding into ``{role: [capability modules]}`` for one agent.

    The one place that defines role expansion, shared by the resolver and the
    analyzer so they can never lint a different role set than what compiles.

    ``agent`` is the executing agent name. Per role, its binding is the agent's
    own cell if named, else the ``"*"`` generic cell, else empty (fail-closed) —
    the ``(role, agent) -> (role, "*") -> deny`` fallback. A named agent's cell
    **replaces** ``"*"`` (it does not merge), so an agent can be more restricted.

    ``roles is None`` (no ``roles.yaml``) means a single ``default`` importing
    every capability — the all-compose back-compat default, agent-independent. An
    **empty** binding (``{}``, a present-but-empty or typo'd ``roles.yaml``) is
    not the same: it yields a fail-closed empty ``default``, so a mistake can't
    silently widen access. A ``default`` bucket is always present. An unknown
    capability name is a :class:`LinkError` (same contract from both callers).
    """
    index: dict[str, ModuleContent] = {cap.name: cap for cap in library}
    if roles is None:
        names_by_role: dict[str, list[str]] = {
            DEFAULT_ROLE_NAME: [cap.name for cap in library]
        }
    else:
        names_by_role = {}
        for role, cells in roles.items():
            if isinstance(cells, Mapping):  # the (role, agent) matrix
                binding = cells.get(agent) or cells.get(DEFAULT_AGENT)
                names_by_role[role] = list(binding.capabilities) if binding else []
            else:  # legacy flat `role: [names]` — agent-independent, = the "*" cell
                names_by_role[role] = list(cells)
    names_by_role.setdefault(DEFAULT_ROLE_NAME, [])

    resolved: dict[str, list[ModuleContent]] = {}
    for role, cap_names in names_by_role.items():
        caps: list[ModuleContent] = []
        for name in cap_names:
            cap = index.get(name)
            if cap is None:
                raise LinkError(
                    f"role {role!r} agent {agent!r} imports unknown capability "
                    f"{name!r} (known capabilities: {sorted(index)!r})"
                )
            caps.append(cap)
        resolved[role] = caps
    return resolved


def resolve_for_project(
    boundaries: list[ModuleContent],
    library: list[ModuleContent],
    roles: RoleMatrix | None,
    *,
    agent: str = DEFAULT_AGENT,
) -> ProjectLinkResult:
    """Resolve a project into one role-keyed :class:`PolicySet`, **for one agent**.

    ``agent`` names the executing agent whose column of the ``(role, agent)``
    matrix to resolve (defaulting to the ``"*"`` generic agent — the whole-project
    view and the back-compat path). Each agent gets its own role-keyed result;
    the caller folds one bundle per agent (Path A: the agent dimension is resolved
    away here, so the compiled bundle and the engines stay role-keyed).

    Boundaries are role- *and* agent-independent global ceilings: every role is
    folded against the same ``boundaries``, so no role or agent can widen its
    ceiling. A ``(role, agent)`` cell names the **capabilities** it imports; the
    fold (:func:`link`) is reused unchanged, once per role.

    ``roles`` is the normalized matrix (``role -> agent-or-"*" -> AgentBinding``).
    ``None`` (no binding at all) means a single ``default`` role importing every
    capability — the all-compose back-compat path. A ``default`` role is always
    present, so unroled callers get fail-closed deny rather than a missing bucket.

    Every capability in the library is validated up front
    (:func:`_reject_capability_denies`), not just the ones a role imports, so a
    malformed but unbound module fails loudly instead of lurking until bound.
    """
    _reject_capability_denies(library)
    resolved = resolve_role_map(roles, library, agent)
    by_role: dict[str, LinkResult] = {}
    effective: dict[str, AgentPolicy] = {}
    for role, caps in resolved.items():
        result = link_policy_set(boundaries, caps)
        by_role[role] = result
        effective[role] = result.effective[DEFAULT_ROLE_NAME]

    return ProjectLinkResult(policy_set=PolicySet(effective), by_role=by_role)


def effective_policy_by_role(
    result: ProjectLinkResult, roles: Sequence[str] | None = None
) -> dict[str, dict]:
    """Role -> effective-policy JSON dict, in a canonical (sorted) role order.

    The single serializer shared by ``hexgate policy resolve`` and the platform's
    resolved-policy YAML, so the same project emits identical bytes from either
    (the two used to iterate ``by_role`` in different orders — CLI sorted, the
    platform in insertion order — quietly breaking that parity). ``roles``
    narrows to a subset in the given order; ``None`` yields every role, sorted.
    """
    names = sorted(result.by_role) if roles is None else list(roles)
    return {
        name: result.by_role[name].effective[DEFAULT_ROLE_NAME].model_dump(mode="json")
        for name in names
    }


def _reject_capability_denies(capabilities: Sequence[ModuleContent]) -> None:
    """A capability that denies is a config error, checked over the WHOLE library.

    The per-tool guard in :func:`_fold_tool` only runs for capabilities a role
    imports, so an unbound malformed module would slip through resolution. This
    is a per-module property (a capability tool with ``mode: deny``), so it is
    hoisted here and run over every capability, bound or not.
    """
    for cap in capabilities:
        # effective_tools, so a capability that denies an agent key (a lowered
        # agents:/admission deny) is caught too — capabilities grant only.
        for tool, tp in cap.policy.effective_tools.items():
            if tp.mode == "deny":
                raise LinkError(
                    f"capability {cap.name!r} denies {tool!r}; capabilities may "
                    f"only grant — move the deny to a boundary ({cap.source})"
                )


def link(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> tuple[AgentPolicy, RuleTrace]:
    """Fold one role's layers into a single :class:`AgentPolicy`. Pure; no I/O."""
    _reject_file_scope(boundaries, capabilities)
    _reject_unsupported_module_fields(boundaries, capabilities)
    _reject_default_policy_constraints(boundaries, capabilities)
    consts = _merge_consts(boundaries, capabilities)

    trace = RuleTrace()
    tools: dict[str, ToolPolicy] = {}
    for name in _tool_names(boundaries, capabilities):
        rule = _fold_tool(name, boundaries, capabilities, trace)
        if rule is not None:
            tools[name] = rule

    # Effective default is fail-closed: a tool no layer grants is denied. The
    # folded map may include lowered agent.* keys (composed agent-level blocks),
    # so build through the resolved path, which carries them in tools directly.
    effective = AgentPolicy.resolved(
        default_policy=BaseToolPolicy(mode="deny"), tools=tools, consts=consts
    )
    return effective, trace


def _merge_consts(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> dict[str, object]:
    """Merge consts across layers. A constant defined twice with **different**
    values is a hard :class:`LinkError`, never a silent last-wins.

    Two collisions matter: a capability redefining a boundary's constant would
    let a lower-authority layer loosen a cap like ``args.amount <= consts.max``;
    and two boundaries disagreeing on a value would silently pick one. Both are
    rejected. Equal values (or a name unique to one module) merge normally.
    """
    merged: dict[str, object] = {}
    owner: dict[str, ModuleContent] = {}
    owner_is_boundary: dict[str, bool] = {}

    def _put(module: ModuleContent, is_boundary: bool) -> None:
        for name, value in module.policy.consts.items():
            if name in merged and merged[name] != value:
                prev = owner[name]
                if owner_is_boundary[name] and not is_boundary:
                    raise LinkError(
                        f"capability {module.name!r} redefines boundary constant "
                        f"consts.{name} ({value!r} vs {merged[name]!r} from "
                        f"{prev.name!r}); capabilities may not override boundary "
                        f"constants ({module.source})"
                    )
                raise LinkError(
                    f"consts.{name} defined twice with conflicting values: "
                    f"{merged[name]!r} in {prev.name!r} vs {value!r} in "
                    f"{module.name!r} ({module.source})"
                )
            merged[name] = value
            owner[name] = module
            owner_is_boundary[name] = is_boundary

    for module in boundaries:
        _put(module, is_boundary=True)
    for module in capabilities:
        _put(module, is_boundary=False)
    return merged


def _reject_default_policy_constraints(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> None:
    """Reject ``default_policy.constraints`` in a module.

    The fold reads a boundary's ``default_policy.mode`` (to tell a ceiling from a
    floor) but the effective default is always fail-closed ``deny``, so any
    constraints on a module's ``default_policy`` would be silently dropped. The
    pydantic engine does enforce them in a single-file policy, so dropping them
    on a migration would quietly lose a fence. Fail loud instead; put the rule on
    a named tool.
    """
    for module in (*boundaries, *capabilities):
        if module.policy.default_policy.constraints:
            raise LinkError(
                f"module {module.name!r} sets default_policy constraints, which "
                f"module composition does not support (the effective default is "
                f"fail-closed deny); move the rule onto a named tool "
                f"({module.source})"
            )


def _reject_file_scope(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> None:
    """Reject ``file_scope`` in a module — composing it isn't supported yet.

    Silently dropping it in the fold would erase a path fence (``file_scope`` is
    enforced by the pydantic engine), so fail loud instead. Keep file-scoped
    tools in a single-file policy until module composition supports them.
    """
    for module in (*boundaries, *capabilities):
        for tool_name, tp in module.policy.tools.items():
            if isinstance(tp, FileToolPolicy) and tp.file_scope is not None:
                raise LinkError(
                    f"module {module.name!r} tool {tool_name!r} uses file_scope, "
                    f"which module composition does not support yet — keep it in a "
                    f"single-file policy or drop file_scope ({module.source})"
                )


# The AgentPolicy fields the fold understands. Anything else a module sets is
# rejected by _reject_unsupported_module_fields, so a field added to AgentPolicy
# later fails closed here instead of being silently dropped by _fold_tool.
_MODULE_COMPOSABLE_FIELDS = frozenset(
    {
        "version",
        "inherits",
        "is_mixin",
        "default_policy",
        "tools",
        "consts",
        # Agent-level blocks lower to agent.* keys the fold composes like tools
        # (a boundary agent-deny is authoritative, a capability agent-grant unions).
        "admission",
        "agents",
    }
)


def _reject_unsupported_module_fields(
    boundaries: list[ModuleContent], capabilities: list[ModuleContent]
) -> None:
    """Reject any top-level AgentPolicy field a module sets that the fold does not
    compose (whatever is added next).

    The fold composes ``tools`` and the lowered ``agent.*`` keys from
    ``effective_tools``, so an un-composed field would be silently dropped, erasing
    a rule an operator authored — the same fail-open :func:`_reject_file_scope`
    guards against, generalized. Allowlisting the fields the fold understands means
    a new AgentPolicy field is rejected automatically until composition learns it,
    rather than shipping fail-open by omission."""
    for module in (*boundaries, *capabilities):
        extra = module.policy.model_fields_set - _MODULE_COMPOSABLE_FIELDS
        if extra:
            raise LinkError(
                f"module {module.name!r} sets {sorted(extra)}, which module "
                f"composition does not support (the fold composes only tools); "
                f"keep it in a single-file policy ({module.source})"
            )


def _fold_tool(
    tool: str,
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    trace: RuleTrace,
) -> ToolPolicy | None:
    """Resolve one tool across all layers. ``None`` means implicit-deny (omit)."""
    # Capabilities may only grant. A capability deny is a config error.
    for cap in capabilities:
        tp = cap.policy.effective_tools.get(tool)
        if tp is not None and tp.mode == "deny":
            raise LinkError(
                f"capability {cap.name!r} denies {tool!r}; capabilities may only "
                f"grant — move the deny to a boundary ({cap.source})"
            )

    # 1. Unconditional boundary deny wins absolutely. A *conditional* deny
    #    (has constraints) instead subtracts its region from the grant (step 5).
    conditional_denies: list[tuple[ModuleContent, list[str]]] = []
    for g in boundaries:
        tp = g.policy.effective_tools.get(tool)
        if tp is not None and tp.mode == "deny":
            if tp.constraints:
                conditional_denies.append((g, list(tp.constraints)))
            else:
                trace.record(tool, [_prov(g)])
                return BaseToolPolicy(mode="deny")

    # 2. Ceiling eligibility + ceiling constraints. A ceiling boundary
    #    (default_policy: deny) that doesn't list the tool makes it ineligible.
    contributors: list[Provenance] = []
    ceiling_constraints: list[str] = []
    for g in boundaries:
        tp = g.policy.effective_tools.get(tool)
        is_ceiling = g.policy.default_policy.mode == "deny"
        if tp is not None and tp.mode in GRANT_MODES:
            ceiling_constraints.extend(tp.constraints)  # fences intersect (AND)
            contributors.append(_prov(g))
        elif is_ceiling and (tp is None or tp.mode not in GRANT_MODES):
            # A ceiling only permits tools it explicitly allows/approves. If it
            # doesn't (unlisted, or mentioned only via a conditional deny), the
            # tool is ineligible — a capability grant can't make it eligible.
            trace.shadow(tool, _prov(g))
            # For an ordinary tool, dropping it (None) IS the implicit deny. An
            # agent key must instead stay as an explicit deny: the gate's
            # engagement is derived from whether the resolved policy still carries
            # the key (declares_admission / declares_reach), so a shadowed-away
            # agent.run would silently DISENGAGE the gate (admit everyone) rather
            # than deny — a fail-open. Keep it present and closed.
            return BaseToolPolicy(mode="deny") if is_agent_key(tool) else None

    # 3+4. Capability grants. No grant → eligible but ungranted → implicit deny.
    grants: list[tuple[ModuleContent, ToolPolicy]] = []
    for cap in capabilities:
        tp = cap.policy.effective_tools.get(tool)
        if tp is not None and tp.mode in GRANT_MODES:
            grants.append((cap, tp))
    if not grants:
        # Same reasoning as the ceiling-shadow branch above: for an ordinary tool
        # omission IS the implicit deny, but an ungranted agent key must stay an
        # explicit deny — dropping it removes agent.run/agent.<via>: from the
        # resolved policy, so declares_admission()/declares_reach() reads it as
        # absent and disengages the gate (admit everyone) instead of denying.
        return BaseToolPolicy(mode="deny") if is_agent_key(tool) else None
    contributors.extend(_prov(cap) for cap, _ in grants)

    mode = (
        "approval_required"
        if _any_approval([tp for _, tp in grants], boundaries, tool)
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
    grants: list[ToolPolicy], boundaries: list[ModuleContent], tool: str
) -> bool:
    """Approval is stricter than allow: any approval among grants/ceilings wins."""
    if any(tp.mode == "approval_required" for tp in grants):
        return True
    return any(
        (tp := g.policy.effective_tools.get(tool)) is not None
        and tp.mode == "approval_required"
        for g in boundaries
    )


def _tool_names(*groups: list[ModuleContent]) -> list[str]:
    names: set[str] = set()
    for group in groups:
        for module in group:
            # effective_tools, so lowered agent.* keys are folded like tool keys.
            names.update(module.policy.effective_tools)
    return sorted(names)


def _prov(module: ModuleContent) -> Provenance:
    return Provenance(
        module=module.name,
        kind=module.kind,
        source=module.source,
        content_hash=module.content_hash,
    )
