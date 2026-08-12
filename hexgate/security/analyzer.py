"""Analyze a linked policy bundle for authoring problems — the lint layer.

The linker (:mod:`hexgate.security.linker`) *raises* :class:`LinkError` for the
unfixable cases (a capability that denies, a conflicting const, ``file_scope`` in
a module). This module runs over a **successfully linked** bundle and reports the
*soft* problems that don't stop composition but are almost always mistakes:

- **dead-grant** — a capability grants a tool a boundary ceiling excludes, so the
  grant never fires.
- **redundant-grant** — two capabilities grant the same tool identically.
- **unknown-tool** / **unknown-arg** — a rule references a tool or arg absent from
  the agent's manifest (drift between policy and code). Only checked when a
  manifest is supplied; boundary drift is fail-open, so it's an error.
- **permissive-default** — the ``default`` role grants something no named role
  grants (:func:`check_default_role_exposure`, over a resolved role map).

Every :class:`PolicyLint` carries the ``source`` file it attributes to — the same
contract the CLI (`hexgate policy check`) and the dashboard editor both consume.
Deferred (needs a solver): semantic conflicts — empty intersection, always-true /
always-false, subsumption.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Literal

from hexgate.security.constraints import (
    ConstraintParseError,
    iter_arg_refs,
    parse_constraint,
)
from hexgate.security.linker import (
    link_policy_set,
    resolve_for_project,
    resolve_role_map,
)
from hexgate.security.modules import (
    GRANT_MODES,
    LayerKind,
    LinkError,
    LinkResult,
    ModuleContent,
    ProjectLinkResult,
)
from hexgate.security.policy_set import DEFAULT_ROLE_NAME, PolicySet, PolicySetError

if TYPE_CHECKING:  # avoid importing the manifest package eagerly
    from hexgate.manifest.models import AgentManifest

Severity = Literal["error", "warning", "info"]
SEVERITY_RANK: dict[Severity, int] = {"error": 0, "warning": 1, "info": 2}


@dataclass(frozen=True)
class PolicyLint:
    """One authoring problem, attributed to the file that caused it.

    ``line`` is ``None`` for now (file-level attribution); line-level lands with
    YAML position tracking in the loader. ``tier`` / ``tool`` are set when known.
    """

    code: str
    severity: Severity
    message: str
    source: str | None = None
    line: int | None = None
    tier: LayerKind | None = None
    tool: str | None = None
    role: str | None = None


def check(
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    *,
    manifest: AgentManifest | None = None,
) -> list[PolicyLint]:
    """Link + analyze in one call.

    A hard failure (the linker rejecting the bundle, or an invalid resolved
    policy) becomes a single ``error`` lint so a caller reports hard failures
    and soft lints through one uniform list. The except tuple matches what
    ``link_policy_set`` can raise: ``LinkError`` from the fold, and
    ``PolicySetError`` / ``ConstraintParseError`` from validating the resolved
    policy (e.g. an undefined ``consts`` reference).
    """
    try:
        result = link_policy_set(boundaries, capabilities)
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        return [PolicyLint("link-error", "error", str(exc))]
    return analyze(result, boundaries, capabilities, manifest=manifest)


def analyze(
    result: LinkResult,
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    *,
    manifest: AgentManifest | None = None,
) -> list[PolicyLint]:
    """Soft lints over a successfully-linked bundle, most-severe first.

    Needs the input modules (not just ``result``) to know what each layer
    *declared* versus what survived the fold.
    """
    lints: list[PolicyLint] = []
    lints += _dead_grants(result, capabilities)
    lints += _redundant_grants(capabilities)
    lints += _constraint_erased(capabilities)
    if manifest is not None:
        lints += _drift(boundaries, capabilities, manifest)
    return sorted(lints, key=lambda lint: SEVERITY_RANK[lint.severity])


def check_project(
    boundaries: list[ModuleContent],
    library: list[ModuleContent],
    roles: Mapping[str, Sequence[str]] | None,
    *,
    agent_leaf: Sequence[ModuleContent] = (),
    agent_boundaries: Sequence[ModuleContent] = (),
    manifest: AgentManifest | None = None,
) -> list[PolicyLint]:
    """Resolve a project and lint every role. See :func:`check` for the single-role
    form. A hard failure folds into one ``error`` lint, same contract as ``check``.
    """
    try:
        result = resolve_for_project(
            boundaries,
            library,
            roles,
            agent_leaf=agent_leaf,
            agent_boundaries=agent_boundaries,
        )
    except (LinkError, PolicySetError, ConstraintParseError) as exc:
        return [PolicyLint("link-error", "error", str(exc))]
    return analyze_project(
        result,
        boundaries,
        library,
        roles,
        agent_leaf=agent_leaf,
        agent_boundaries=agent_boundaries,
        manifest=manifest,
    )


def analyze_project(
    result: ProjectLinkResult,
    boundaries: list[ModuleContent],
    library: list[ModuleContent],
    roles: Mapping[str, Sequence[str]] | None,
    *,
    agent_leaf: Sequence[ModuleContent] = (),
    agent_boundaries: Sequence[ModuleContent] = (),
    manifest: AgentManifest | None = None,
) -> list[PolicyLint]:
    """Soft lints across every role, each tagged with the role it fired in.

    A grant dead under one role's ceiling can be alive under another, so the
    per-capability lints run once per role over that role's imported set. Two
    project-level lints span roles: ``unused-capability`` (a library pack no role
    imports) and ``no-default-role`` (roles defined but no ``default``, so unroled
    callers get fail-closed deny).
    """
    # Same expansion the resolver used, so the analyzer lints exactly the roles
    # that compiled. Raises LinkError on an unknown capability, matching
    # resolve_for_project — but check_project resolves first, so by the time we
    # get here the same input has already succeeded.
    resolved = resolve_role_map(roles, library)
    fences = [*boundaries, *agent_boundaries]

    lints: list[PolicyLint] = []
    for role, caps in resolved.items():
        role_result = result.by_role.get(role)
        if role_result is None:
            continue
        for lint in analyze(
            role_result, fences, [*caps, *agent_leaf], manifest=manifest
        ):
            lints.append(replace(lint, role=role))

    lints += _unused_capabilities(library, resolved)
    if roles and DEFAULT_ROLE_NAME not in roles:
        lints.append(
            PolicyLint(
                code="no-default-role",
                severity="info",
                message=(
                    f"no {DEFAULT_ROLE_NAME!r} role defined; a caller with no role "
                    "resolves to fail-closed deny"
                ),
                # role stays None: this spans roles, so a role-scoped `check
                # --role X` view must still surface it (like unused-capability).
            )
        )
    return sorted(lints, key=lambda lint: SEVERITY_RANK[lint.severity])


def _unused_capabilities(
    library: list[ModuleContent], resolved: Mapping[str, Sequence[ModuleContent]]
) -> list[PolicyLint]:
    """A library capability that no role imports. An authoring dead-weight signal."""
    imported = {cap.name for caps in resolved.values() for cap in caps}
    return [
        PolicyLint(
            code="unused-capability",
            severity="info",
            message=f"capability {cap.name!r} is imported by no role",
            source=cap.source,
            tier="capability",
            tool=None,
        )
        for cap in library
        if cap.name not in imported
    ]


def _dead_grants(
    result: LinkResult, capabilities: list[ModuleContent]
) -> list[PolicyLint]:
    """A capability grant that the effective policy doesn't allow never fires.

    Keyed off the *resolved* policy, not just ``trace.shadowed``, so it catches
    every dead grant: a ceiling that excludes the tool AND a boundary that
    hard-denies it (the latter never enters ``shadowed`` — it takes the
    absolute-deny path in the fold). A grant survives iff the effective tool is
    still allow/approval.
    """
    effective = result.effective[DEFAULT_ROLE_NAME]
    out: list[PolicyLint] = []
    for cap in capabilities:
        for tool, tp in cap.policy.tools.items():
            if tp.mode not in GRANT_MODES:
                continue
            eff = effective.tools.get(tool)
            if eff is not None and eff.mode in GRANT_MODES:
                continue  # the grant contributes to the effective allow — alive
            out.append(
                PolicyLint(
                    code="dead-grant",
                    severity="warning",
                    message=(
                        f"{cap.name!r} grants {tool!r} but {_dead_reason(tool, result)}"
                        f" — this grant never fires"
                    ),
                    source=cap.source,
                    tier="capability",
                    tool=tool,
                )
            )
    return out


def _dead_reason(tool: str, result: LinkResult) -> str:
    """Why a grant is dead: a ceiling that excludes it, or a boundary deny."""
    shadowed_by = result.trace.shadowed.get(tool)
    if shadowed_by is not None:
        return f"boundary {shadowed_by.module!r} (a ceiling) never permits it"
    return "a boundary denies it"


def _redundant_grants(capabilities: list[ModuleContent]) -> list[PolicyLint]:
    """Two capabilities granting the same tool with the same mode + constraints."""
    out: list[PolicyLint] = []
    seen: dict[tuple[str, str, tuple[str, ...]], ModuleContent] = {}
    for cap in capabilities:
        for tool, tp in cap.policy.tools.items():
            if tp.mode not in GRANT_MODES:
                continue
            key = (tool, tp.mode, tuple(sorted(tp.constraints)))
            first = seen.get(key)
            if first is not None:
                out.append(
                    PolicyLint(
                        code="redundant-grant",
                        severity="info",
                        message=(
                            f"{cap.name!r} repeats the {tool!r} grant already in "
                            f"{first.name!r}"
                        ),
                        source=cap.source,
                        tier="capability",
                        tool=tool,
                    )
                )
            else:
                seen[key] = cap
    return out


def _constraint_erased(capabilities: list[ModuleContent]) -> list[PolicyLint]:
    """A constrained grant nullified by an unconditional sibling grant.

    Capability grants for one tool union, so an unconditional grant (no
    constraints) widens the tool to everything and drops every sibling's
    condition. That is intended union semantics, but it is the security-relevant
    direction (a tight rule silently erased), so it warrants a warning.
    """
    grants: dict[str, list[tuple[ModuleContent, Any]]] = {}
    for cap in capabilities:
        for tool, tp in cap.policy.tools.items():
            if tp.mode in GRANT_MODES:
                grants.setdefault(tool, []).append((cap, tp))

    out: list[PolicyLint] = []
    for tool, entries in grants.items():
        unconditional = [cap for cap, tp in entries if not tp.constraints]
        if not unconditional:
            continue
        for cap, tp in entries:
            if tp.constraints:
                out.append(
                    PolicyLint(
                        code="constraint-erased",
                        severity="warning",
                        message=(
                            f"{cap.name!r} constrains {tool!r}, but "
                            f"{unconditional[0].name!r} grants it unconditionally, "
                            f"so the constraint is dropped from the effective policy"
                        ),
                        source=cap.source,
                        tier="capability",
                        tool=tool,
                    )
                )
    return out


def _drift(
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    manifest: AgentManifest,
) -> list[PolicyLint]:
    """Rules referencing tools / args the agent's code doesn't have.

    Severity follows the failure direction, not just the tier:
      * boundary allow/approval (a ceiling) naming a missing tool leaves the real
        tool uncapped -> fail-open -> error.
      * boundary deny naming a missing tool protects nothing and breaks nothing
        -> info.
      * capability drift is a dead grant -> warning.
      * a boundary deny's arg typo inverts (``not(<missing> ...)`` folds to allow)
        -> fail-open -> error; other arg drift -> warning.
    """
    tool_props: dict[str, set[str]] = {
        t.name: set(t.input_schema.properties) for t in manifest.tools
    }
    known_tools = set(tool_props)

    out: list[PolicyLint] = []
    tiers: list[tuple[list[ModuleContent], LayerKind]] = [
        (boundaries, "boundary"),
        (capabilities, "capability"),
    ]
    for modules, tier in tiers:
        for module in modules:
            for tool, tp in module.policy.tools.items():
                if tool not in known_tools:
                    out.append(
                        PolicyLint(
                            code="unknown-tool",
                            severity=_unknown_tool_severity(tier, tp.mode),
                            message=(
                                f"{module.name!r} references tool {tool!r}, which "
                                f"the agent's manifest doesn't declare"
                            ),
                            source=module.source,
                            tier=tier,
                            tool=tool,
                        )
                    )
                    continue
                arg_severity: Severity = (
                    "error" if (tier == "boundary" and tp.mode == "deny") else "warning"
                )
                out += _unknown_args(
                    module, tier, tool, tp, tool_props[tool], arg_severity
                )
    return out


def _unknown_tool_severity(tier: LayerKind, mode: str) -> Severity:
    """A boundary deny on a missing tool is harmless; a boundary ceiling that
    names a missing tool leaves the real tool uncapped (fail-open)."""
    if tier == "capability":
        return "warning"
    return "info" if mode == "deny" else "error"


def _unknown_args(
    module: ModuleContent,
    tier: LayerKind,
    tool: str,
    tool_policy: Any,
    valid_args: set[str],
    severity: Severity,
) -> list[PolicyLint]:
    """Constraint ``args.<x>`` paths where ``<x>`` isn't a parameter of the tool."""
    out: list[PolicyLint] = []
    flagged: set[str] = set()
    for raw in tool_policy.constraints:
        for path in iter_arg_refs(parse_constraint(raw)):
            if len(path) >= 2 and path[0] == "args" and path[1] not in valid_args:
                arg = path[1]
                if arg in flagged:
                    continue
                flagged.add(arg)
                out.append(
                    PolicyLint(
                        code="unknown-arg",
                        severity=severity,
                        message=(
                            f"{module.name!r} constrains {tool!r} on args.{arg}, "
                            f"which the tool doesn't accept"
                        ),
                        source=module.source,
                        tier=tier,
                        tool=tool,
                    )
                )
    return out


# ---------------------------------------------------------------------------
# Cross-role exposure. Not part of ``analyze()``: that pipeline is module-scoped
# and single-role (``LinkResult.effective`` holds only ``default``), so it has
# nothing to say about a role map. Takes a resolved PolicySet instead.
# ---------------------------------------------------------------------------


def check_default_role_exposure(policy_set: PolicySet) -> list[PolicyLint]:
    """Warn when the ``default`` role grants something no named role grants.

    Any unrecognised role name resolves to ``default`` and joins the caller's
    union, so a tool reachable only through ``default`` is reachable by anyone.

    A document that declares roles but no ``default`` gets an ``implicit-default``
    lint of its own: the loader aliases one named role as the fallback, handing
    that role's whole grant set to every undefined name.

    Silent for a single-role policy set: a legacy flat ``policy.yaml`` *is* the
    ``default`` role. ``warning`` rather than ``error`` for the same reason —
    CI opts in via ``--max-severity warning``.
    """
    named = [role for role in policy_set.roles if role != DEFAULT_ROLE_NAME]
    if not named:
        return []

    default_policy = policy_set.policy_for(DEFAULT_ROLE_NAME)
    # Drop the role ``default`` merely aliases: it resolves to the *same policy
    # object*, so leaving it in answers "does a named role grant this too?" with
    # yes for every one of its own grants — silencing the check on the very
    # shape that most needs it.
    others = [
        policy
        for policy in (policy_set.policy_for(role) for role in named)
        if policy is not default_policy
    ]
    lints: list[PolicyLint] = []

    if policy_set.aliased_default is not None:
        lints.append(
            PolicyLint(
                code="implicit-default",
                severity="warning",
                message=(
                    f"no role is named {DEFAULT_ROLE_NAME!r}, so "
                    f"{policy_set.aliased_default!r} is the fallback for every "
                    "role name this policy doesn't define — any caller reaches "
                    "its grants by carrying an undefined name. Add an explicit "
                    f"least-privilege {DEFAULT_ROLE_NAME!r} role."
                ),
            )
        )

    for tool, tool_policy in sorted(default_policy.tools.items()):
        if tool_policy.mode not in GRANT_MODES:
            continue
        if any(
            tool in other.tools and other.tools[tool].mode in GRANT_MODES
            for other in others
        ):
            continue
        lints.append(
            PolicyLint(
                code="permissive-default",
                severity="warning",
                message=(
                    f"the {DEFAULT_ROLE_NAME!r} role grants {tool!r} "
                    f"({tool_policy.mode}) and no named role does. "
                    f"{DEFAULT_ROLE_NAME!r} is the fallback for every "
                    "unrecognised role name, so any caller can reach this tool "
                    "by carrying a role this policy doesn't define. Move the "
                    "grant to the roles that need it, or into a mixin they "
                    f"inherit, and keep {DEFAULT_ROLE_NAME!r} least-privilege."
                ),
                tool=tool,
            )
        )

    if default_policy.default_policy.mode in GRANT_MODES and not any(
        other.default_policy.mode in GRANT_MODES for other in others
    ):
        lints.append(
            PolicyLint(
                code="permissive-default",
                severity="warning",
                message=(
                    f"the {DEFAULT_ROLE_NAME!r} role's default_policy is "
                    f"{default_policy.default_policy.mode!r}, so every tool not "
                    "listed anywhere is reachable by any caller carrying an "
                    f"unrecognised role name. Set it to 'deny' and grant tools "
                    "explicitly."
                ),
            )
        )
    return lints
