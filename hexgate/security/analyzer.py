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

Every :class:`PolicyLint` carries the ``source`` file it attributes to — the same
contract the CLI (`hexgate policy check`) and the dashboard editor both consume.
Deferred (needs a solver): semantic conflicts — empty intersection, always-true /
always-false, subsumption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from hexgate.security.constraints import iter_arg_refs, parse_constraint
from hexgate.security.linker import link_policy_set
from hexgate.security.modules import (
    LayerKind,
    LinkError,
    LinkResult,
    ModuleContent,
)

if TYPE_CHECKING:  # avoid importing the manifest package eagerly
    from hexgate.manifest.models import AgentManifest

Severity = Literal["error", "warning", "info"]
_GRANT_MODES = ("allow", "approval_required")
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


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


def check(
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    *,
    manifest: AgentManifest | None = None,
) -> list[PolicyLint]:
    """Link + analyze in one call.

    A :class:`LinkError` (the hard cases) becomes a single ``error`` lint so a
    caller reports hard failures and soft lints through one uniform list.
    """
    try:
        result = link_policy_set(boundaries, capabilities)
    except LinkError as exc:
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
    if manifest is not None:
        lints += _drift(boundaries, capabilities, manifest)
    return sorted(lints, key=lambda lint: _SEVERITY_RANK[lint.severity])


def _dead_grants(
    result: LinkResult, capabilities: list[ModuleContent]
) -> list[PolicyLint]:
    """A capability grant for a tool a ceiling made ineligible never fires."""
    out: list[PolicyLint] = []
    for tool, shadowed_by in result.trace.shadowed.items():
        for cap in capabilities:
            tp = cap.policy.tools.get(tool)
            if tp is not None and tp.mode in _GRANT_MODES:
                out.append(
                    PolicyLint(
                        code="dead-grant",
                        severity="warning",
                        message=(
                            f"{cap.name!r} grants {tool!r} but boundary "
                            f"{shadowed_by.module!r} (a ceiling) never permits it "
                            f"— this grant never fires"
                        ),
                        source=cap.source,
                        tier="capability",
                        tool=tool,
                    )
                )
    return out


def _redundant_grants(capabilities: list[ModuleContent]) -> list[PolicyLint]:
    """Two capabilities granting the same tool with the same mode + constraints."""
    out: list[PolicyLint] = []
    seen: dict[tuple[str, str, tuple[str, ...]], ModuleContent] = {}
    for cap in capabilities:
        for tool, tp in cap.policy.tools.items():
            if tp.mode not in _GRANT_MODES:
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


def _drift(
    boundaries: list[ModuleContent],
    capabilities: list[ModuleContent],
    manifest: AgentManifest,
) -> list[PolicyLint]:
    """Rules referencing tools / args the agent's code doesn't have.

    Boundary drift is fail-open (a stale deny protects nothing) → error;
    capability drift is fail-safe (a dead grant) → warning.
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
        severity: Severity = "error" if tier == "boundary" else "warning"
        for module in modules:
            for tool, tp in module.policy.tools.items():
                if tool not in known_tools:
                    out.append(
                        PolicyLint(
                            code="unknown-tool",
                            severity=severity,
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
                out += _unknown_args(module, tier, tool, tp, tool_props[tool])
    return out


def _unknown_args(
    module: ModuleContent,
    tier: LayerKind,
    tool: str,
    tool_policy: Any,
    valid_args: set[str],
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
                        severity="warning",
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
