"""Load policy modules from local files — the SDK / dev path.

Reads a repo's ``policies/boundaries/`` and ``policies/capabilities/``
directories into :class:`~hexgate.security.modules.ModuleContent`, hashing each
for content identity. Devs point the linker + analyzer at this with no platform.

This is the **loader seam**: the platform swaps :class:`ModuleLoader` for a
store-backed (and, later, version-pinned) implementation. Everything downstream
of the seam — link, analyze, compile — is shared.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Protocol

import yaml

from hexgate.security.models import AgentPolicy
from hexgate.security.modules import (
    DEFAULT_AGENT,
    AgentBinding,
    LayerKind,
    ModuleContent,
    RoleMatrix,
)

BOUNDARY_SUBDIR = ("policies", "boundaries")
CAPABILITY_SUBDIR = ("policies", "capabilities")

# The role-binding file. Lives at the repo root, deliberately OUTSIDE policies/,
# because a role is a binding (role -> capabilities), not a policy module. Module
# discovery never walks it. Mirrors the platform's `role_binding` table, which is
# separate from `policy_module`.
ROLES_FILE = "roles.yaml"


class ModuleLoader(Protocol):
    """Resolve the modules that apply to an agent.

    Returns ``(boundaries, capabilities)`` in resolution order. The local-files
    loader ignores ``agent_name`` (it returns the repo's whole bundle); the
    platform loader will use it to scope-attach org boundaries + imports.
    """

    def load(
        self, agent_name: str
    ) -> tuple[list[ModuleContent], list[ModuleContent]]: ...


def load_local_modules(
    root: str | Path,
) -> tuple[list[ModuleContent], list[ModuleContent]]:
    """Load ``(boundaries, capabilities)`` from a repo root's ``policies/`` tree.

    Boundaries come from ``<root>/policies/boundaries/`` (``*.yaml`` / ``*.yml``,
    recursively), capabilities from ``<root>/policies/capabilities/``. Missing
    directories yield an empty list (a repo may ship only one tier). A module's
    name is its path under the tier dir without suffix (so nested files with the
    same stem stay distinct); its content hash is the sha256 of its canonical JSON.
    """
    root = Path(root)
    boundaries = _read_dir(root.joinpath(*BOUNDARY_SUBDIR), "boundary")
    capabilities = _read_dir(root.joinpath(*CAPABILITY_SUBDIR), "capability")
    return boundaries, capabilities


def load_roles(root: str | Path) -> RoleMatrix | None:
    """Load the role bindings from ``<root>/roles.yaml`` as a ``(role, agent)`` matrix.

    Returns ``None`` when the file is **absent** — the signal the resolver reads
    as "no roles, one default importing every capability" (all-compose
    back-compat). Returns a dict (possibly empty) when the file **exists**: an
    empty or typo'd binding resolves to a fail-closed default, not all-compose,
    so a one-character mistake can't silently widen access. Boundaries are never
    listed here; a role selects capabilities only.

    A role maps either to a **flat** capability list (applies to any agent) or to
    a per-agent **matrix**; both normalize to ``{agent-or-"*": AgentBinding}``::

        version: 1
        roles:
          support: [read_only]                 # flat: sugar for {"*": [read_only]}
          member:
            "*": [read_only]                    # generic default for any agent
            billing_bot:                        # a named agent, more specific
              capabilities: [read_only, payments]
            triage_bot: [read_only]             # agent value may also be a bare list

    A named agent's binding **replaces** ``"*"`` for that agent (it does not merge),
    so an agent can be more restricted than the role's generic baseline.
    """
    path = Path(root) / ROLES_FILE
    if not path.is_file():
        return None
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 — surface the offending file
        raise ValueError(f"{ROLES_FILE} is invalid: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(
            f"{ROLES_FILE}: top level must be a mapping (got {type(payload).__name__})"
        )
    unknown = set(payload) - {"version", "roles"}
    if unknown:
        # A typo'd `role:` would otherwise parse to no binding and fall through
        # to a silent, fail-open all-compose. Reject it loudly instead.
        raise ValueError(
            f"{ROLES_FILE}: unknown top-level key(s) {sorted(unknown)!r} "
            f"(expected 'version' and/or 'roles')"
        )

    raw = payload.get("roles")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError(f"{ROLES_FILE}: 'roles' must be a mapping of role -> binding")

    return {
        str(role): _parse_role_binding(str(role), value) for role, value in raw.items()
    }


def _parse_role_binding(role: str, value: object) -> dict[str, AgentBinding]:
    """Normalize one role's value into ``{agent-or-"*": AgentBinding}``.

    A bare list is the flat form (the generic ``"*"`` agent); a mapping is the
    per-agent matrix, each agent's value itself either a bare capability list or a
    ``{capabilities: [...]}`` block.
    """
    if isinstance(value, list):
        return {DEFAULT_AGENT: _agent_binding(role, DEFAULT_AGENT, value)}
    if isinstance(value, dict):
        return {
            str(agent): _agent_binding(role, str(agent), cell)
            for agent, cell in value.items()
        }
    raise ValueError(
        f"{ROLES_FILE}: role {role!r} must map to a capability list or an "
        f"agent mapping (got {type(value).__name__})"
    )


def _agent_binding(role: str, agent: str, cell: object) -> AgentBinding:
    """One ``(role, agent)`` cell → :class:`AgentBinding`. ``cell`` is a bare
    capability list or a ``{capabilities: [...]}`` mapping."""
    if isinstance(cell, list):
        caps = cell
    elif isinstance(cell, dict):
        unknown = set(cell) - {"capabilities"}
        if unknown:
            raise ValueError(
                f"{ROLES_FILE}: role {role!r} agent {agent!r} has unknown key(s) "
                f"{sorted(unknown)!r} (expected 'capabilities')"
            )
        caps = cell.get("capabilities", [])
    else:
        raise ValueError(
            f"{ROLES_FILE}: role {role!r} agent {agent!r} must be a capability list "
            f"or a {{capabilities: [...]}} mapping (got {type(cell).__name__})"
        )
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise ValueError(
            f"{ROLES_FILE}: role {role!r} agent {agent!r} capabilities must be a "
            f"list of capability names"
        )
    return AgentBinding(capabilities=tuple(caps))


def _read_dir(directory: Path, kind: LayerKind) -> list[ModuleContent]:
    if not directory.is_dir():
        return []
    files = sorted({*directory.glob("**/*.yaml"), *directory.glob("**/*.yml")})
    modules: list[ModuleContent] = []
    seen: dict[str, Path] = {}
    for file in files:
        # Path-relative name (no suffix) so nested files with the same stem stay
        # distinct, e.g. "team/refunds" vs "refunds".
        name = file.relative_to(directory).with_suffix("").as_posix()
        if name in seen:
            # Two files collapsing to one name (e.g. dup.yaml + dup.yml) would
            # otherwise silently shadow each other and drop one file's grants.
            raise ValueError(f"duplicate module name {name!r}: {seen[name]} and {file}")
        seen[name] = file
        # Everything that can fail on a bad file — parse, validate, hash — runs
        # inside the try so the error always names the offending file.
        try:
            payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
            policy = AgentPolicy.model_validate(payload)
            content_hash = _canonical_hash(payload)
        except Exception as exc:  # noqa: BLE001 — surface the offending file
            raise ValueError(
                f"module {file.relative_to(directory).as_posix()!r} is invalid: {exc}"
            ) from exc
        modules.append(
            ModuleContent(
                name=name,
                kind=kind,
                policy=policy,
                source=str(file),
                content_hash=content_hash,
            )
        )
    return modules


def _canonical_hash(payload: object) -> str:
    """sha256 of the module's canonical JSON — stable across dict ordering.

    ``default=str`` so non-JSON scalars YAML can produce (e.g. an unquoted date
    becomes ``datetime.date``) serialize deterministically instead of raising.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
