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
from hexgate.security.modules import LayerKind, ModuleContent

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


def load_roles(root: str | Path) -> dict[str, list[str]] | None:
    """Load the role bindings from ``<root>/roles.yaml``.

    Returns ``None`` when the file is **absent** — the signal the resolver reads
    as "no roles, one default importing every capability" (all-compose
    back-compat). Returns a dict (possibly empty) when the file **exists**: an
    empty or typo'd binding resolves to a fail-closed default, not all-compose,
    so a one-character mistake can't silently widen access. Boundaries are never
    listed here; a role selects capabilities only.

    Shape::

        version: 1
        roles:
          support: [read_only, refunds_small]
          default: [read_only]
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
        raise ValueError(f"{ROLES_FILE}: 'roles' must be a mapping of role -> [names]")

    roles: dict[str, list[str]] = {}
    for role, names in raw.items():
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise ValueError(
                f"{ROLES_FILE}: role {role!r} must map to a list of capability names"
            )
        roles[str(role)] = list(names)
    return roles


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
