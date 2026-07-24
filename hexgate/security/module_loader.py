"""Load policy modules from local files — the SDK / dev path.

Reads a repo's ``policies/guardrails/`` and ``policies/capabilities/``
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

GUARDRAIL_SUBDIR = ("policies", "guardrails")
CAPABILITY_SUBDIR = ("policies", "capabilities")


class ModuleLoader(Protocol):
    """Resolve the modules that apply to an agent.

    Returns ``(guardrails, capabilities)`` in resolution order. The local-files
    loader ignores ``agent_name`` (it returns the repo's whole bundle); the
    platform loader will use it to scope-attach org guardrails + imports.
    """

    def load(
        self, agent_name: str
    ) -> tuple[list[ModuleContent], list[ModuleContent]]: ...


def load_local_modules(
    root: str | Path,
) -> tuple[list[ModuleContent], list[ModuleContent]]:
    """Load ``(guardrails, capabilities)`` from a repo root's ``policies/`` tree.

    Guardrails come from ``<root>/policies/guardrails/**.yaml``, capabilities
    from ``<root>/policies/capabilities/**.yaml``. Missing directories yield an
    empty list (a repo may ship only one tier). Each file's stem is the module
    name; its content hash is the sha256 of its canonical JSON.
    """
    root = Path(root)
    guardrails = _read_dir(root.joinpath(*GUARDRAIL_SUBDIR), "guardrail")
    capabilities = _read_dir(root.joinpath(*CAPABILITY_SUBDIR), "capability")
    return guardrails, capabilities


def _read_dir(directory: Path, kind: LayerKind) -> list[ModuleContent]:
    if not directory.is_dir():
        return []
    modules: list[ModuleContent] = []
    for file in sorted(directory.glob("**/*.yaml")):
        payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        try:
            policy = AgentPolicy.model_validate(payload)
        except Exception as exc:  # noqa: BLE001 — surface the offending file
            raise ValueError(f"module {file.name!r} is invalid: {exc}") from exc
        modules.append(
            ModuleContent(
                name=file.stem,
                kind=kind,
                policy=policy,
                source=str(file),
                content_hash=_canonical_hash(payload),
            )
        )
    return modules


def _canonical_hash(payload: object) -> str:
    """sha256 of the module's canonical JSON — stable across dict ordering."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
