"""Data model for stacked policy modules and the linker's output.

A *module* is an :class:`~hexgate.security.models.AgentPolicy` fragment given an
identity (``name``), a tier (``kind``), an origin (``source``), and a content
hash. Modules compose — via :mod:`hexgate.security.linker` — into one effective
policy per agent, which then compiles to Rego/WASM exactly as a single policy
does today. See ``policy-modules-plan.md``.

Everything here is SDK-side: devs load, link, and lint modules locally with no
platform. ``content_hash`` is the content-identity half of versioning (cheap, no
DB) — present now so durable version history can clip on later without rework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from hexgate.security.models import AgentPolicy

if TYPE_CHECKING:  # avoid an import cycle — policy_set imports models, not this
    from hexgate.security.policy_set import PolicySet

LayerKind = Literal["boundary", "capability"]

# The modes that grant a tool (as opposed to deny). Shared by the linker's fold
# and the analyzer's lints so they can't drift out of lockstep.
GRANT_MODES: tuple[str, ...] = ("allow", "approval_required")


class LinkError(ValueError):
    """Raised when a bundle of modules can't be composed.

    The common case is a capability that tries to ``deny`` — capabilities may
    only grant; a deny belongs to a boundary.
    """


@dataclass(frozen=True)
class ModuleContent:
    """One policy fragment in a bundle, with identity + provenance.

    ``policy`` is the fragment itself (``default_policy`` + ``tools`` + ``consts``).
    ``kind`` fixes its tier. ``source`` is where it came from (a file path for the
    local loader) and ``content_hash`` is its stable identity.
    """

    name: str
    kind: LayerKind
    policy: AgentPolicy
    source: str
    content_hash: str


@dataclass(frozen=True)
class Provenance:
    """Where a resolved rule — or a contributing layer — came from.

    Threaded through the linker so the analyzer and editor can attribute every
    effective rule (and every shadowed one) back to its source file. ``line`` is
    populated later; file-level attribution is what the linker guarantees now.
    """

    module: str
    kind: LayerKind
    source: str
    content_hash: str
    line: int | None = None


@dataclass
class RuleTrace:
    """Per-tool provenance the analyzer + editor consume.

    ``contributors[tool]`` — the layers that fed the effective rule for ``tool``.
    ``shadowed[tool]`` — a higher-tier layer (a boundary ceiling) that made a
    tool ineligible, so any lower grant for it is inert. This is the raw material
    the analyzer turns into ``dead`` / ``shadowed`` lints.
    """

    contributors: dict[str, list[Provenance]] = field(default_factory=dict)
    shadowed: dict[str, Provenance] = field(default_factory=dict)

    def record(self, tool: str, provs: list[Provenance]) -> None:
        if provs:
            self.contributors.setdefault(tool, []).extend(provs)

    def shadow(self, tool: str, by: Provenance) -> None:
        self.shadowed[tool] = by


@dataclass(frozen=True)
class LinkResult:
    """The linker's output: one effective policy + full provenance.

    ``policy_set`` feeds ``compile_to_rego`` unchanged. ``effective`` is the
    folded policy per role (single ``default`` role in this iteration).
    ``layers`` lists every input module in resolution order — the provenance the
    signed bundle records and audit will later pin. ``trace`` carries per-tool
    attribution for the analyzer/editor.
    """

    policy_set: "PolicySet"
    effective: dict[str, AgentPolicy]
    layers: list[Provenance]
    trace: RuleTrace


@dataclass(frozen=True)
class ProjectLinkResult:
    """A whole project resolved into one role-keyed :class:`PolicySet`.

    ``policy_set`` folds every role and feeds ``compile_to_rego`` unchanged.
    ``by_role`` keeps each role's single-role :class:`LinkResult` (effective +
    layers + trace), so the analyzer and editor can attribute a lint to the role
    it fired in. Boundaries apply to every role; only the capability selection
    differs, so a grant dead in one role can be alive in another.
    """

    policy_set: "PolicySet"
    by_role: dict[str, LinkResult]
