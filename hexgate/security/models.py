"""Pydantic models for agent security policies."""

from __future__ import annotations

from functools import cached_property
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from hexgate.security.constraints import parse_constraint
from hexgate.security.naming import canonical_name

PolicyMode = Literal["allow", "deny", "approval_required"]


class BaseToolPolicy(BaseModel):
    """Define the access mode and per-call constraints for a single tool.

    ``constraints`` is a list of expression strings evaluated against the
    tool's invocation arguments (e.g. ``"args.amount <= 50"``). Every
    constraint must pass for the call to authorize. The grammar is parsed
    by :mod:`hexgate.security.constraints` — see that module for the full
    operator set. When the policy engine swaps to OPA/Rego in a later
    milestone, these strings carry through verbatim.
    """

    mode: PolicyMode = "deny"
    constraints: list[str] = Field(default_factory=list)

    @field_validator("constraints")
    @classmethod
    def _validate_constraint_grammar(cls, value: list[str]) -> list[str]:
        """Parse every constraint at load — a malformed expression is a config
        error, surfaced here at ``model_validate`` time rather than lazily at
        the first matching tool call. Keeps ``models.py`` (document schema) and
        ``constraints.py`` (expression grammar) jointly the enforced spec."""
        for constraint in value:
            parse_constraint(constraint)
        return value


class FileScope(BaseModel):
    """Restrict a file-oriented tool to explicit path patterns."""

    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)


class FileToolPolicy(BaseToolPolicy):
    """Define access policy for file-oriented tools."""

    file_scope: FileScope | None = None


ToolPolicy = BaseToolPolicy | FileToolPolicy

AgentVia = Literal["tool", "handoff"]

# Reserved synthetic tool keys that agent-level gating lowers to. Kept here so
# the lowering and the agent gate (which builds the same keys at the seam) share
# one definition. ``.`` and ``:`` are safe in a tool name: both engines treat the
# name as an opaque string (the Rego compiler emits ``input.tool == "<name>"``),
# exactly as the ``net.*`` egress tools already do.
AGENT_RUN_TOOL = "agent.run"

# Prefixes for the reach keys (``agent.tool:<name>`` / ``agent.handoff:<name>``),
# derived from AgentVia so a new via mode is covered everywhere automatically. One
# source of truth for the namespace reservation and for both engines' closed-world
# handling, so pydantic and Rego cannot drift on which names are agent keys.
AGENT_REACH_PREFIXES = tuple(f"agent.{via}:" for via in get_args(AgentVia))


def agent_target_key(via: AgentVia, target: str) -> str:
    """Synthetic tool key for reaching ``target`` in a given transfer mode."""
    return f"agent.{via}:{target}"


def is_agent_via_key(name: str, via: AgentVia) -> bool:
    """True for a reach key of a specific ``via`` mode (``agent.<via>:``).

    Lets a caller tell agent-as-tool reach from handoff reach, e.g. to warn only
    about the mode a given adapter cannot enforce."""
    return name.startswith(f"agent.{via}:")


def is_agent_reach_key(name: str) -> bool:
    """True for an ``agent.tool:`` / ``agent.handoff:`` reach key.

    Distinguishes reach keys from admission (``agent.run``) for callers that gate
    the two differently at the seam. Both are closed-world at the engine
    (R-AGENT-002): an unlisted agent key denies regardless of ``default_policy``.
    Opt-in survives only as the gate's ``declares_admission()`` / ``declares_reach()``
    engagement check, not as an admit-on-absence fallback."""
    return name.startswith(AGENT_REACH_PREFIXES)


def is_agent_key(name: str) -> bool:
    """True for any synthetic agent-level key (``agent.run`` or a reach key).

    Used to reserve the ``agent.*`` namespace from authored tools. Both admission
    and reach are closed-world at the engine (R-AGENT-002); :func:`is_agent_reach_key`
    only separates the two for callers that need to tell a handoff/tool reach from
    admission (e.g. per-adapter warnings), not because they enforce differently."""
    return name == AGENT_RUN_TOOL or is_agent_reach_key(name)


class AgentTargetPolicy(BaseToolPolicy):
    """Authorize reaching one named target agent, per transfer mode.

    ``via`` names the transfer modes this rule governs: ``tool`` (agent-as-tool,
    the orchestrator keeps control) and/or ``handoff`` (control transfers). A
    target listed for ``tool`` only cannot be handed off to, and the reverse.
    ``mode`` and ``constraints`` behave exactly as on a tool policy.
    """

    via: list[AgentVia] = Field(default_factory=lambda: ["tool", "handoff"])

    @field_validator("via")
    @classmethod
    def _validate_via(cls, value: list[AgentVia]) -> list[AgentVia]:
        if not value:
            raise ValueError("via must list at least one of 'tool', 'handoff'")
        # De-dup, order-preserving.
        return list(dict.fromkeys(value))


class AgentPolicy(BaseModel):
    """Define an agent-wide tool authorization policy.

    ``inherits`` names other policy bundles whose ``tools`` map is merged
    in before this one's, left-to-right (later wins). Used for mixin
    policies like ``read_only`` that several roles share.

    ``is_mixin = True`` marks the policy as a building block — the SDK
    won't pick it as the effective policy for any HexgateContext scope; it can only
    be referenced via ``inherits``.

    ``consts`` names reusable values referenced from constraints as
    ``consts.<name>`` (e.g. ``args.amount <= consts.max_refund``). Merged
    through ``inherits`` like ``tools`` — put shared constants in a mixin.

    Agent-level gating (both optional):

    * ``admission`` — ingress. May this role start or enter *this* agent at all?
    * ``agents`` — egress. Which *other* agents may this role reach, keyed by
      target name, each an :class:`AgentTargetPolicy`.

    Both lower into synthetic tool keys via :attr:`effective_tools`, which both
    policy engines read, so agent-level rules evaluate through the identical
    decision path as tools with no engine change. Agent keys are closed-world
    (R-AGENT-002): an unlisted ``agent.run`` / ``agent.<via>:<target>`` denies at
    the engine rather than falling to ``default_policy``. Whether a gate fires at
    all is a separate, opt-in signal derived per run from whether the policy
    declares the block (``declares_admission()`` / ``declares_reach()``).
    """

    # frozen: policies are immutable after load (inheritance builds fresh
    # instances, nothing reassigns a field), which is what makes memoizing
    # effective_tools safe. cached_property is a plain descriptor, not a field,
    # so pydantic must leave it alone.
    model_config = ConfigDict(frozen=True, ignored_types=(cached_property,))

    version: int = 1
    inherits: list[str] = Field(default_factory=list)
    is_mixin: bool = False
    default_policy: BaseToolPolicy = Field(default_factory=BaseToolPolicy)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    consts: dict[str, Any] = Field(default_factory=dict)
    admission: BaseToolPolicy | None = None
    agents: dict[str, AgentTargetPolicy] = Field(default_factory=dict)

    @field_validator("tools")
    @classmethod
    def _reject_reserved_tool_names(
        cls, value: dict[str, ToolPolicy], info: ValidationInfo
    ) -> dict[str, ToolPolicy]:
        """Keep the ``agent.*`` key namespace for agent-level gating.

        An authored tool named ``agent.run`` / ``agent.tool:x`` / ``agent.handoff:x``
        would collide with a lowered agent rule in :attr:`effective_tools` and
        silently shadow (or be shadowed by) it. Reject it at load.

        Skipped when validated under a ``{"resolved": True}`` context: a *resolved*
        policy legitimately carries the lowered ``agent.*`` keys in ``tools`` (the
        linker's :meth:`resolved` builder puts them there), and it must round-trip
        back through this loader when a modular agent's bundle is compiled from its
        resolved YAML (R-POL-002). The guard is an authoring ergonomic — it only
        needs to fire on hand-written source, not on a machine-resolved artifact."""
        if info.context and info.context.get("resolved"):
            return value
        for name in value:
            if is_agent_key(name):
                raise ValueError(
                    f"tool name {name!r} is reserved for agent-level gating; "
                    "use the 'admission'/'agents' blocks instead"
                )
        return value

    @classmethod
    def resolved(
        cls,
        *,
        default_policy: BaseToolPolicy,
        tools: dict[str, ToolPolicy],
        consts: dict[str, Any],
    ) -> "AgentPolicy":
        """Build a linker-resolved policy directly from folded tool keys.

        The fold composes agent-level blocks into lowered ``agent.*`` keys and
        stores them alongside ordinary tools, so a resolved policy carries them
        in ``tools`` rather than in ``admission``/``agents``: per-via divergence
        across capabilities (a target allowed via one mode, denied via another,
        or granted different constraints per mode) can't always be reverse-lowered
        into a single :class:`AgentTargetPolicy`. The reserved-key guard on
        ``tools`` is an authoring ergonomic that does not apply to this machine
        path, so this bypasses validation via ``model_construct`` — every value is
        an already-validated model instance produced by the fold."""
        return cls.model_construct(
            default_policy=default_policy, tools=dict(tools), consts=dict(consts)
        )

    def lowered_agent_tools(self) -> dict[str, BaseToolPolicy]:
        """Expand ``admission``/``agents`` into synthetic tool entries.

        ``admission`` → ``agent.run``; each ``agents`` target → one entry per
        ``via`` mode (``agent.tool:<name>`` / ``agent.handoff:<name>``). Only the
        *listed* rules are lowered; the fallback for an unlisted target is the
        agent gate's concern, not this map's.

        The target name is canonicalized (:func:`~hexgate.security.naming.canonical_name`)
        so the lowered key matches the one the reach gate derives from the runtime
        target's name — both sides normalize identically, or a padded authored name
        would never match and a policy-allowed handoff would fall to closed-world deny.
        """
        lowered: dict[str, BaseToolPolicy] = {}
        if self.admission is not None:
            lowered[AGENT_RUN_TOOL] = self.admission
        for target, target_policy in self.agents.items():
            # Use the AgentTargetPolicy directly (it is a BaseToolPolicy): a bare
            # rebuild would silently drop any field later added to BaseToolPolicy.
            # via is an extra field the engines ignore.
            for via in target_policy.via:
                lowered[agent_target_key(via, canonical_name(target))] = target_policy
        return lowered

    @cached_property
    def effective_tools(self) -> dict[str, ToolPolicy]:
        """Authored ``tools`` plus the lowered agent-level entries.

        The single view both engines read (:func:`~hexgate.security.policy.get_tool_policy`
        and the Rego compiler), so a lowered ``agent.*`` key evaluates byte-for-byte
        the same on the pydantic and WASM paths. Memoized: ``get_tool_policy`` reads
        this on every decision, and policies are immutable after load (inheritance
        builds fresh instances), so the merge runs once per policy, not per call.
        """
        lowered = self.lowered_agent_tools()
        if not lowered:
            return self.tools
        return {**self.tools, **lowered}
