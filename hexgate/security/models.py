"""Pydantic models for agent security policies."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from hexgate.security.constraints import parse_constraint

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


def agent_target_key(via: AgentVia, target: str) -> str:
    """Synthetic tool key for reaching ``target`` in a given transfer mode."""
    return f"agent.{via}:{target}"


def _is_reserved_agent_key(name: str) -> bool:
    return (
        name == AGENT_RUN_TOOL
        or name.startswith("agent.tool:")
        or name.startswith("agent.handoff:")
    )


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

    Agent-level gating (all optional):

    * ``admission`` — ingress. May this role start or enter *this* agent at all?
    * ``agents`` — egress. Which *other* agents may this role reach, keyed by
      target name, each an :class:`AgentTargetPolicy`.
    * ``default_agent_policy`` — the fallback for a target not named in ``agents``.
      Consumed by the agent gate at the seam, not by the engines directly; when a
      target's synthetic key is absent it already falls to ``default_policy``
      (deny by default), so a listed-``agents`` policy is closed-world for free
      unless ``default_policy`` is permissive.

    ``admission`` and ``agents`` lower into synthetic tool keys via
    :attr:`effective_tools`, which both policy engines read, so agent-level rules
    evaluate through the identical decision path as tools with no engine change.
    """

    version: int = 1
    inherits: list[str] = Field(default_factory=list)
    is_mixin: bool = False
    default_policy: BaseToolPolicy = Field(default_factory=BaseToolPolicy)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    consts: dict[str, Any] = Field(default_factory=dict)
    admission: BaseToolPolicy | None = None
    agents: dict[str, AgentTargetPolicy] = Field(default_factory=dict)
    default_agent_policy: BaseToolPolicy | None = None

    @field_validator("tools")
    @classmethod
    def _reject_reserved_tool_names(
        cls, value: dict[str, ToolPolicy]
    ) -> dict[str, ToolPolicy]:
        """Keep the ``agent.*`` key namespace for agent-level gating.

        An authored tool named ``agent.run`` / ``agent.tool:x`` / ``agent.handoff:x``
        would collide with a lowered agent rule in :attr:`effective_tools` and
        silently shadow (or be shadowed by) it. Reject it at load."""
        for name in value:
            if _is_reserved_agent_key(name):
                raise ValueError(
                    f"tool name {name!r} is reserved for agent-level gating; "
                    "use the 'admission'/'agents' blocks instead"
                )
        return value

    def lowered_agent_tools(self) -> dict[str, BaseToolPolicy]:
        """Expand ``admission``/``agents`` into synthetic tool entries.

        ``admission`` → ``agent.run``; each ``agents`` target → one entry per
        ``via`` mode (``agent.tool:<name>`` / ``agent.handoff:<name>``). Only the
        *listed* rules are lowered; the fallback for an unlisted target is the
        agent gate's concern, not this map's.
        """
        lowered: dict[str, BaseToolPolicy] = {}
        if self.admission is not None:
            lowered[AGENT_RUN_TOOL] = self.admission
        for target, target_policy in self.agents.items():
            base = BaseToolPolicy(
                mode=target_policy.mode, constraints=target_policy.constraints
            )
            for via in target_policy.via:
                lowered[agent_target_key(via, target)] = base
        return lowered

    @property
    def effective_tools(self) -> dict[str, ToolPolicy]:
        """Authored ``tools`` plus the lowered agent-level entries.

        The single view both engines read (:func:`~hexgate.security.policy.get_tool_policy`
        and the Rego compiler), so a lowered ``agent.*`` key evaluates byte-for-byte
        the same on the pydantic and WASM paths.
        """
        lowered = self.lowered_agent_tools()
        if not lowered:
            return self.tools
        return {**self.tools, **lowered}
