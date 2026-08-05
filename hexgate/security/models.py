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
    """

    version: int = 1
    inherits: list[str] = Field(default_factory=list)
    is_mixin: bool = False
    default_policy: BaseToolPolicy = Field(default_factory=BaseToolPolicy)
    tools: dict[str, ToolPolicy] = Field(default_factory=dict)
    consts: dict[str, Any] = Field(default_factory=dict)
