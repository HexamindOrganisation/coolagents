"""Typed result of evaluating one proposed tool call against a PolicySet."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class DecisionOutcome(str, Enum):
    """Authorization outcome."""

    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass(frozen=True, slots=True)
class Verdict:
    """Engine-agnostic result of evaluating one tool call.

    What a policy engine knows on its own — the outcome plus any
    structured detail it produced — with none of the host context
    (agent name, role, argument snapshot) that :class:`PolicyEnforcer`
    layers on top when it builds a :class:`Decision`.

    Both engines return this shape so the enforcer never branches on
    which one ran:

      * ``violations`` — raw constraint strings the call failed (WASM
        engine); empty otherwise.
      * ``hint`` — machine-readable file-scope hint on a path denial
        (pydantic engine); ``None`` otherwise.
    """

    outcome: DecisionOutcome
    reason: str = ""
    violations: tuple[str, ...] = ()
    hint: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is DecisionOutcome.ALLOW


@runtime_checkable
class PolicyEngine(Protocol):
    """Evaluates one proposed tool call into a :class:`Verdict`.

    Implemented by :class:`~hexgate.security.policy_set.PolicySet` (the
    pydantic engine) and :class:`~hexgate.security.bundle.PolicyBundle`
    (the WASM engine). The two are interchangeable from
    :class:`~hexgate.security.enforcer.PolicyEnforcer`'s point of view —
    it depends on this protocol, not on either concrete type.
    """

    def evaluate(
        self,
        *,
        role: str | None,
        tool: str,
        args: Mapping[str, Any],
        attributes: Mapping[str, Any] | None = None,
    ) -> Verdict: ...


# Outcome → the legacy ``error_type`` tag adapters key off of in rendered
# payloads/messages. ALLOW has no error tag.
_ERROR_TYPE_BY_OUTCOME: dict[DecisionOutcome, str] = {
    DecisionOutcome.DENY: "policy_denied",
    DecisionOutcome.NEEDS_APPROVAL: "approval_required",
}


@dataclass(frozen=True, slots=True)
class Decision:
    """One policy decision for a proposed tool invocation."""

    outcome: DecisionOutcome
    agent_name: str
    tool_name: str
    role: str | None = None
    reason: str = ""
    error_type: str | None = None
    hint: dict[str, Any] | None = None
    violations: tuple[str, ...] = ()
    arguments: dict[str, Any] | None = None
    # The ABAC attribute snapshot the decision was evaluated against, so an
    # in-process observer sees the ``ctx.*`` values that drove the outcome.
    # Deliberately NOT rendered into ``as_error_payload`` (LLM-facing) nor
    # persisted by the audit sender yet — durable audit + PII/retention policy
    # lands with the signed tier.
    attributes: dict[str, Any] | None = None

    @classmethod
    def from_verdict(
        cls,
        verdict: Verdict,
        *,
        agent_name: str,
        tool_name: str,
        role: str | None = None,
        arguments: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> "Decision":
        """Lift an engine :class:`Verdict` into a host-facing decision.

        The verdict carries the outcome and any structured detail the
        engine produced (reason, file-scope hint); this stamps on the
        host context the engine doesn't know — agent name, role, the
        argument snapshot, and the ABAC attribute snapshot — and derives
        the ``error_type`` tag.
        """
        return cls(
            outcome=verdict.outcome,
            agent_name=agent_name,
            tool_name=tool_name,
            role=role,
            reason=verdict.reason,
            error_type=_ERROR_TYPE_BY_OUTCOME.get(verdict.outcome),
            hint=verdict.hint,
            violations=verdict.violations,
            arguments=arguments,
            attributes=attributes,
        )

    @property
    def allowed(self) -> bool:
        return self.outcome is DecisionOutcome.ALLOW

    def as_error_payload(self) -> dict[str, Any]:
        """Default LLM-facing dict rendering. Adapters can build their own."""
        payload: dict[str, Any] = {
            "type": self.error_type or self.outcome.value,
            "message": self.reason,
            "tool_name": self.tool_name,
            "agent_name": self.agent_name,
            "retryable": False,
        }
        if self.role is not None:
            payload["role"] = self.role
        if self.hint is not None:
            payload["hint"] = self.hint
        if self.violations:
            payload["violations"] = list(self.violations)
        return payload

    def as_error_message(self) -> str:
        """Default LLM-facing string rendering for adapters that return a
        tool-result string (OpenAI Agents, Google ADK) or raise a
        text-bearing exception (pydantic_ai's `ModelRetry`).
        """
        marker = self.error_type or self.outcome.value
        if self.outcome is DecisionOutcome.NEEDS_APPROVAL:
            body = f"Tool '{self.tool_name}' requires human approval before execution"
        else:
            body = f"Tool '{self.tool_name}' is denied by the agent policy"
        return f"[{marker}] {body}. The tool was not executed."
