"""Security-related runtime errors."""

from __future__ import annotations


class PolicyDeniedError(RuntimeError):
    """Raise when a policy denies a tool invocation."""


class ApprovalRequiredError(RuntimeError):
    """Raise when a policy marks a tool invocation as approval-gated."""


class AgentBannedError(RuntimeError):
    """Execution refused by a kill-switch ban, before the LLM runs.

    Enriched (not a bare throw) so integrators can render good UX without
    reverse-engineering: ``code`` / ``ban_type`` / ``reason`` allow localization,
    and ``user_message`` is a sensible default safe to show verbatim.
    """

    def __init__(
        self,
        *,
        ban_type: str,
        target: str,
        code: str,
        reason: str | None = None,
        user_message: str | None = None,
    ) -> None:
        self.ban_type = ban_type  # "agent" | "user"
        self.target = target  # agent_name or user_id
        self.code = code  # "agent_banned" | "user_banned"
        self.reason = reason  # operator-supplied, may be None
        self.user_message = user_message or (
            "This agent is currently disabled by an administrator."
            if ban_type == "agent"
            else "Your access to this agent has been suspended by an administrator."
        )
        super().__init__(self.user_message)
