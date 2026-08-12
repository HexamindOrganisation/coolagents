"""Shared helpers for the tool-hook pipeline tests.

The runner is exercised directly with a lightweight fake enforcer so the
tests isolate pipeline behavior from the policy engine. End-to-end wiring
through ``GuardedTool`` is covered under ``tests/adapters/langchain``.
"""

from __future__ import annotations

from typing import Any

from hexgate.security.decision import Decision, DecisionOutcome, Verdict


class FakeEnforcer:
    """Records the args ``decide`` saw and returns a preset Decision."""

    def __init__(
        self, outcome: DecisionOutcome = DecisionOutcome.ALLOW, reason: str = ""
    ) -> None:
        self.agent_name = "test-agent"
        self._outcome = outcome
        self._reason = reason
        self.seen_args: dict[str, Any] | None = None

    def decide(self, tool_name: str, arguments: Any) -> Decision:
        self.seen_args = dict(arguments)
        return Decision.from_verdict(
            Verdict(outcome=self._outcome, reason=self._reason),
            agent_name=self.agent_name,
            tool_name=tool_name,
        )


def langchain_error(decision: Decision) -> dict[str, Any]:
    """Mirror the adapter's error renderer so assertions match production."""
    return {"ok": False, "error": decision.as_error_payload()}


class RecordingInvoke:
    """An ``invoke`` closure that records the final args and returns a value."""

    def __init__(self, value: Any = "tool-ran") -> None:
        self.value = value
        self.calls: list[dict[str, Any]] = []

    async def aio(self, final: dict[str, Any]) -> Any:
        self.calls.append(final)
        return self.value

    def sync(self, final: dict[str, Any]) -> Any:
        self.calls.append(final)
        return self.value
