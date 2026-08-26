"""Agent-level admission enforcement.

:class:`AgentGate` is to a whole agent run what the egress :class:`~hexgate.egress.gate.Gate`
is to a network request: one place that reuses :meth:`PolicyEnforcer.decide` for
a non-tool subject. It gates *admission* — may this caller, in this role, run this
agent — by deciding the synthetic ``agent.run`` key at run entry, before the model
sees anything.

Engagement is opt-in. The gate enforces only when the current policy declares an
``admission`` block anywhere, read per run via ``PolicyEngine.declares_admission()``
(not at build time), so an agent whose policy never mentions admission runs exactly
as before, and a hot-reloaded policy that adds or drops admission is honored on the
next run. Once admission is declared, agent keys are closed-world (R-AGENT-002): a
caller whose role is not granted admission is refused, so a silent co-role can
neither admit an unknown caller nor defeat an explicit deny. A denial is
caller-facing: admission fires before the model runs, so there is no tool result to
render into, the run simply does not start.
"""

from __future__ import annotations

import logging
from inspect import isawaitable
from typing import TYPE_CHECKING, Any

from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.models import AGENT_RUN_TOOL

if TYPE_CHECKING:
    from hexgate.approvals import ApprovalHandler
    from hexgate.security.decision import PolicyEngine
    from hexgate.security.enforcer import PolicyEnforcer

_log = logging.getLogger(__name__)

# Dedupe key: admission is enforced only on the native HexgateAgent in A2, so the
# framework adapters warn once per (framework, agent) that a declared admission
# block is not enforced there yet. Per-adapter run-entry admission lands in A3.
_admission_unenforced_warned: set[tuple[str, str]] = set()


def warn_if_admission_unenforced(
    engine: PolicyEngine, *, framework: str, agent_name: str
) -> None:
    """Warn once when a policy declares admission on an adapter that can't enforce it.

    Admission (the ``agent.run`` run-entry gate) is wired only into the native
    :class:`~hexgate.agents.factory.HexgateAgent` in A2; the OpenAI/Google/
    pydantic_ai/LangChain adapters check the ban gate at run entry but not
    admission. Until per-adapter admission lands (A3), a declared ``admission``
    block is a silent no-op on those adapters — so surface it loudly at wrap time
    rather than fail open without a trace. No-op when the policy declares no
    admission (the common case), and deduped per ``(framework, agent_name)`` so a
    long-lived process logs it once, not per run."""
    if not engine.declares_admission():
        return
    key = (framework, agent_name)
    if key in _admission_unenforced_warned:
        return
    _admission_unenforced_warned.add(key)
    _log.warning(
        "policy for agent %r declares an 'admission' block, but admission is not "
        "enforced on the %s adapter yet (only on the native HexgateAgent); this run "
        "will proceed without an admission check. Per-adapter admission lands in a "
        "follow-up (A3); use the native agent to enforce admission today.",
        agent_name,
        framework,
    )


class AgentNotAdmittedError(Exception):
    """Raised at run entry when admission policy refuses this caller.

    Carries the :class:`Decision` so the caller can inspect the reason; the
    message is the model-safe rendering (arguments and attributes withheld).
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.as_error_message())


class AgentGate:
    """Reduce an agent run to an admit/refuse verdict via the enforcer.

    Always built; whether it enforces is decided per run from
    ``PolicyEngine.declares_admission()``, so its presence does not mean "enforce".
    Mirrors the egress ``Gate``: hold the enforcer and the approval handler, decide,
    fold approval, fail closed.
    """

    def __init__(
        self,
        enforcer: PolicyEnforcer,
        *,
        approval_handler: ApprovalHandler | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._approval_handler = approval_handler

    def check_admission(self) -> None:
        """Raise :class:`AgentNotAdmittedError` if admission policy refuses (sync).

        Reads the caller's role from the active context the enforcer sees, so the
        caller's ``HexgateContext`` scope must already be open at this call site.
        No-op when the current policy declares no admission — checked here, not at
        build time, so a hot-reloaded policy that adds or drops admission is
        honored on the next run rather than frozen at bind.
        """
        if not self._enforcer.policy.declares_admission():
            return
        decision = self._decide()
        if decision.allowed:
            return
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and self._approval_handler is not None
            and self._resolve_approval_sync(decision)
        ):
            return
        raise AgentNotAdmittedError(decision)

    async def check_admission_async(self) -> None:
        """Async mirror of :meth:`check_admission` — awaits an async handler."""
        if not self._enforcer.policy.declares_admission():
            return
        decision = self._decide()
        if decision.allowed:
            return
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and self._approval_handler is not None
            and await self._resolve_approval_async(decision)
        ):
            return
        raise AgentNotAdmittedError(decision)

    def _decide(self) -> Decision:
        # agent name rides in args so a constraint can read args.agent; the
        # enforcer folds the caller's roles and emits the audit event.
        return self._enforcer.decide(
            AGENT_RUN_TOOL, {"agent": self._enforcer.agent_name}
        )

    def _resolve_approval_sync(self, decision: Decision) -> bool:
        handler = self._approval_handler
        if isinstance(handler, bool):
            return handler
        try:
            result: Any = handler(decision)  # type: ignore[misc]
            if isawaitable(result):
                # A sync run entrypoint has no loop to await on; deny rather than
                # silently skip the human check. Close the coroutine so it does
                # not leak as a never-awaited warning.
                if hasattr(result, "close"):
                    result.close()
                _log.error(
                    "admission approval_handler is async on a sync run; "
                    "denying (fail-closed)"
                )
                return False
            return bool(result)
        except Exception:
            _log.exception("admission approval_handler raised; denying (fail-closed)")
            return False

    async def _resolve_approval_async(self, decision: Decision) -> bool:
        handler = self._approval_handler
        if isinstance(handler, bool):
            return handler
        try:
            result: Any = handler(decision)  # type: ignore[misc]
            if isawaitable(result):
                result = await result
            return bool(result)
        except Exception:
            _log.exception("admission approval_handler raised; denying (fail-closed)")
            return False


def resolve_agent_gate(
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> AgentGate:
    """Build the admission gate for ``enforcer``.

    Always returns a gate (unlike :func:`~hexgate.security.bans.resolve_ban_gate`,
    which needs a platform): admission is a local policy decision. Whether the gate
    actually enforces is decided per run inside :meth:`AgentGate.check_admission`,
    so a hot-reloaded policy that adds or drops admission is honored without
    rebuilding the gate. A policy with no admission block makes every check a no-op.
    """
    return AgentGate(enforcer, approval_handler=approval_handler)
