"""Agent-level admission and reach enforcement.

Two gates that are to a whole agent run what the egress :class:`~hexgate.egress.gate.Gate`
is to a network request: one place that reuses :meth:`PolicyEnforcer.decide` for a
non-tool subject, folds approval, and fails closed.

* :class:`AgentGate` gates *admission* — may this caller, in this role, run this
  agent at all — by deciding the synthetic ``agent.run`` key at run entry, before
  the model sees anything.
* :class:`ReachGate` gates *reach* — may this agent hand off to (or delegate
  as-tool to) another agent — by deciding the synthetic ``agent.handoff:<target>``
  / ``agent.tool:<target>`` key at the handoff/delegation seam.

Both share one shape (:class:`_PolicyGate`): hold the enforcer + approval handler,
decide, fold approval, fail closed. Engagement is opt-in and read per run from the
policy (``declares_admission()`` / ``declares_reach()``), not frozen at build time,
so a hot-reloaded policy that adds or drops a block is honored on the next run and
an agent whose policy never mentions admission/reach runs exactly as before. Once a
block is declared, agent keys are closed-world (R-AGENT-002): a caller/agent not
granted the key is refused, so a silent co-role can neither grant an unknown subject
nor defeat an explicit deny.
"""

from __future__ import annotations

import logging
from inspect import isawaitable
from typing import TYPE_CHECKING, Any

from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.models import AGENT_RUN_TOOL, agent_target_key
from hexgate.security.naming import canonical_name

if TYPE_CHECKING:
    from hexgate.approvals import ApprovalHandler
    from hexgate.security.decision import PolicyEngine
    from hexgate.security.enforcer import PolicyEnforcer
    from hexgate.security.models import AgentVia

_log = logging.getLogger(__name__)


# ---- interim adapter warnings ---------------------------------------------
#
# Admission and reach are wired into some adapters incrementally. Where an adapter
# cannot enforce a declared block yet, warn once per (framework, agent) rather than
# fail open in silence. Deduped so a long-lived process logs it once, not per run.
_admission_unenforced_warned: set[tuple[str, str]] = set()
_reach_unenforced_warned: set[tuple[str, str]] = set()


def warn_if_admission_unenforced(
    engine: PolicyEngine, *, framework: str, agent_name: str
) -> None:
    """Warn once when a policy declares admission on an adapter that can't enforce it.

    Admission (the ``agent.run`` run-entry gate) is not wired into every framework
    adapter yet. Where it is not, a declared ``admission`` block is a silent no-op,
    so surface it loudly at wrap time. No-op when the policy declares no admission
    (the common case)."""
    if not engine.declares_admission():
        return
    if not _mark_warned(_admission_unenforced_warned, framework, agent_name):
        return
    _log.warning(
        "policy for agent %r declares an 'admission' block, but admission is not "
        "enforced on the %s adapter yet; this run will proceed without an admission "
        "check. Use the native agent (or a supported adapter) to enforce admission.",
        agent_name,
        framework,
    )


def warn_if_reach_unenforced(
    engine: PolicyEngine, *, framework: str, agent_name: str
) -> None:
    """Warn once when a policy declares reach on an adapter that can't enforce it.

    Reach (``agent.handoff:`` / ``agent.tool:``) is enforced only where the
    framework exposes a target-agent handle at the seam (OpenAI handoffs, Google
    sub-agents/AgentTool). On adapters that hide the target (pydantic_ai delegation
    inside a tool body, the native single-graph agent), a declared reach block is a
    silent no-op, so surface it loudly. No-op when no reach is declared."""
    if not engine.declares_reach():
        return
    if not _mark_warned(_reach_unenforced_warned, framework, agent_name):
        return
    _log.warning(
        "policy for agent %r declares agent reach ('agents' block), but reach is not "
        "enforced on the %s adapter yet (it exposes no target-agent handle at the "
        "handoff/delegation seam); handoffs will proceed without a reach check.",
        agent_name,
        framework,
    )


def _mark_warned(seen: set[tuple[str, str]], framework: str, agent_name: str) -> bool:
    """Record ``(framework, agent_name)`` in ``seen``; return True the first time."""
    key = (framework, agent_name)
    if key in seen:
        return False
    seen.add(key)
    return True


# ---- errors ---------------------------------------------------------------


class AgentNotAdmittedError(Exception):
    """Raised at run entry when admission policy refuses this caller.

    Carries the :class:`Decision` so the caller can inspect the reason; the
    message is the model-safe rendering (arguments and attributes withheld).
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.as_error_message())


class ReachNotAllowedError(Exception):
    """Raised at a handoff/delegation seam when reach policy refuses the target.

    The reach counterpart to :class:`AgentNotAdmittedError`: it fires when the
    source agent may not reach the target agent, before control transfers. Carries
    the :class:`Decision`; the message is the model-safe rendering.
    """

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.as_error_message())


# ---- gates ----------------------------------------------------------------


class _PolicyGate:
    """Shared machinery for the admission and reach gates.

    Holds the enforcer and approval handler and folds a NEEDS_APPROVAL verdict
    through the handler (fail-closed on any error, or on an async handler reached
    from a sync entrypoint). Subclasses add their subject-specific ``decide`` and
    the engagement check; ``_SUBJECT`` labels the fail-closed log lines.
    """

    _SUBJECT = "policy"

    def __init__(
        self,
        enforcer: PolicyEnforcer,
        *,
        approval_handler: ApprovalHandler | None = None,
    ) -> None:
        self._enforcer = enforcer
        self._approval_handler = approval_handler

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
                    "%s approval_handler is async on a sync run; denying (fail-closed)",
                    self._SUBJECT,
                )
                return False
            return bool(result)
        except Exception:
            _log.exception(
                "%s approval_handler raised; denying (fail-closed)", self._SUBJECT
            )
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
            _log.exception(
                "%s approval_handler raised; denying (fail-closed)", self._SUBJECT
            )
            return False


class AgentGate(_PolicyGate):
    """Reduce an agent run to an admit/refuse verdict via the enforcer.

    Always built; whether it enforces is decided per run from
    ``PolicyEngine.declares_admission()``, so its presence does not mean "enforce".
    """

    _SUBJECT = "admission"

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


class ReachGate(_PolicyGate):
    """Reduce an agent-to-agent reach to an allow/refuse verdict via the enforcer.

    Always built; whether it enforces is decided per seam from
    ``PolicyEngine.declares_reach()``. The source agent's policy governs reach, so
    this gate is built from the source agent's enforcer and decides the target's
    lowered key (``agent.handoff:<target>`` / ``agent.tool:<target>``).
    """

    _SUBJECT = "reach"

    def check_reach(self, target: str, *, via: AgentVia) -> None:
        """Raise :class:`ReachNotAllowedError` if reach to ``target`` is refused (sync).

        ``target`` is the target agent's name (canonicalized here so it matches the
        policy key derived from the same name). No-op when the current policy
        declares no reach.
        """
        if not self._enforcer.policy.declares_reach():
            return
        decision = self._decide(target, via)
        if decision.allowed:
            return
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and self._approval_handler is not None
            and self._resolve_approval_sync(decision)
        ):
            return
        raise ReachNotAllowedError(decision)

    async def check_reach_async(self, target: str, *, via: AgentVia) -> None:
        """Async mirror of :meth:`check_reach` — awaits an async handler."""
        if not self._enforcer.policy.declares_reach():
            return
        decision = self._decide(target, via)
        if decision.allowed:
            return
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and self._approval_handler is not None
            and await self._resolve_approval_async(decision)
        ):
            return
        raise ReachNotAllowedError(decision)

    def _decide(self, target: str, via: AgentVia) -> Decision:
        # target/via ride in args so a constraint can read args.target / args.via;
        # the key encodes the same (canonical) target so the policy match is exact.
        canonical = canonical_name(target)
        return self._enforcer.decide(
            agent_target_key(via, canonical),
            {"agent": self._enforcer.agent_name, "target": canonical, "via": via},
        )


# ---- builders -------------------------------------------------------------


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


def resolve_reach_gate(
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> ReachGate:
    """Build the reach gate for ``enforcer`` (the reach counterpart to
    :func:`resolve_agent_gate`). Always returns a gate; enforcement is decided per
    seam from the current policy, so a policy with no ``agents`` block is a no-op.
    """
    return ReachGate(enforcer, approval_handler=approval_handler)
