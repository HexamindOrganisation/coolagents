"""Tool-shape-agnostic policy enforcement.

:class:`PolicyEnforcer` returns a :class:`Decision` for a proposed tool
call and stops — adapters translate it for their host. Stateless across
calls: each :meth:`decide` re-reads the active :class:`HexgateContext`
from the contextvar.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Callable, Mapping
from typing import Any

from hexgate.audit import AuditEvent, configure
from hexgate.runtime.context import (
    get_current_context,
    get_current_tool_use_context,
)
from hexgate.security.decision import Decision, PolicyEngine
from hexgate.tracing._senders import AuditSender

_log = logging.getLogger(__name__)

# A sync, fire-and-forget hook fired after every decision is built.
# Used today by ``hexgate chat`` to render denies / approvals inline in the
# REPL; future consumers (metrics, debuggers) would slot in the same way.
# Distinct from ``AuditSender`` (which posts to the platform) — the observer
# stays on the caller's machine and gets the full ``Decision`` object, not
# a wire-shaped payload.
DecisionObserver = Callable[[Decision], None]


def _snapshot(values: Mapping[str, Any], *, deep: bool) -> dict[str, Any]:
    """Copy a mapping for retention on a :class:`Decision`.

    Deep when an audit sender or observer may inspect it after ``decide()``
    returns: a shallow copy would let the caller mutate a nested value first
    and make the captured record lie about what was decided.
    """
    return copy.deepcopy(dict(values)) if deep else dict(values)


class PolicyEnforcer:
    """Evaluate proposed tool calls against a policy engine.

    ``policy`` is any :class:`~hexgate.security.decision.PolicyEngine` —
    in practice a :class:`~hexgate.security.policy_set.PolicySet` (the
    role-aware pydantic engine) or a
    :class:`~hexgate.security.bundle.PolicyBundle` (a compiled WASM bundle,
    the Rego enforcement path). The enforcer only knows the protocol, so
    it never branches on which engine ran.
    """

    def __init__(
        self,
        policy: PolicyEngine,
        *,
        agent_name: str = "default",
        audit_sender: AuditSender | None = None,
        decision_observer: DecisionObserver | None = None,
    ) -> None:
        self.policy = policy
        self.agent_name = agent_name
        # Injected per-agent so each agent emits with its own api_key's sender.
        # ``None`` means audit is inert for this enforcer.
        self._audit_sender = audit_sender
        # Local-process hook (no IO). ``hexgate chat`` injects one that
        # appends to a deque the REPL drains between turns; tests inject
        # a list-append. Distinct slot from audit so a deployment can have
        # one without the other.
        self._decision_observer = decision_observer

    def decide(self, tool_name: str, arguments: Mapping[str, Any]) -> Decision:
        """Resolve role from the contextvar, ask the engine for a
        :class:`~hexgate.security.decision.Verdict`, and lift it into a
        host-facing :class:`Decision` with this agent's context.

        Emits an :class:`~hexgate.audit.AuditEvent` to this enforcer's
        injected sender after the decision is built, and calls the
        injected ``decision_observer`` (if any) with the same Decision.
        Both are no-ops when not injected; both are isolated so a
        broken observer never breaks enforcement."""
        context = get_current_context()
        role = context.primary_role if context is not None else None
        # Resolve the ABAC bag under the two-tier trust model: advisory keys
        # pass through from the contextvar, but any key the policy declared
        # *trusted* is taken only from the cryptographically-verified token —
        # a spoofed contextvar value for a trusted key is dropped, and a
        # trusted key absent from the token is omitted entirely (so a ``ctx.*``
        # constraint on it fails closed).
        attributes = self._resolve_attributes(context)
        # Both snapshots deep-copy on the same condition: ``attributes`` can
        # hold a ``list[str]`` and lives on a contextvar that outlives the
        # call, so a shallow copy would alias a mutable value into a retained
        # Decision exactly like a shallow ``args`` copy would.
        retained = self._audit_sender is not None or self._decision_observer is not None
        args_snapshot = _snapshot(arguments, deep=retained)
        attrs_snapshot = (
            _snapshot(attributes, deep=retained) if attributes is not None else None
        )

        verdict = self.policy.evaluate(
            role=role, tool=tool_name, args=args_snapshot, attributes=attrs_snapshot
        )
        decision = Decision.from_verdict(
            verdict,
            agent_name=self.agent_name,
            tool_name=tool_name,
            role=role,
            arguments=args_snapshot,
            attributes=attrs_snapshot,
        )

        if self._audit_sender is not None:
            self._audit_sender.emit(
                AuditEvent(
                    decision=decision,
                    user_id=context.user_id
                    if context is not None and context.user_id
                    else "",
                    session_id=context.session_id
                    if (context is not None and context.session_id)
                    else "",
                    trusted_attributes=self._trusted_attributes(),
                )
            )

        if self._decision_observer is not None:
            try:
                self._decision_observer(decision)
            except Exception:
                # A broken observer (chat-panel render bug, third-party
                # subscriber raising) must not break enforcement — the
                # Decision the agent acts on is the source of truth.
                _log.exception("decision_observer raised; ignoring")

        return decision

    def _trusted_attributes(self) -> frozenset[str]:
        """Policy-declared trusted ``ctx.*`` keys, read defensively.

        Reads the engine's ``trusted_attributes`` if present; an engine that
        predates the signed tier (or a lightweight test double) has none, so it
        resolves to empty — every attribute stays advisory, i.e. the pre-signed
        behavior. Never raises."""
        return frozenset(getattr(self.policy, "trusted_attributes", frozenset()))

    def _resolve_attributes(self, context: object) -> dict[str, Any] | None:
        """Merge the advisory contextvar bag with token-verified trusted attrs.

        Returns the single ``ctx.*`` mapping both engines evaluate against:

        * advisory (non-trusted) keys pass through from
          ``HexgateContext.attributes`` unchanged;
        * trusted keys are dropped from the advisory bag (a spoofed contextvar
          value must never influence a trusted decision) and re-added *only*
          from the verified token — so a trusted key the token doesn't carry
          is simply absent, and any constraint on it fails closed.

        Trust resolution lives here (host layer), not in either engine, so the
        two engines keep receiving one identical bag — the zero-drift invariant
        holds with no engine change. ``None`` when no context scope is active.
        """
        if context is None:
            return None
        advisory = dict(getattr(context, "attributes", {}) or {})
        trusted = self._trusted_attributes()
        if not trusted:
            return advisory
        tool_ctx = get_current_tool_use_context()
        verified = (
            tool_ctx.verified_attributes if tool_ctx is not None else None
        ) or {}
        resolved = {key: val for key, val in advisory.items() if key not in trusted}
        resolved.update({key: verified[key] for key in trusted if key in verified})
        return resolved


def build_enforcer(
    engine: PolicyEngine,
    *,
    agent_name: str = "default",
    api_key: str | None = None,
    decision_observer: DecisionObserver | None = None,
) -> PolicyEnforcer:
    """Compose a governed enforcer — engine + audit sender from ``api_key``.

    The one place that pairs an engine with its audit sink, so the six
    surfaces (``HexgateAgent.enforce_policy``, the four adapters, the
    OpenAI runner) don't each repeat the ``audit.configure`` wiring.
    ``api_key=None`` falls back to ``HEXGATE_API_KEY`` (audit stays inert when
    neither resolves). ``decision_observer`` threads the local-process
    decision hook (see :class:`PolicyEnforcer`); ``None`` is silent.
    """
    return PolicyEnforcer(
        engine,
        agent_name=agent_name,
        audit_sender=configure(api_key),
        decision_observer=decision_observer,
    )
