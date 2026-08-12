"""Typed result of evaluating one proposed tool call against a PolicySet.

Also home to :func:`combine_role_verdicts`, the permissive union that turns
N single-role :class:`Verdict`s into one. It lives here rather than in the
enforcer because it is pure and engine-agnostic: both engines produce the
same ``Verdict`` shape per role, so folding above them keeps the two
byte-for-byte comparable one role at a time.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
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


# --- Permissive union over a caller's roles -----------------------------------
#
# "Access iff any of the caller's roles grants it", extended to cover approval:
# a lattice max over the three outcomes. ALLOW beats NEEDS_APPROVAL — if one
# role grants unconditional access, the caller has it and no approval is asked.
# Approval is deliberately NOT sticky; the opposite reading is restrictive,
# which would contradict the point of a union.
_RANK: dict[DecisionOutcome, int] = {
    DecisionOutcome.ALLOW: 2,
    DecisionOutcome.NEEDS_APPROVAL: 1,
    DecisionOutcome.DENY: 0,
}

# Mirrors the platform's ``DecisionEvent.reason`` max_length. A merged reason
# over N roles can genuinely get long; over this cap the platform rejects the
# audit event outright, losing the record for exactly the calls most worth
# keeping. Bounded here, at the one place that composes such a reason.
_MAX_REASON_CHARS = 4096


def combine_role_verdicts(
    roles: Sequence[str | None],
    evaluate: Callable[[str | None], Verdict],
) -> tuple[Verdict, str | None]:
    """Permissive union over one caller's roles: ALLOW > NEEDS_APPROVAL > DENY.

    Calls ``evaluate`` once per role, in the order given, short-circuiting on
    the first ALLOW — so the common case costs a single engine invocation.
    Returns the winning verdict and the role that decided it (``None`` when
    every role denied, since no role granted anything).

    A single role — or several roles producing equal denials — returns that
    verdict verbatim, so single-role behaviour is identical to evaluating that
    role on its own. Callers must pass a non-empty sequence; the enforcer sends
    ``[None]`` for "no roles", which the engines map to the ``default`` policy.
    """
    if not roles:
        raise ValueError(
            "combine_role_verdicts needs at least one role; pass [None] to "
            "evaluate the default policy (an empty list would fail open)"
        )

    best: Verdict | None = None
    best_role: str | None = None
    denials: list[Verdict] = []
    denial_roles: list[str | None] = []

    for role in roles:
        verdict = evaluate(role)
        if verdict.outcome is DecisionOutcome.ALLOW:
            return verdict, role
        if verdict.outcome is DecisionOutcome.DENY:
            denials.append(verdict)
            denial_roles.append(role)
        if best is None or _RANK[verdict.outcome] > _RANK[best.outcome]:
            best, best_role = verdict, role

    if best is not None and best.outcome is not DecisionOutcome.DENY:
        return best, best_role
    return _merge_denials(denials, denial_roles), None


def _merge_denials(denials: Sequence[Verdict], roles: Sequence[str | None]) -> Verdict:
    """Fold every role's denial into one, so "why?" stays answerable.

    Identical denials collapse to the first verbatim — the common case, since
    unrecognised roles all resolve to the same ``default`` policy, and it keeps
    a single-role denial's message unchanged. Otherwise the reason names each
    role's cause and ``violations`` are unioned in first-seen order.

    ``hint`` survives only when every denial produced an equal one: a
    file-scope hint promises the scope the caller may stay within, so merging
    two different scopes would state something false to the model.
    """
    if not denials:  # pragma: no cover - callers only merge non-empty denials
        raise ValueError("_merge_denials needs at least one denial")
    first = denials[0]
    if all(other == first for other in denials[1:]):
        return first

    violations: list[str] = []
    for verdict in denials:
        for violation in verdict.violations:
            if violation not in violations:
                violations.append(violation)

    named = [role for role in roles if role is not None]
    header = f"denied for all roles [{', '.join(named)}]" if named else "denied"
    clauses: list[str] = []
    for role, verdict in zip(roles, denials):
        if verdict.reason:
            clauses.append(f"{role or 'default'}: {verdict.reason}")
    reason = _bounded_reason(header, clauses)

    hint = first.hint if all(v.hint == first.hint for v in denials[1:]) else None
    return Verdict(
        outcome=DecisionOutcome.DENY,
        reason=reason,
        violations=tuple(violations),
        hint=hint,
    )


def _bounded_reason(header: str, clauses: Sequence[str]) -> str:
    """Join per-role clauses under ``_MAX_REASON_CHARS``, trimming the tail.

    Drops whole clauses rather than cutting mid-sentence, and says how many it
    dropped — a truncated explanation that hides its own truncation is worse
    than a short one.
    """
    reason = f"{header}: {'; '.join(clauses)}" if clauses else header
    if len(reason) <= _MAX_REASON_CHARS:
        return reason
    kept: list[str] = []
    for clause in clauses:
        candidate = [*kept, clause]
        suffix = f" (+{len(clauses) - len(candidate)} more roles)"
        if len(f"{header}: {'; '.join(candidate)}{suffix}") > _MAX_REASON_CHARS:
            break
        kept.append(clause)
    dropped = len(clauses) - len(kept)
    if not kept:
        return f"{header} (+{dropped} more roles)"[:_MAX_REASON_CHARS]
    return f"{header}: {'; '.join(kept)} (+{dropped} more roles)"


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
    # The distinct roles the caller carried, in their order, as evaluated by
    # the permissive union. Empty when no context was active (or it carried no
    # roles) — that call was decided by the ``default`` policy.
    user_roles: tuple[str, ...] = ()
    # The role whose policy granted the call (or gated it on approval).
    # ``None`` on a deny: no role granted anything, so attributing the denial
    # to one of them would misdirect whoever reads the record.
    deciding_role: str | None = None
    reason: str = ""
    error_type: str | None = None
    hint: dict[str, Any] | None = None
    violations: tuple[str, ...] = ()
    arguments: dict[str, Any] | None = None
    # The ABAC attribute snapshot the decision was evaluated against, so an
    # in-process observer sees the ``ctx.*`` values that drove the outcome, and
    # so the audit record can explain a ``ctx.*``-driven deny. Persisted by the
    # audit sender (redacted + capped in ``audit.as_payload``); deliberately
    # still absent from ``as_error_payload`` — the model must never see it.
    attributes: dict[str, Any] | None = None

    @classmethod
    def from_verdict(
        cls,
        verdict: Verdict,
        *,
        agent_name: str,
        tool_name: str,
        user_roles: tuple[str, ...] = (),
        deciding_role: str | None = None,
        arguments: dict[str, Any] | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> "Decision":
        """Lift an engine :class:`Verdict` into a host-facing decision.

        The verdict carries the outcome and any structured detail the
        engine produced (reason, file-scope hint); this stamps on the
        host context the engine doesn't know — agent name, the caller's
        role set and which of them decided, the argument snapshot, and the
        ABAC attribute snapshot — and derives the ``error_type`` tag.
        """
        return cls(
            outcome=verdict.outcome,
            agent_name=agent_name,
            tool_name=tool_name,
            user_roles=user_roles,
            deciding_role=deciding_role,
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

    @property
    def role(self) -> str | None:
        """The caller's first role, or ``None`` when they carried none.

        The legacy single-role view, kept because that is what renderers and
        the audit wire field have always shown. Enforcement reads
        ``user_roles``; provenance reads ``deciding_role``.
        """
        return self.user_roles[0] if self.user_roles else None

    def as_error_payload(self) -> dict[str, Any]:
        """Default LLM-facing dict rendering. Adapters can build their own.

        ``role`` is the *deciding* role, so it appears on an approval (the role
        that would grant it) and not on a deny (no role granted anything). The
        caller's full role set is deliberately withheld — same minimisation as
        ``attributes``: the model has no use for the other roles, and a denial's
        explanation belongs in ``message``.
        """
        payload: dict[str, Any] = {
            "type": self.error_type or self.outcome.value,
            "message": self.reason,
            "tool_name": self.tool_name,
            "agent_name": self.agent_name,
            "retryable": False,
        }
        if self.deciding_role is not None:
            payload["role"] = self.deciding_role
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
