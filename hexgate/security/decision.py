"""Typed result of evaluating one proposed tool call against a PolicySet.

Also home to :func:`combine_role_verdicts`, the permissive union over a caller's
roles. It sits above both engines rather than inside them, so they stay
single-role and byte-for-byte comparable.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final, Protocol, runtime_checkable

from hexgate.tracing import semconv


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
        run: Mapping[str, Any] | None = None,
    ) -> Verdict: ...


# Over the platform's ``DecisionEvent.reason`` max_length the audit event is
# rejected outright, losing the record for the calls most worth keeping.
_MAX_REASON_CHARS = 4096


def combine_role_verdicts(
    roles: Sequence[str | None],
    evaluate: Callable[[str | None], Verdict],
) -> tuple[Verdict, str | None]:
    """Permissive union over one caller's roles: ALLOW > NEEDS_APPROVAL > DENY.

    Returns the winning verdict and the role that decided it (``None`` when every
    role denied). ALLOW beats NEEDS_APPROVAL — approval is not sticky, so one
    role granting outright removes another role's gate.

    A single role, or several producing equal denials, returns that verdict
    verbatim. ``roles`` must be non-empty; ``[None]`` means "no roles" and
    selects the ``default`` policy.
    """
    if not roles:
        raise ValueError(
            "combine_role_verdicts needs at least one role; pass [None] to "
            "evaluate the default policy (an empty list would fail open)"
        )

    approval: tuple[Verdict, str | None] | None = None
    denials: list[tuple[str | None, Verdict]] = []

    for role in roles:
        verdict = evaluate(role)
        if verdict.outcome is DecisionOutcome.ALLOW:
            return verdict, role  # short-circuit: the rest are never asked
        if verdict.outcome is DecisionOutcome.NEEDS_APPROVAL:
            approval = approval or (verdict, role)
        else:
            denials.append((role, verdict))

    return approval or (_merge_denials(denials), None)


def _merge_denials(denials: Sequence[tuple[str | None, Verdict]]) -> Verdict:
    """Fold every role's denial into one, so "why?" stays answerable.

    Identical denials collapse to the first verbatim — the common case, since
    unrecognised roles share the ``default`` policy. Otherwise the reason names
    each role's cause and ``violations`` are unioned.

    ``hint`` survives only if unanimous: it promises the scope the caller may
    stay within, so merging two different scopes would state something false.
    """
    if not denials:  # pragma: no cover - callers only merge non-empty denials
        raise ValueError("_merge_denials needs at least one denial")
    verdicts = [verdict for _, verdict in denials]
    first = verdicts[0]
    if all(other == first for other in verdicts[1:]):
        return first

    violations: list[str] = []
    for verdict in verdicts:
        for violation in verdict.violations:
            if violation not in violations:
                violations.append(violation)

    named = [role for role, _ in denials if role is not None]
    header = f"denied for all roles [{', '.join(named)}]" if named else "denied"
    clauses = [
        f"{role or 'default'}: {verdict.reason}"
        for role, verdict in denials
        if verdict.reason
    ]
    reason = _bounded_reason(header, clauses)

    hint = first.hint if all(v.hint == first.hint for v in verdicts[1:]) else None
    return Verdict(
        outcome=DecisionOutcome.DENY,
        reason=reason,
        violations=tuple(violations),
        hint=hint,
    )


def _bounded_reason(header: str, clauses: Sequence[str]) -> str:
    """Join clauses under ``_MAX_REASON_CHARS``, dropping whole ones and saying
    how many — a truncation that hides itself is worse than a short reason."""
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


# ``run.elapsed_seconds`` is a float; the platform column is UInt32 ms.
_MILLISECONDS_PER_SECOND = 1000


@dataclass(frozen=True, slots=True)
class RunAttribution:
    """The run a decision belongs to, in the shape the audit wire wants.

    ``run_id`` is ``""`` outside a run scope, matching ``run_facts.DETACHED``.
    An in-process signal only — the wire field is ``UUID | None``.
    """

    run_id: str = ""
    tool_calls: int = 0
    llm_calls: int = 0
    denials: int = 0
    total_tokens: int = 0
    elapsed_ms: int = 0

    @classmethod
    def from_namespace(cls, run: Mapping[str, Any] | None) -> "RunAttribution":
        """Project the ``run.*`` namespace onto the five persisted counters.

        A subset: the other paths have no column yet.
        """
        if not run:
            return DETACHED_RUN
        return cls(
            run_id=str(run.get("id", "")),
            tool_calls=int(run.get("tool_calls", 0)),
            llm_calls=int(run.get("llm_calls", 0)),
            denials=int(run.get("denials", 0)),
            total_tokens=int(run.get("total_tokens", 0)),
            elapsed_ms=int(
                float(run.get("elapsed_seconds", 0.0)) * _MILLISECONDS_PER_SECOND
            ),
        )

    def as_span_attributes(self) -> dict[str, Any]:
        """Span attributes for a decision's run attribution.

        ``run_id`` is omitted outside a run scope, never sent as ``""``: OTLP
        attributes cannot carry null, and an empty string fails the enricher's
        ``UUID | None`` validation, which would DLQ the whole record rather
        than just its attribution. The counters always travel — zero is a
        meaningful tally.
        """
        attrs: dict[str, Any] = {
            semconv.RUN_TOOL_CALLS: self.tool_calls,
            semconv.RUN_LLM_CALLS: self.llm_calls,
            semconv.RUN_DENIALS: self.denials,
            semconv.RUN_TOTAL_TOKENS: self.total_tokens,
            semconv.RUN_ELAPSED_MS: self.elapsed_ms,
        }
        if self.run_id:
            attrs[semconv.RUN_ID] = self.run_id
        return attrs


# A decision with no run scope behind it. Safe to share: the class is frozen.
DETACHED_RUN: Final[RunAttribution] = RunAttribution()


@dataclass(frozen=True, slots=True)
class Decision:
    """One policy decision for a proposed tool invocation."""

    outcome: DecisionOutcome
    agent_name: str
    tool_name: str
    # Distinct roles the caller carried, in order; empty means the ``default``
    # policy decided the call.
    user_roles: tuple[str, ...] = ()
    # Role that granted or gated the call. ``None`` on a deny: no role granted
    # it, so naming one would misdirect whoever reads the record.
    deciding_role: str | None = None
    reason: str = ""
    error_type: str | None = None
    hint: dict[str, Any] | None = None
    violations: tuple[str, ...] = ()
    arguments: dict[str, Any] | None = None
    # The ABAC attribute snapshot the decision was evaluated against, so an
    # in-process observer sees the ``ctx.*`` values that drove the outcome, and
    # so the audit record can explain a ``ctx.*``-driven deny. Persisted by the
    # audit sender (redacted + capped in ``audit.AuditEvent.span_attributes``);
    # deliberately still absent from ``as_error_payload`` — the model must
    # never see it.
    attributes: dict[str, Any] | None = None
    # The run this decision belongs to. Persisted untouched (bounded ints and a
    # UUID, not caller data); absent from ``as_error_payload`` like
    # ``attributes`` — the model must not learn how close it is to its budget.
    run: RunAttribution = DETACHED_RUN

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
        run: RunAttribution = DETACHED_RUN,
    ) -> "Decision":
        """Lift an engine :class:`Verdict` into a host-facing decision, stamping
        on the context the engine doesn't know."""
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
            run=run,
        )

    @property
    def allowed(self) -> bool:
        return self.outcome is DecisionOutcome.ALLOW

    def as_error_payload(self) -> dict[str, Any]:
        """Default LLM-facing dict rendering. Adapters can build their own.

        ``role`` is the deciding role, so it is absent on a deny. The caller's
        other roles are withheld, like ``attributes``.
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

        Includes ``reason`` when present, so a guard ``Halt``'s actionable
        message (e.g. "remove the credential") reaches the model on the
        string-rendering adapters, the way it does in ``as_error_payload``.
        """
        marker = self.error_type or self.outcome.value
        if self.outcome is DecisionOutcome.NEEDS_APPROVAL:
            body = f"Tool '{self.tool_name}' requires human approval before execution"
        else:
            body = f"Tool '{self.tool_name}' is denied by the agent policy"
        if self.reason:
            # Introduce the reason with a colon (so a lowercase, imperative
            # guard reason reads naturally) and give it terminal punctuation,
            # so it does not run straight into the closing sentence.
            reason = self.reason.rstrip()
            end = "" if reason.endswith((".", "!", "?")) else "."
            return f"[{marker}] {body}: {reason}{end} The tool was not executed."
        return f"[{marker}] {body}. The tool was not executed."
