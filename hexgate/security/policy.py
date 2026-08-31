"""Helpers for loading and evaluating agent security policies."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from hexgate.security.constraints import check_constraints
from hexgate.security.decision import DecisionOutcome, Verdict
from hexgate.security.errors import ApprovalRequiredError, PolicyDeniedError
from hexgate.security.file_scope import build_file_scope_hint, is_path_allowed
from hexgate.security.models import (
    AGENT_RUN_TOOL,
    AgentPolicy,
    BaseToolPolicy,
    FileToolPolicy,
    ToolPolicy,
    is_agent_reach_key,
)

# Reach keys are closed-world: an unlisted agent.tool:/agent.handoff: denies
# regardless of default_policy, so a permissive tool default never silently grants
# agent reach. Admission (agent.run) is the opposite: opt-in, so an unlisted
# agent.run admits (a role that declares no admission does not restrict it).
_AGENT_REACH_CLOSED_WORLD_DENY = BaseToolPolicy(mode="deny")
_ADMISSION_OPT_IN_ALLOW = BaseToolPolicy(mode="allow")

if TYPE_CHECKING:
    from hexgate.security.bundle import PolicyBundle


def default_agent_policy() -> AgentPolicy:
    """Return the default deny-by-default policy."""
    return AgentPolicy()


def load_policy(policy: str | Path | AgentPolicy | None) -> AgentPolicy:
    """Load and validate an agent policy from YAML or an existing model."""
    if policy is None:
        return default_agent_policy()
    if isinstance(policy, AgentPolicy):
        return policy

    path = Path(policy)
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AgentPolicy.model_validate(payload)


def get_tool_policy(policy: AgentPolicy, tool_name: str) -> ToolPolicy:
    """Resolve the effective policy for a tool name.

    Reads ``effective_tools`` (authored tools plus lowered ``agent.*`` keys) so a
    synthetic agent-level key resolves through the same path as any tool. Fallbacks
    for an unlisted key differ by kind:

    * an unlisted **reach** key (``agent.tool:`` / ``agent.handoff:``) denies,
      closed-world, so a permissive ``default_policy`` cannot silently grant a
      handoff or sub-agent call;
    * an unlisted ``agent.run`` **admits** (admission is opt-in — a role that
      declares no admission does not restrict who may start the agent);
    * any other unlisted tool falls to ``default_policy``.

    The Rego compiler mirrors both (it excludes reach keys from its permissive
    catch-all and emits an opt-in allow rule for ``agent.run``), keeping the engines
    in agreement.
    """
    tool_policy = policy.effective_tools.get(tool_name)
    if tool_policy is not None:
        return tool_policy
    if tool_name == AGENT_RUN_TOOL:
        return _ADMISSION_OPT_IN_ALLOW
    if is_agent_reach_key(tool_name):
        return _AGENT_REACH_CLOSED_WORLD_DENY
    return policy.default_policy


def evaluate_tool_call(
    policy: AgentPolicy,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: Mapping[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> Verdict:
    """Return a :class:`Verdict` for a proposed tool call (pydantic engine).

    Evaluates the tool's ``constraints`` list against the invocation's
    arguments (see :mod:`hexgate.security.constraints` for the grammar).
    Every constraint must pass for the call to authorize — fail-closed by
    design. A path denial carries a machine-readable ``hint`` so the host
    can tell the model what scope it stayed within.

    Returns rather than raises; :func:`authorize_tool_call` wraps this for
    callers that want the legacy raise-on-deny contract. A malformed
    constraint (:class:`~hexgate.security.constraints.ConstraintParseError`)
    is a config error, not a denial, so it propagates instead of becoming
    a DENY verdict.
    """
    tool_policy = get_tool_policy(policy, tool_name)
    if tool_policy.mode == "deny":
        return Verdict(
            outcome=DecisionOutcome.DENY,
            reason=f'Policy denied tool "{tool_name}"',
        )

    try:
        check_constraints(
            tool_policy.constraints,
            arguments,
            tool_name,
            role=role,
            consts=policy.consts,
            attributes=attributes,
            run=run,
        )
    except PolicyDeniedError as exc:
        return Verdict(outcome=DecisionOutcome.DENY, reason=str(exc))

    if isinstance(tool_policy, FileToolPolicy) and not is_path_allowed(
        tool_name, arguments, tool_policy
    ):
        return Verdict(
            outcome=DecisionOutcome.DENY,
            reason=f'Policy denied tool "{tool_name}" for the requested path',
            hint=build_file_scope_hint(tool_policy),
        )

    if tool_policy.mode == "allow":
        return Verdict(outcome=DecisionOutcome.ALLOW)
    if tool_policy.mode == "approval_required":
        return Verdict(
            outcome=DecisionOutcome.NEEDS_APPROVAL,
            reason=f'Policy requires approval for tool "{tool_name}"',
        )
    return Verdict(
        outcome=DecisionOutcome.DENY,
        reason=f'Policy denied tool "{tool_name}"',
    )


def _raise_for_verdict(verdict: Verdict) -> None:
    """Translate a non-allow :class:`Verdict` into the legacy exception."""
    if verdict.outcome is DecisionOutcome.DENY:
        raise PolicyDeniedError(verdict.reason)
    if verdict.outcome is DecisionOutcome.NEEDS_APPROVAL:
        raise ApprovalRequiredError(verdict.reason)


def authorize_tool_call(
    policy: AgentPolicy,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    role: str | None = None,
    attributes: Mapping[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> None:
    """Raise when a tool call is denied or requires approval.

    Thin raise-on-deny wrapper over :func:`evaluate_tool_call`, kept for
    callers (the CLI, direct API users) that prefer the exception contract.
    ``role`` is forwarded so ``role``-scoped constraints see the caller's
    role — omitting it here would diverge from the WASM engine, which always
    receives ``input.role``. ``attributes`` and ``run`` are forwarded for the
    same reason: ``ctx.*`` constraints must see the caller's ABAC bag, and
    ``run.*`` constraints the current invocation's facts.
    """
    _raise_for_verdict(
        evaluate_tool_call(
            policy, tool_name, arguments, role=role, attributes=attributes, run=run
        )
    )


def evaluate_tool_call_wasm(
    bundle: PolicyBundle,
    role: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    attributes: Mapping[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> Verdict:
    """WASM-backed counterpart of :func:`evaluate_tool_call`.

    Evaluates the policy bundle's compiled wasm module for the given
    role + tool + args and maps the raw verdict onto an engine-agnostic
    :class:`Verdict`, so callers can't tell which engine produced it.

    On deny, ``violations`` carries the raw constraint strings the dev
    wrote in their YAML (kept as a list, not flattened), and ``reason``
    embeds them for a human-readable message. When no rule matched at all
    (deny-by-absence rather than deny-by-constraint), the reason surfaces
    a "no allow rule matched" hint so the message isn't silently empty.
    """
    decision = bundle.policy().decide(
        role=role,
        tool=tool_name,
        args=arguments or {},
        ctx=dict(attributes or {}),
        run=dict(run or {}),
    )
    return verdict_from_rego(decision, tool_name=tool_name, role=role)


def verdict_from_rego(rego: Any, *, tool_name: str, role: str) -> Verdict:
    """Map a raw :class:`~hexgate.security.wasm_engine.RegoVerdict` onto an
    engine-agnostic :class:`Verdict`.

    Shared by :func:`evaluate_tool_call_wasm` (production) and the CLI's
    ``hexgate policy test --engine wasm`` so both render WASM decisions
    identically. Kept argument-typed as ``Any`` to avoid importing the
    wasm engine eagerly — it only needs the ``allow`` /
    ``requires_approval`` / ``violations`` attributes.
    """
    if rego.allow:
        return Verdict(outcome=DecisionOutcome.ALLOW)
    if rego.requires_approval:
        return Verdict(
            outcome=DecisionOutcome.NEEDS_APPROVAL,
            reason=f'Policy requires approval for tool "{tool_name}"',
        )
    if rego.violations:
        reasons = "; ".join(rego.violations)
        return Verdict(
            outcome=DecisionOutcome.DENY,
            reason=f'Policy denied tool "{tool_name}": {reasons}',
            violations=tuple(rego.violations),
        )
    return Verdict(
        outcome=DecisionOutcome.DENY,
        reason=(
            f'Policy denied tool "{tool_name}" '
            f"(no allow rule matched for role={role!r})"
        ),
    )


def authorize_tool_call_wasm(
    bundle: PolicyBundle,
    role: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    *,
    attributes: Mapping[str, Any] | None = None,
    run: Mapping[str, Any] | None = None,
) -> None:
    """Raise-on-deny wrapper over :func:`evaluate_tool_call_wasm`.

    Raises the same exception shape as :func:`authorize_tool_call` so call
    sites don't care which engine produced the decision.
    """
    _raise_for_verdict(
        evaluate_tool_call_wasm(
            bundle, role, tool_name, arguments, attributes=attributes, run=run
        )
    )
