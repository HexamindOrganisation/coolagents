"""OpenAI Agents adapter: wrap ``FunctionTool`` so ``on_invoke_tool``
consults a :class:`PolicyEnforcer` first. Non-allow outcomes render as
markered strings the model sees as tool output.

When a caller supplies ``approval_handler``, a ``NEEDS_APPROVAL``
decision fires the callback and runs the original tool on truthy return;
falsy return (or a missing handler) keeps today's behavior of surfacing
the ``[approval_required]`` marker to the model.
"""

from __future__ import annotations

import copy
import functools
import json
from typing import Any

from agents import FunctionTool
from agents.tool import ToolContext

from hexgate.approvals import ApprovalHandler
from hexgate.guards.runner import run_guarded_async
from hexgate.guards.types import ToolPipeline
from hexgate.security.decision import DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.models import agent_target_key
from hexgate.security.naming import canonical_name

try:
    # The Agents SDK tags an ``Agent.as_tool()`` tool with its origin (the target
    # agent's name), which lets us gate the reach edge under ``agent.tool:<target>``.
    from agents.tool import ToolOriginType, get_function_tool_origin

    _CAN_DETECT_AGENT_TOOLS = True
except ImportError:  # older SDK without tool-origin metadata
    _CAN_DETECT_AGENT_TOOLS = False


def _agent_tool_target(tool: FunctionTool) -> str | None:
    """Canonical target-agent name if ``tool`` is an ``Agent.as_tool()``, else ``None``.

    Reads the SDK's public tool-origin metadata so an agent reached *as a tool*
    can be gated under its reach key rather than its plain tool name. Returns
    ``None`` for an ordinary function tool, or on an SDK too old to expose the
    origin (capability fallback — the caller keeps name-gating)."""
    if not _CAN_DETECT_AGENT_TOOLS:
        return None
    origin = get_function_tool_origin(tool)
    if (
        origin is not None
        and origin.type is ToolOriginType.AGENT_AS_TOOL
        and origin.agent_name
    ):
        return canonical_name(origin.agent_name)
    return None


def _render_error(decision: Any) -> str:
    """OpenAI renders a blocked decision as a string tool result."""
    return decision.as_error_message()


def _render_reach_error(target: str):
    """Model-facing renderer for a denied/held agent-as-tool reach.

    Keeps :meth:`Decision.as_error_message`'s ``[marker] …`` shape so adapters and
    the dashboard still key off the ``policy_denied`` / ``approval_required``
    marker, but names the bare target agent instead of the lowered
    ``agent.tool:<target>`` key — the same no-leak stance as
    :class:`~hexgate.security.agent_gate.ReachNotAllowedError`."""

    def render(decision: Any) -> str:
        marker = decision.error_type or decision.outcome.value
        if decision.outcome is DecisionOutcome.NEEDS_APPROVAL:
            body = f"reach to agent {target!r} requires human approval before it runs"
        else:
            body = f"reach to agent {target!r} is not permitted by this agent's policy"
        return f"[{marker}] {body}. The sub-agent was not invoked."

    return render


def _parse_args(raw: str) -> dict[str, Any] | None:
    """Best-effort JSON-to-dict parse of a tool-call payload."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def wrap_tool(
    tool: FunctionTool,
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
    pipeline: ToolPipeline | None = None,
) -> FunctionTool:
    """Return a copy of ``tool`` with ``on_invoke_tool`` gated by ``enforcer``.

    Routes through the shared :func:`run_guarded_async`, so before/after
    guards run around the policy check exactly as on the other adapters.
    """
    if not isinstance(tool, FunctionTool):
        raise TypeError(
            f"Cannot install policy on tool {getattr(tool, 'name', tool)!r}: "
            f"expected agents.FunctionTool, got {type(tool).__name__}. "
        )

    name = tool.name
    original_invoke = tool.on_invoke_tool
    # An ``Agent.as_tool()`` is a reach edge, not an ordinary tool. When the
    # policy declares reach we gate it under its reach key ``agent.tool:<target>``
    # (closed-world, ``via``/constraints honored) rather than its tool name.
    # ``None`` for a normal tool, or an SDK too old to expose the origin.
    reach_target = _agent_tool_target(tool)
    # Without guards nothing can rewrite the args, so we forward the model's
    # payload byte-for-byte. Re-serializing would be a silent change on every
    # call (reformatted whitespace, collapsed duplicate keys, 1e400 -> Infinity,
    # escaped unicode), and until a caller adds guards every call is guard-free.
    has_guards = pipeline is not None and not pipeline.is_empty

    @functools.wraps(original_invoke, updated=())
    async def guarded_invoke(ctx: ToolContext[Any], input: str) -> Any:
        parsed = _parse_args(input)  # None when the payload is not a JSON object
        # Engagement is read here, per call, so a hot-reloaded policy that adds or
        # drops a via:tool target is honored on the next call. Gate under the reach
        # key only when the policy declares *tool* reach (an ``agent.tool:`` key) —
        # not merely any ``agents`` block: agent keys are closed-world, so engaging
        # on a handoff-only policy would deny every as-tool with no diagnostic. A
        # policy that declares no via:tool target keeps today's name-gating.
        if reach_target is not None and enforcer.policy.declares_tool_reach():
            # Decide on the reach key, but keep ``name`` as the call/guard identity
            # (policy_key), so a guard scoped to the tool's function name still fires.
            policy_key = agent_target_key("tool", reach_target)
            render_error = _render_reach_error(reach_target)
        else:
            policy_key = None
            render_error = _render_error

        def invoke(final: dict[str, Any]) -> Any:
            if not has_guards:
                return original_invoke(ctx, input)
            # A non-object payload (bare string, list, or unparseable) has no
            # dict form to forward, so keep the raw ``input`` — unless a guard
            # replaced the args outright (then ``final`` is non-empty).
            if parsed is None and not final:
                return original_invoke(ctx, input)
            # Guards ran: serialize the (possibly rewritten) args, so an
            # in-place nested rewrite reaches the tool the way it does on the
            # Google/Pydantic adapters, not only a Proceed(args=...) replace.
            try:
                payload = json.dumps(final)
            except (TypeError, ValueError) as exc:
                # Parsed args always round-trip, so a non-JSON value here is a
                # guard rewrite. This adapter alone re-serializes, so without
                # this the failure would surface as an opaque json TypeError
                # that reads like a tool crash; name the real cause. (It also
                # rides ToolOutcome.error, so a failure-halting after-guard
                # still sees it.)
                raise TypeError(
                    f"a before-guard rewrote {name!r} arguments to a value "
                    f"that is not JSON-serializable ({exc}); tool arguments "
                    "must stay JSON (the OpenAI tool receives them as a JSON "
                    "string)."
                ) from exc
            return original_invoke(ctx, payload)

        return await run_guarded_async(
            name,
            parsed or {},
            enforcer=enforcer,
            pipeline=pipeline,
            approval_handler=approval_handler,
            invoke=invoke,
            render_error=render_error,
            policy_key=policy_key,
        )

    wrapped = copy.copy(tool)
    wrapped.on_invoke_tool = guarded_invoke
    return wrapped


def wrap_tools(
    tools: list[FunctionTool],
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
    pipeline: ToolPipeline | None = None,
) -> list[FunctionTool]:
    """Return a fresh list of policy-gated copies."""
    return [
        wrap_tool(t, enforcer, approval_handler=approval_handler, pipeline=pipeline)
        for t in tools
    ]


__all__ = ["_parse_args", "wrap_tool", "wrap_tools"]
