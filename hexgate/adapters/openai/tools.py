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

from hexgate.agents.approvals import resolve_approval_async
from hexgate.approvals import ApprovalHandler
from hexgate.security.decision import DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer


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
) -> FunctionTool:
    """Return a copy of ``tool`` with ``on_invoke_tool`` gated by ``enforcer``."""
    if not isinstance(tool, FunctionTool):
        raise TypeError(
            f"Cannot install policy on tool {getattr(tool, 'name', tool)!r}: "
            f"expected agents.FunctionTool, got {type(tool).__name__}. "
        )

    name = tool.name
    original_invoke = tool.on_invoke_tool

    @functools.wraps(original_invoke, updated=())
    async def guarded_invoke(ctx: ToolContext[Any], input: str) -> Any:
        decision = enforcer.decide(name, _parse_args(input) or {})
        if decision.allowed:
            return await original_invoke(ctx, input)
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and approval_handler is not None
            and await resolve_approval_async(approval_handler, decision)
        ):
            return await original_invoke(ctx, input)
        return decision.as_error_message()

    wrapped = copy.copy(tool)
    wrapped.on_invoke_tool = guarded_invoke
    return wrapped


def wrap_tools(
    tools: list[FunctionTool],
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> list[FunctionTool]:
    """Return a fresh list of policy-gated copies."""
    return [wrap_tool(t, enforcer, approval_handler=approval_handler) for t in tools]


__all__ = ["_parse_args", "wrap_tool", "wrap_tools"]
