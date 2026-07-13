"""pydantic_ai adapter: wrap ``Tool.function_schema.call`` so it consults
a :class:`PolicyEnforcer` first. Non-allow outcomes raise
:class:`ModelRetry` with a rendered :class:`Decision` message (pydantic_ai's
idiom for feeding a tool failure back to the model).

When a caller supplies ``approval_handler``, a ``NEEDS_APPROVAL``
decision fires the callback and runs the original tool on truthy return;
falsy return (or a missing handler) keeps today's behavior of raising
``ModelRetry`` with the ``[approval_required]`` marker.
"""

from __future__ import annotations

import copy
import functools
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry
from pydantic_ai.tools import Tool

from hexgate.agents.approvals import resolve_approval_async
from hexgate.approvals import ApprovalHandler
from hexgate.security.decision import DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer


def wrap_tool(
    tool: Tool,
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> Tool:
    """Return a copy of ``tool`` with ``function_schema.call`` gated by ``enforcer``."""
    name = tool.name
    tool_copy = copy.copy(tool)
    tool_copy.function_schema = copy.copy(tool.function_schema)
    original_call = tool_copy.function_schema.call

    @functools.wraps(original_call)
    async def guarded_call(args_dict: dict[str, Any], context: RunContext[Any]) -> Any:
        decision = enforcer.decide(name, args_dict or {})
        if decision.allowed:
            return await original_call(args_dict, context)
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and approval_handler is not None
            and await resolve_approval_async(approval_handler, decision)
        ):
            return await original_call(args_dict, context)
        raise ModelRetry(decision.as_error_message())

    tool_copy.function_schema.call = guarded_call
    return tool_copy


def wrap_tools(
    tools: list[Tool],
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> list[Tool]:
    """Return a fresh list of policy-gated copies."""
    return [wrap_tool(t, enforcer, approval_handler=approval_handler) for t in tools]
