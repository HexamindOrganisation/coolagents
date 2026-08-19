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

from hexgate.approvals import ApprovalHandler
from hexgate.guards.runner import run_guarded_async
from hexgate.guards.types import ToolPipeline
from hexgate.security.enforcer import PolicyEnforcer


def _raise_model_retry(decision: Any) -> Any:
    """pydantic_ai renders a blocked decision by raising ``ModelRetry``.

    The shared runner returns ``render_error``'s value; a closure that raises
    instead propagates the exception out of ``run_guarded_async``, which is the
    pydantic_ai idiom for feeding a tool failure back to the model.
    """
    raise ModelRetry(decision.as_error_message())


def wrap_tool(
    tool: Tool,
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
    pipeline: ToolPipeline | None = None,
) -> Tool:
    """Return a copy of ``tool`` with ``function_schema.call`` gated by ``enforcer``.

    Routes through the shared :func:`run_guarded_async`, so before/after
    guards run around the policy check exactly as on the other adapters.
    """
    name = tool.name
    tool_copy = copy.copy(tool)
    tool_copy.function_schema = copy.copy(tool.function_schema)
    original_call = tool_copy.function_schema.call

    @functools.wraps(original_call)
    async def guarded_call(args_dict: dict[str, Any], context: RunContext[Any]) -> Any:
        return await run_guarded_async(
            name,
            args_dict or {},
            enforcer=enforcer,
            pipeline=pipeline,
            approval_handler=approval_handler,
            invoke=lambda final: original_call(final, context),
            render_error=_raise_model_retry,
        )

    tool_copy.function_schema.call = guarded_call
    return tool_copy


def wrap_tools(
    tools: list[Tool],
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
    pipeline: ToolPipeline | None = None,
) -> list[Tool]:
    """Return a fresh list of policy-gated copies."""
    return [
        wrap_tool(t, enforcer, approval_handler=approval_handler, pipeline=pipeline)
        for t in tools
    ]
