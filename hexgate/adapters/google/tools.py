"""Google ADK adapter: wrap ``BaseTool`` so ``run_async`` consults a
:class:`PolicyEnforcer` first. Non-allow outcomes render as markered
strings the model sees as tool output.

When a caller supplies ``approval_handler``, a ``NEEDS_APPROVAL``
decision fires the callback and runs the original tool on truthy return;
falsy return (or a missing handler) keeps today's behavior of surfacing
the ``[approval_required]`` marker to the model.
"""

from __future__ import annotations

import copy
import functools
from collections.abc import Callable
from inspect import isawaitable
from typing import Any, Union

from google.adk.tools.base_tool import BaseTool
from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.tool_context import ToolContext

from hexgate.agents.factory import ApprovalHandler
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer


ToolEntry = Union[BaseTool, Callable[..., Any]]


async def _resolve_approval(handler: ApprovalHandler, decision: Decision) -> bool:
    """Resolve a NEEDS_APPROVAL decision. ``bool`` handlers short-circuit."""
    if isinstance(handler, bool):
        return handler
    result: Any = handler(decision)
    if isawaitable(result):
        result = await result  # type: ignore[assignment]
    return bool(result)


def _normalize(tool: ToolEntry) -> BaseTool:
    """Coerce a tool entry into a ``BaseTool`` (plain callables → FunctionTool)."""
    if isinstance(tool, BaseTool):
        return tool
    if callable(tool):
        return FunctionTool(func=tool)
    raise TypeError(
        f"Cannot install policy on tool {tool!r}: expected google.adk BaseTool "
        f"or callable, got {type(tool).__name__}."
    )


def wrap_tool(
    tool: ToolEntry,
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> BaseTool:
    """Return a copy of ``tool`` with ``run_async`` gated by ``enforcer``."""
    base = _normalize(tool)
    name = base.name
    original_run_async = base.run_async

    @functools.wraps(original_run_async, updated=())
    async def guarded_run_async(
        *, args: dict[str, Any], tool_context: ToolContext
    ) -> Any:
        decision = enforcer.decide(name, args or {})
        if decision.allowed:
            return await original_run_async(args=args, tool_context=tool_context)
        if (
            decision.outcome is DecisionOutcome.NEEDS_APPROVAL
            and approval_handler is not None
            and await _resolve_approval(approval_handler, decision)
        ):
            return await original_run_async(args=args, tool_context=tool_context)
        return decision.as_error_message()

    wrapped = copy.copy(base)
    wrapped.run_async = guarded_run_async
    return wrapped


def wrap_tools(
    tools: list[ToolEntry],
    enforcer: PolicyEnforcer,
    *,
    approval_handler: ApprovalHandler | None = None,
) -> list[BaseTool]:
    """Return a fresh list of policy-gated copies."""
    return [wrap_tool(t, enforcer, approval_handler=approval_handler) for t in tools]
