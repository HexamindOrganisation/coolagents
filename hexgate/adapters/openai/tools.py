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
from hexgate.hooks.runner import run_guarded_async
from hexgate.hooks.types import ToolPipeline
from hexgate.security.enforcer import PolicyEnforcer


def _render_error(decision: Any) -> str:
    """OpenAI renders a blocked decision as a string tool result."""
    return decision.as_error_message()


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

    @functools.wraps(original_invoke, updated=())
    async def guarded_invoke(ctx: ToolContext[Any], input: str) -> Any:
        parsed = _parse_args(input) or {}

        def invoke(final: dict[str, Any]) -> Any:
            # Keep the original raw ``input`` when no before-guard rewrote the
            # args (this preserves a non-dict payload the parse dropped);
            # re-serialize only when a rewrite actually changed them.
            if final == parsed:
                payload = input
            else:
                try:
                    payload = json.dumps(final)
                except (TypeError, ValueError) as exc:
                    # A guard rewrote args to a non-JSON value. This adapter
                    # alone re-serializes, so without this the failure would
                    # surface as an opaque json TypeError that reads like a
                    # tool crash. Name the real cause instead.
                    raise TypeError(
                        f"a before-guard rewrote {name!r} arguments to a value "
                        f"that is not JSON-serializable ({exc}); tool arguments "
                        "must stay JSON (the OpenAI tool receives them as a JSON "
                        "string)."
                    ) from exc
            return original_invoke(ctx, payload)

        return await run_guarded_async(
            name,
            parsed,
            enforcer=enforcer,
            pipeline=pipeline,
            approval_handler=approval_handler,
            invoke=invoke,
            render_error=_render_error,
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
