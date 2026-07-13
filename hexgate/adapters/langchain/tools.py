"""LangChain adapter for :class:`PolicyEnforcer`.

:class:`GuardedTool` wraps a ``BaseTool`` (used by
:meth:`HexgateAgent.enforce_policy`, which rebuilds the graph) and
carries an optional ``approval_handler`` for inline ``NEEDS_APPROVAL``
resolution.
:func:`install_enforcer_on_tool` mutates ``StructuredTool``'s ``func``/
``coroutine`` in place (used by :func:`wrap_langchain_agent` for
pre-built ``CompiledStateGraph``s) and always renders non-allow as a
structured error — approval flows wire in on the host side.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.tools import BaseTool
from langchain_core.tools.structured import StructuredTool
from pydantic import ConfigDict

from hexgate.agents.approvals import (
    resolve_approval_async as _resolve_approval_async,
)
from hexgate.agents.approvals import (
    resolve_approval_sync as _resolve_approval_sync,
)
from hexgate.approvals import ApprovalHandler
from hexgate.security.decision import DecisionOutcome
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.tools.decorators import TOOL_METADATA_ATTR


def _copy_tool_metadata(source: Any, target: Any) -> Any:
    """Copy hexgate tool metadata (tracing labels, etc.) onto a wrapper."""
    metadata = getattr(source, TOOL_METADATA_ATTR, None)
    if metadata is not None:
        setattr(target, TOOL_METADATA_ATTR, metadata)
    return target


class GuardedTool(BaseTool):
    """LangChain tool wrapper that consults a :class:`PolicyEnforcer`.

    ALLOW delegates to the wrapped tool; non-ALLOW renders
    ``Decision.as_error_payload()`` so the LLM sees governance failures
    as tool output. NEEDS_APPROVAL is treated as denial unless
    ``approval_handler`` (callable taking the :class:`Decision`, or a
    ``bool`` shorthand) returns truthy.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    wrapped_tool: BaseTool
    enforcer: PolicyEnforcer | None = None
    approval_handler: ApprovalHandler | None = None

    @classmethod
    def wrap(
        cls,
        tool: BaseTool,
        *,
        enforcer: PolicyEnforcer | None = None,
        approval_handler: ApprovalHandler | None = None,
    ) -> "GuardedTool":
        """Return a GuardedTool delegating to ``tool`` after policy check.

        Idempotent re-wrap: an existing ``GuardedTool`` is unwrapped once
        so enforcers don't stack; fields fall through unless explicitly
        overridden.
        """
        if isinstance(tool, cls):
            inner = tool.wrapped_tool
            resolved_enforcer = enforcer if enforcer is not None else tool.enforcer
            resolved_approval = (
                approval_handler
                if approval_handler is not None
                else tool.approval_handler
            )
        else:
            inner = tool
            resolved_enforcer = enforcer
            resolved_approval = approval_handler

        guarded = cls(
            name=inner.name,
            description=inner.description,
            args_schema=inner.args_schema,
            return_direct=inner.return_direct,
            verbose=inner.verbose,
            callbacks=inner.callbacks,
            tags=inner.tags,
            metadata=inner.metadata,
            handle_tool_error=inner.handle_tool_error,
            handle_validation_error=inner.handle_validation_error,
            response_format=inner.response_format,
            extras=inner.extras,
            wrapped_tool=inner,
            enforcer=resolved_enforcer,
            approval_handler=resolved_approval,
        )
        return _copy_tool_metadata(inner, guarded)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        if self.enforcer is not None:
            decision = self.enforcer.decide(self.name, kwargs)
            if not decision.allowed:
                if (
                    decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                    and self.approval_handler is not None
                    and await _resolve_approval_async(self.approval_handler, decision)
                ):
                    pass  # approved → fall through and invoke
                else:
                    return {"ok": False, "error": decision.as_error_payload()}
        return await self._invoke_wrapped_async(*args, **kwargs)

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        if self.enforcer is not None:
            decision = self.enforcer.decide(self.name, kwargs)
            if not decision.allowed:
                if (
                    decision.outcome is DecisionOutcome.NEEDS_APPROVAL
                    and self.approval_handler is not None
                    and _resolve_approval_sync(self.approval_handler, decision)
                ):
                    pass
                else:
                    return {"ok": False, "error": decision.as_error_payload()}
        return self._invoke_wrapped_sync(*args, **kwargs)

    async def _invoke_wrapped_async(self, *args: Any, **kwargs: Any) -> Any:
        """Call the wrapped tool without re-entering LangChain instrumentation."""
        if isinstance(self.wrapped_tool, StructuredTool):
            if self.wrapped_tool.coroutine is not None:
                return await self.wrapped_tool.coroutine(*args, **kwargs)
            if self.wrapped_tool.func is not None:
                return self.wrapped_tool.func(*args, **kwargs)
        return await self.wrapped_tool._arun(*args, **kwargs)

    def _invoke_wrapped_sync(self, *args: Any, **kwargs: Any) -> Any:
        if (
            isinstance(self.wrapped_tool, StructuredTool)
            and self.wrapped_tool.func is not None
        ):
            return self.wrapped_tool.func(*args, **kwargs)
        return self.wrapped_tool._run(*args, **kwargs)


# ---------------------------------------------------------------------------
# In-place installer for retrofitting existing CompiledStateGraph tools.
# ---------------------------------------------------------------------------

_ORIGINAL_FUNC_ATTR = "_hexgate_original_func"
_ORIGINAL_COROUTINE_ATTR = "_hexgate_original_coroutine"
_INSTALLED_ATTR = "_hexgate_enforcer_installed"


def install_enforcer_on_tool(
    tool: BaseTool,
    *,
    enforcer: PolicyEnforcer,
) -> BaseTool:
    """Install :class:`PolicyEnforcer` gating on ``tool`` in place.

    Same semantics as :class:`GuardedTool` but mutates ``StructuredTool``'s
    ``func``/``coroutine`` instead of constructing a wrapper — use when
    the tool is already bound to a ``CompiledStateGraph``. Idempotent:
    re-install restores captured originals first so gates don't stack.
    Non-allow outcomes render as the structured error dict; approval
    flows belong on the host side, not on this in-place installer.
    """
    name = tool.name
    original_func: Callable[..., Any] | None = getattr(tool, _ORIGINAL_FUNC_ATTR, None)
    if original_func is None:
        original_func = getattr(tool, "func", None)
    original_coroutine: Callable[..., Awaitable[Any]] | None = getattr(
        tool, _ORIGINAL_COROUTINE_ATTR, None
    )
    if original_coroutine is None:
        original_coroutine = getattr(tool, "coroutine", None)

    if original_func is None and original_coroutine is None:
        raise TypeError(
            f"Cannot install policy on tool {name!r}: it is a "
            f"{type(tool).__name__} without `func`/`coroutine` attributes. "
            "In-place wrapping only supports StructuredTool-style tools."
        )

    if original_func is not None:
        captured_func = original_func

        @functools.wraps(captured_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            decision = enforcer.decide(name, kwargs)
            if decision.allowed:
                return captured_func(*args, **kwargs)
            return {"ok": False, "error": decision.as_error_payload()}

        setattr(tool, _ORIGINAL_FUNC_ATTR, captured_func)
        tool.func = guarded_func

    if original_coroutine is not None:
        captured_coroutine = original_coroutine

        @functools.wraps(captured_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            decision = enforcer.decide(name, kwargs)
            if decision.allowed:
                return await captured_coroutine(*args, **kwargs)
            return {"ok": False, "error": decision.as_error_payload()}

        setattr(tool, _ORIGINAL_COROUTINE_ATTR, captured_coroutine)
        tool.coroutine = guarded_coroutine

    tool.handle_tool_error = True
    setattr(tool, _INSTALLED_ATTR, True)
    return tool


def install_enforcer_on_tools(
    tools: list[BaseTool],
    *,
    enforcer: PolicyEnforcer,
) -> list[BaseTool]:
    """Install enforcement on every StructuredTool-style tool in place."""
    for t in tools:
        install_enforcer_on_tool(t, enforcer=enforcer)
    return tools
