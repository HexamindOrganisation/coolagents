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

from hexgate.approvals import ApprovalHandler
from hexgate.hooks.runner import run_guarded_async, run_guarded_sync
from hexgate.hooks.types import ToolPipeline
from hexgate.security.decision import Decision
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.tools.decorators import TOOL_METADATA_ATTR


def _copy_tool_metadata(source: Any, target: Any) -> Any:
    """Copy hexgate tool metadata (tracing labels, etc.) onto a wrapper."""
    metadata = getattr(source, TOOL_METADATA_ATTR, None)
    if metadata is not None:
        setattr(target, TOOL_METADATA_ATTR, metadata)
    return target


def _langchain_error(decision: Decision) -> dict[str, Any]:
    """Render a blocked decision as the LangChain tool-result error dict.

    The shared runner shapes every non-allow (policy deny, approval-required,
    or a hook ``Halt``) into a :class:`Decision` and hands it here, so the LLM
    sees governance failures as ``{"ok": False, ...}`` tool output.
    """
    return {"ok": False, "error": decision.as_error_payload()}


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
    pipeline: ToolPipeline | None = None

    @classmethod
    def wrap(
        cls,
        tool: BaseTool,
        *,
        enforcer: PolicyEnforcer | None = None,
        approval_handler: ApprovalHandler | None = None,
        pipeline: ToolPipeline | None = None,
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
            resolved_pipeline = pipeline if pipeline is not None else tool.pipeline
        else:
            inner = tool
            resolved_enforcer = enforcer
            resolved_approval = approval_handler
            resolved_pipeline = pipeline

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
            pipeline=resolved_pipeline,
        )
        return _copy_tool_metadata(inner, guarded)

    def _guarded(self) -> bool:
        """True when this tool has anything to run: an enforcer or hooks."""
        return self.enforcer is not None or (
            self.pipeline is not None and not self.pipeline.is_empty
        )

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        if not self._guarded():
            return await self._invoke_wrapped_async(*args, **kwargs)
        return await run_guarded_async(
            self.name,
            kwargs,
            enforcer=self.enforcer,
            pipeline=self.pipeline,
            approval_handler=self.approval_handler,
            invoke=lambda final: self._invoke_wrapped_async(*args, **final),
            render_error=_langchain_error,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        if not self._guarded():
            return self._invoke_wrapped_sync(*args, **kwargs)
        return run_guarded_sync(
            self.name,
            kwargs,
            enforcer=self.enforcer,
            pipeline=self.pipeline,
            approval_handler=self.approval_handler,
            invoke=lambda final: self._invoke_wrapped_sync(*args, **final),
            render_error=_langchain_error,
        )

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
    pipeline: ToolPipeline | None = None,
) -> BaseTool:
    """Install :class:`PolicyEnforcer` gating on ``tool`` in place.

    Same semantics as :class:`GuardedTool` but mutates ``StructuredTool``'s
    ``func``/``coroutine`` instead of constructing a wrapper — use when
    the tool is already bound to a ``CompiledStateGraph``. Idempotent:
    re-install restores captured originals first so gates don't stack.
    Non-allow outcomes render as the structured error dict; approval
    flows belong on the host side, not on this in-place installer, so the
    runner runs with ``approval_handler=None``.
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
            return run_guarded_sync(
                name,
                kwargs,
                enforcer=enforcer,
                pipeline=pipeline,
                approval_handler=None,
                invoke=lambda final: captured_func(*args, **final),
                render_error=_langchain_error,
            )

        setattr(tool, _ORIGINAL_FUNC_ATTR, captured_func)
        tool.func = guarded_func

    if original_coroutine is not None:
        captured_coroutine = original_coroutine

        @functools.wraps(captured_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            return await run_guarded_async(
                name,
                kwargs,
                enforcer=enforcer,
                pipeline=pipeline,
                approval_handler=None,
                invoke=lambda final: captured_coroutine(*args, **final),
                render_error=_langchain_error,
            )

        setattr(tool, _ORIGINAL_COROUTINE_ATTR, captured_coroutine)
        tool.coroutine = guarded_coroutine

    tool.handle_tool_error = True
    setattr(tool, _INSTALLED_ATTR, True)
    return tool


def install_enforcer_on_tools(
    tools: list[BaseTool],
    *,
    enforcer: PolicyEnforcer,
    pipeline: ToolPipeline | None = None,
) -> list[BaseTool]:
    """Install enforcement on every StructuredTool-style tool in place."""
    for t in tools:
        install_enforcer_on_tool(t, enforcer=enforcer, pipeline=pipeline)
    return tools
