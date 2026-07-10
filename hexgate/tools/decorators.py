"""Decorator helpers for agent tools."""

from __future__ import annotations

from collections.abc import Callable
import inspect
from typing import Any, Literal

import httpx

from hexgate.runtime import get_current_tool_use_context
from hexgate.tracing.langfuse_core import observe
from hexgate.utils.retry import async_retry, is_retryable_error

TOOL_METADATA_ATTR = "__tool_metadata__"
CallFormatter = Callable[[dict[str, Any]], str]
FailureMode = Literal["raise", "result"]
TOOL_USE_CONTEXT_PARAM = "tool_use_context"


def _default_call_label(tool_name: str, arguments: dict[str, Any]) -> str:
    """Return the default human-readable label for a tool call."""
    _ = arguments
    return tool_name


def format_tool_call_label(tool: Any, arguments: dict[str, Any] | None = None) -> str:
    """Return a human-readable label for a tool call."""
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", None) or "tool"
    metadata = getattr(tool, TOOL_METADATA_ATTR, {})
    formatter = metadata.get("call_formatter")
    payload = arguments or {}

    if callable(formatter):
        try:
            label = formatter(payload)
        except Exception:
            label = ""
        if isinstance(label, str) and label.strip():
            return label

    return _default_call_label(str(tool_name), payload)


def _humanize_tool_error(error: BaseException) -> dict[str, Any]:
    """Return a compact structured payload for a tool execution error."""
    if isinstance(error, httpx.HTTPStatusError):
        status_code = error.response.status_code
        return {
            "type": "http_status_error",
            "message": f"Request rejected by provider ({status_code}).",
            "status_code": status_code,
            "retryable": is_retryable_error(error),
        }
    if isinstance(error, httpx.TimeoutException):
        return {
            "type": "timeout_error",
            "message": "Request timed out.",
            "status_code": None,
            "retryable": True,
        }
    if isinstance(error, httpx.ConnectError):
        return {
            "type": "connect_error",
            "message": "Connection failed.",
            "status_code": None,
            "retryable": True,
        }
    return {
        "type": error.__class__.__name__,
        "message": str(error) or "Tool execution failed.",
        "status_code": None,
        "retryable": is_retryable_error(error),
    }


def _exposed_signature(func: Callable[..., Any]) -> inspect.Signature:
    """Return the model-visible signature with hidden meta-args removed."""
    signature = inspect.signature(func)
    parameters = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.name != TOOL_USE_CONTEXT_PARAM
    ]
    return signature.replace(parameters=parameters)


def _exposed_annotations(func: Callable[..., Any]) -> dict[str, Any]:
    """Return model-visible annotations with hidden meta-args removed."""
    annotations = dict(getattr(func, "__annotations__", {}))
    annotations.pop(TOOL_USE_CONTEXT_PARAM, None)
    return annotations


def agent_tool(
    *,
    name: str,
    retries: int = 3,
    delay_ms: int = 1000,
    exceptions: tuple[type[BaseException], ...] = (httpx.HTTPError,),
    call_formatter: CallFormatter | None = None,
    failure_mode: FailureMode = "raise",
) -> Callable[[Callable[..., Any]], Any]:
    """Compose tracing, retry, and tool registration for agent tools."""

    def decorator(func: Callable[..., Any]) -> Any:
        """Wrap a function with the standard tool stack."""
        exposed_signature = _exposed_signature(func)
        accepts_tool_use_context = (
            TOOL_USE_CONTEXT_PARAM in inspect.signature(func).parameters
        )

        retried = async_retry(
            retries=retries,
            delay_ms=delay_ms,
            exceptions=exceptions,
        )(func)

        @observe(name=name)
        async def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
            """Run a tool with configured retry and failure behavior."""
            call_kwargs = dict(kwargs)
            if accepts_tool_use_context:
                tool_use_context = get_current_tool_use_context()
                if tool_use_context is None:
                    raise RuntimeError(
                        "tool_use_context is not available outside an active agent run"
                    )
                call_kwargs[TOOL_USE_CONTEXT_PARAM] = tool_use_context
            try:
                result = await retried(*args, **call_kwargs)
            except Exception as error:
                if failure_mode == "raise":
                    raise
                return {"ok": False, "error": _humanize_tool_error(error)}

            if isinstance(result, dict):
                return {"ok": True, **result}
            return {"ok": True, "content": result}

        wrapped.__name__ = func.__name__
        wrapped.__qualname__ = getattr(func, "__qualname__", func.__name__)
        wrapped.__doc__ = func.__doc__
        wrapped.__annotations__ = _exposed_annotations(func)
        wrapped.__signature__ = exposed_signature
        # Lazy LC import: the @agent_tool decorator produces a
        # ``langchain_core.tools.BaseTool``, but we don't want the
        # import at module load time — that would drag LC into every
        # adapter-only user's install just by having decorators.py on
        # the import graph. Paid once at decoration time (which only
        # happens when the caller actually uses the decorator).
        from langchain_core.tools import tool as _lc_tool

        registered_tool = _lc_tool(wrapped)
        setattr(
            registered_tool,
            TOOL_METADATA_ATTR,
            {
                "call_formatter": call_formatter,
                "failure_mode": failure_mode,
            },
        )
        return registered_tool

    return decorator
