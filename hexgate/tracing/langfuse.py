"""LangChain-tied Langfuse integration.

The framework-agnostic bits (``get_client``, ``propagate_attributes``,
``observe``, ``maybe_get_trace_url``, the ``LangfuseHandler`` Protocol)
live in :mod:`hexgate.tracing.langfuse_core` and are re-exported here so
pre-refactor imports of the form ``from hexgate.tracing.langfuse import
observe`` keep working. Code that DOESN'T need the LangChain callback
handler should import from ``_core`` directly to skip the
``langfuse.langchain`` + ``langchain_core.runnables`` load.
"""

from __future__ import annotations

from inspect import signature

from langchain_core.runnables import RunnableConfig
from langfuse.langchain import CallbackHandler

# Re-exports for back-compat with pre-split callers.
from hexgate.tracing.langfuse_core import (  # noqa: F401 — re-export
    LangfuseHandler,
    get_client,
    maybe_get_trace_url,
    observe,
    propagate_attributes,
)


def get_langfuse_handler(
    *,
    session_id: str | None = None,
    user_id: str | None = None,
    tags: list[str] | None = None,
) -> CallbackHandler:
    """Create a Langfuse LangChain callback handler."""
    init_params = signature(CallbackHandler.__init__).parameters
    default_tags = tags or ["hexgate"]

    if "session_id" in init_params:
        return CallbackHandler(
            session_id=session_id,
            user_id=user_id,
            tags=default_tags,
        )

    handler = CallbackHandler()
    handler.langfuse_metadata = {
        "langfuse_session_id": session_id,
        "langfuse_user_id": user_id,
        "langfuse_tags": default_tags,
    }
    return handler


def get_langfuse_runnable_config(handler: CallbackHandler) -> RunnableConfig:
    """Build LangChain runnable config for the current Langfuse SDK."""
    config: RunnableConfig = {"callbacks": [handler]}
    metadata = getattr(handler, "langfuse_metadata", None)
    if metadata:
        config["metadata"] = {k: v for k, v in metadata.items() if v is not None}

    return config
