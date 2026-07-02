"""LangChain-facing wrapper for :class:`~hexgate.mcp.MCPToolset`.

Every :class:`~hexgate.mcp.MCPToolProxy` produced by the toolset becomes
a :class:`~langchain_core.tools.StructuredTool` that forwards to the
proxy's ``call``. Once wrapped, the resulting :class:`BaseTool` objects
are indistinguishable from native ``@agent_tool`` functions to the rest
of the LangChain path — hand them to :func:`create_agent`, call
:func:`enforce_policy`, and the existing :class:`GuardedTool` pass
gates every invocation through :class:`PolicyEnforcer`.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from hexgate.mcp.proxy import MCPToolProxy, MCPToolset


def _wrap_one(proxy: MCPToolProxy) -> BaseTool:
    """Build a single :class:`StructuredTool` around ``proxy.call``.

    LangChain's ``StructuredTool.from_function(args_schema=<dict>)``
    accepts a raw JSON Schema directly — no Pydantic model generation
    needed. The wrapping ``async def`` is a thin passthrough so
    LangChain's introspection sees a coroutine with the right name.
    """
    schema = proxy.input_schema
    call = proxy.call

    async def coroutine(**kwargs: Any) -> dict[str, Any]:
        return await call(**kwargs)

    coroutine.__name__ = proxy.qualified_name
    return StructuredTool.from_function(
        coroutine=coroutine,
        name=proxy.qualified_name,
        description=proxy.description,
        args_schema=schema,
    )


def wrap_mcp_toolset(toolset: MCPToolset) -> list[BaseTool]:
    """Wrap every proxy in ``toolset`` as a LangChain :class:`BaseTool`.

    Called implicitly by :meth:`MCPToolset.tools` for back-compat, or
    explicitly by adapter-aware callers that want the same
    ``wrap_mcp_toolset(mcp)`` shape they'd use with the OpenAI /
    Pydantic AI / Google ADK adapters. The returned tools share the
    toolset's connection lifecycle — they stop working (returning a
    ``use_after_close`` envelope) once the ``async with MCPToolset(...)``
    block exits.
    """
    return [_wrap_one(p) for p in toolset.proxies]
