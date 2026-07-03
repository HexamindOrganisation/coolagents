"""Pydantic AI adapter for :class:`~hexgate.mcp.MCPToolset`.

Every :class:`~hexgate.mcp.MCPToolProxy` produced by the toolset becomes
a :class:`pydantic_ai.tools.Tool` via ``Tool.from_schema`` — Pydantic
AI's raw-JSON-Schema entry point. Once wrapped, the resulting Tools
are indistinguishable from ``@agent.tool``-decorated callables to the
rest of the Pydantic AI path — attach them to an ``Agent`` and wrap
via :func:`~hexgate.adapters.pydantic_ai.wrap_pydantic_agent` so the
existing per-tool policy gate covers MCP invocations too.

Usage::

    from pydantic_ai import Agent
    from hexgate.adapters.pydantic_ai import wrap_pydantic_agent
    from hexgate.adapters.pydantic_ai.mcp import wrap_mcp_toolset
    from hexgate.mcp import MCPServerConfig, MCPToolset

    slack = MCPServerConfig(name="slack", transport="stdio", command="slack-mcp")
    async with MCPToolset(slack) as mcp:
        agent = Agent("openai:gpt-5.4", tools=[*wrap_mcp_toolset(mcp), *native])
        proxy = wrap_pydantic_agent(agent=agent)
        await proxy.run("…", user=user)
"""

from __future__ import annotations

from pydantic_ai.tools import Tool

from hexgate.mcp.proxy import MCPToolProxy, MCPToolset


def _wrap_one(proxy: MCPToolProxy) -> Tool:
    """Build a single :class:`Tool` around ``proxy.call``.

    Pydantic AI's ``Tool.from_schema`` accepts a raw JSON Schema — no
    dynamic Pydantic model generation is needed. ``proxy.call`` is
    passed verbatim as the function; its ``__name__`` is already the
    qualified name (set by :func:`hexgate.mcp.proxy._build_proxy`).
    Pydantic AI's own validator (built from the same schema) is the
    outer gate; our ``proxy.call`` runs its own JSON-Schema check as a
    defence-in-depth layer before the server round-trip.
    """
    return Tool.from_schema(
        function=proxy.call,
        name=proxy.qualified_name,
        description=proxy.description,
        json_schema=proxy.input_schema,
    )


def wrap_mcp_toolset(toolset: MCPToolset) -> list[Tool]:
    """Wrap every proxy in ``toolset`` as a Pydantic AI :class:`Tool`.

    The returned tools share the toolset's connection lifecycle — they
    stop working (returning a ``use_after_close`` envelope) once the
    ``async with MCPToolset(...)`` block exits. Combine with
    :func:`~hexgate.adapters.pydantic_ai.wrap_pydantic_agent` to gate
    every invocation through :class:`~hexgate.security.PolicyEnforcer`.
    """
    return [_wrap_one(p) for p in toolset.proxies]
