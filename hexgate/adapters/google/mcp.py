"""Google ADK adapter for :class:`~hexgate.mcp.MCPToolset`.

Every :class:`~hexgate.mcp.MCPToolProxy` produced by the toolset becomes
a :class:`google.adk.tools.BaseTool` subclass whose ``_get_declaration``
returns a ``FunctionDeclaration`` carrying the MCP tool's raw
JSON Schema (via ``parametersJsonSchema``) and whose ``run_async``
forwards to the proxy's ``call``. Once wrapped, the resulting tools
are indistinguishable from ADK-native :class:`FunctionTool` instances
to the rest of the Google ADK path — attach them to an ``Agent``, then
wrap via :func:`~hexgate.adapters.google.wrap_google_agent` so the
existing per-tool policy gate covers MCP invocations too.

Usage::

    from google.adk.agents import Agent
    from hexgate.adapters.google import wrap_google_agent
    from hexgate.adapters.google.mcp import wrap_mcp_toolset
    from hexgate.mcp import MCPServerConfig, MCPToolset

    slack = MCPServerConfig(name="slack", transport="stdio", command="slack-mcp")
    async with MCPToolset(slack) as mcp:
        agent = Agent(
            name="bot",
            tools=[*wrap_mcp_toolset(mcp), *native],
        )
        wrapped, binding = wrap_google_agent(agent, api_key=api_key)
"""

from __future__ import annotations

from typing import Any

from google.adk.tools import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types as genai_types

from hexgate.mcp.proxy import MCPToolProxy, MCPToolset


class _MCPProxyTool(BaseTool):
    """One :class:`BaseTool` that forwards to an :class:`MCPToolProxy`.

    ADK's :class:`FunctionTool` derives its schema from a Python
    callable's signature via reflection, which can't express the shapes
    MCP servers advertise (partial ``required``, ``anyOf`` unions,
    nested objects with dynamic keys). Subclassing :class:`BaseTool`
    and returning a hand-built :class:`FunctionDeclaration` from
    ``_get_declaration`` bypasses the reflection path and hands the
    server's raw JSON Schema straight to the model — via ADK's
    ``parametersJsonSchema`` alias which accepts JSON Schema dicts.
    """

    def __init__(self, proxy: MCPToolProxy) -> None:
        super().__init__(name=proxy.qualified_name, description=proxy.description)
        # Store the schema + call as private attrs — ADK's BaseTool has
        # no field for them, so we ride on the object dict.
        self._input_schema = proxy.input_schema
        self._call = proxy.call

    def _get_declaration(self) -> genai_types.FunctionDeclaration:
        return genai_types.FunctionDeclaration(
            name=self.name,
            description=self.description,
            parametersJsonSchema=self._input_schema,
        )

    async def run_async(
        self, *, args: dict[str, Any], tool_context: ToolContext
    ) -> Any:
        return await self._call(**(args or {}))


def wrap_mcp_toolset(toolset: MCPToolset) -> list[BaseTool]:
    """Wrap every proxy in ``toolset`` as a Google ADK :class:`BaseTool`.

    The returned tools share the toolset's connection lifecycle — they
    stop working (returning a ``use_after_close`` envelope) once the
    ``async with MCPToolset(...)`` block exits. Combine with
    :func:`~hexgate.adapters.google.wrap_google_agent` to gate every
    invocation through :class:`~hexgate.security.PolicyEnforcer`.
    """
    return [_MCPProxyTool(p) for p in toolset.proxies]
