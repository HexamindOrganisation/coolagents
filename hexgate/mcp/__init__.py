"""Wrap third-party MCP (Model Context Protocol) servers as guarded tools.

The public entry point is :class:`MCPToolset`, an async context manager
that connects to one or more MCP servers, enumerates their tool
catalogs, and exposes them as framework-agnostic
:class:`MCPToolProxy` descriptors. Each supported agent framework has
its own ``wrap_mcp_toolset(toolset)`` that turns proxies into
framework-native tool objects; from there the existing per-adapter
``enforce_policy`` pass gates every invocation through
:class:`PolicyEnforcer`, so MCP tools behave like native
``@agent_tool`` functions all the way through — including audit and
approval flows.

Adapters:

  * ``hexgate.adapters.langchain.mcp`` → LangChain ``BaseTool``
  * ``hexgate.adapters.openai.mcp`` → OpenAI Agents ``FunctionTool``
  * ``hexgate.adapters.pydantic_ai.mcp`` → Pydantic AI ``Tool``
  * ``hexgate.adapters.google.mcp`` → Google ADK ``BaseTool``

Tool naming is ``mcp-<server>-<tool>`` (hyphens, not colons — OpenAI's
function-calling spec rejects colons in tool names). The server name is
caller-supplied and validated to ``^[a-z0-9-]{1,32}$`` so qualified
names stay under OpenAI's 64-char tool-name limit.

Example (OpenAI Agents; substitute the adapter that matches your stack)::

    from agents import Agent
    from hexgate.adapters.openai import wrap_openai_agent
    from hexgate.adapters.openai.mcp import wrap_mcp_toolset
    from hexgate.mcp import MCPServerConfig, MCPToolset

    slack = MCPServerConfig(
        name="slack",
        transport="stdio",
        command="slack-mcp-server",
        env={"SLACK_TOKEN": "..."},
    )

    async with MCPToolset(slack) as mcp:
        agent = Agent(name="bot", tools=[*wrap_mcp_toolset(mcp), *native_tools])
        wrapped = wrap_openai_agent(agent, enforcer=enforcer)

For LangChain-first code, :meth:`MCPToolset.tools` is a back-compat
shortcut that returns LangChain ``BaseTool`` objects directly —
equivalent to importing ``wrap_mcp_toolset`` from
``hexgate.adapters.langchain.mcp``.
"""

from hexgate.mcp.client import MCPClient, MCPConnectionError
from hexgate.mcp.config import MCPServerConfig, MCPServerConfigError
from hexgate.mcp.proxy import MCPToolProxy, MCPToolset

__all__ = [
    "MCPClient",
    "MCPConnectionError",
    "MCPServerConfig",
    "MCPServerConfigError",
    "MCPToolProxy",
    "MCPToolset",
]
