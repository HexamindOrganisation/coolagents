"""Wrap third-party MCP (Model Context Protocol) servers as guarded tools.

The single public entry point is :class:`MCPToolset`, an async context
manager that connects to one or more MCP servers, enumerates their tool
catalogs, and exposes them as LangChain :class:`BaseTool` objects ready
to hand to :func:`create_agent`. From there the existing
:func:`enforce_policy` pass wraps each one in :class:`GuardedTool` —
MCP tools become indistinguishable from native ``@agent_tool``
functions to the rest of the runtime, including policy enforcement,
audit, and approval flows.

Tool naming is ``mcp-<server>-<tool>`` (hyphens, not colons — OpenAI's
function-calling spec rejects colons in tool names). The server name is
caller-supplied and validated to ``^[a-z0-9-]{1,32}$`` so qualified
names stay under OpenAI's 64-char tool-name limit.

Example::

    from hexgate import create_agent, enforce_policy
    from hexgate.mcp import MCPServerConfig, MCPToolset

    slack = MCPServerConfig(
        name="slack",
        transport="stdio",
        command="slack-mcp-server",
        env={"SLACK_TOKEN": "..."},
    )

    async with MCPToolset(slack) as mcp:
        agent, handler = create_agent(
            model="gpt-5.4", tools=[*native_tools, *mcp.tools]
        )
        agent = enforce_policy(agent, "policy.yaml")
        await agent.ainvoke({"messages": [...]})
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
