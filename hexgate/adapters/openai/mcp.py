"""OpenAI Agents adapter for :class:`~hexgate.mcp.MCPToolset`.

Every :class:`~hexgate.mcp.MCPToolProxy` produced by the toolset becomes
an :class:`agents.FunctionTool` whose ``on_invoke_tool`` forwards to the
proxy's ``call``. Once wrapped, the resulting :class:`FunctionTool`
objects are indistinguishable from native ``@function_tool``-decorated
callables to the rest of the OpenAI Agents path — hand them to an
``Agent`` alongside your other tools, then wrap the agent via
:func:`~hexgate.adapters.openai.wrap_openai_agent` so the existing
per-tool policy gate covers MCP invocations too.

Usage::

    from agents import Agent
    from hexgate.adapters.openai import wrap_openai_agent
    from hexgate.adapters.openai.mcp import wrap_mcp_toolset
    from hexgate.mcp import MCPServerConfig, MCPToolset

    slack = MCPServerConfig(name="slack", transport="stdio", command="slack-mcp")
    async with MCPToolset(slack) as mcp:
        agent = Agent(
            name="bot",
            tools=[*wrap_mcp_toolset(mcp), *native_tools],
        )
        wrapped = wrap_openai_agent(agent, enforcer=enforcer)
        await HexgateRunner(api_key).run(wrapped, "…", hexgate_context=context)
"""

from __future__ import annotations

import json
from typing import Any

from agents import FunctionTool
from agents.tool import ToolContext

from hexgate.mcp.proxy import MCPToolProxy, MCPToolset


def _parse_args(raw: str) -> dict[str, Any]:
    """Best-effort JSON-to-dict parse of a tool-call payload.

    An empty or unparseable payload becomes ``{}`` — the proxy's
    JSON-Schema validator then decides whether that's acceptable.
    Matches the same tolerance the native OpenAI wrap has.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _wrap_one(proxy: MCPToolProxy) -> FunctionTool:
    """Build a single :class:`FunctionTool` around ``proxy.call``.

    OpenAI Agents' ``FunctionTool`` accepts a raw JSON Schema in
    ``params_json_schema`` — no dynamic Pydantic model generation
    needed. ``strict_json_schema=False`` is deliberate: MCP servers
    routinely advertise schemas that don't meet OpenAI's strict-mode
    requirements (partial ``required``, optional ``additionalProperties``,
    ``anyOf`` unions), and we'd rather forward the server's spec
    verbatim than reject legitimate tools at wrap time. Our own
    pre-call validator in ``proxy.call`` still catches malformed args
    before the round trip.

    ``on_invoke_tool`` is the one bit that can't collapse to
    ``proxy.call`` directly — OpenAI hands us the raw JSON string, not
    a parsed dict.
    """
    call = proxy.call

    async def on_invoke_tool(ctx: ToolContext[Any], raw: str) -> Any:
        return await call(**_parse_args(raw))

    return FunctionTool(
        name=proxy.qualified_name,
        description=proxy.description,
        params_json_schema=proxy.input_schema,
        on_invoke_tool=on_invoke_tool,
        strict_json_schema=False,
    )


def wrap_mcp_toolset(toolset: MCPToolset) -> list[FunctionTool]:
    """Wrap every proxy in ``toolset`` as an OpenAI Agents
    :class:`FunctionTool`.

    The returned tools share the toolset's connection lifecycle — they
    stop working (returning a ``use_after_close`` envelope) once the
    ``async with MCPToolset(...)`` block exits. Combine with
    :func:`~hexgate.adapters.openai.wrap_openai_agent` to gate every
    invocation through :class:`~hexgate.security.PolicyEnforcer`.
    """
    return [_wrap_one(p) for p in toolset.proxies]
