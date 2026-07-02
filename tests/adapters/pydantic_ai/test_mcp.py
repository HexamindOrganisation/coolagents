"""Tests for the Pydantic AI adapter's MCP tool-set wrapper.

Framework-agnostic behavior (envelope shape, schema validation,
lifecycle, use-after-close) is exercised against
:class:`MCPToolProxy` directly in ``tests/mcp/test_proxy_core.py``.
This file covers only the ``MCPToolProxy → Tool`` conversion:
metadata passthrough and envelope roundtrip via
``function_schema.call``.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.types import CallToolResult, TextContent, Tool as MCPTool
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai.mcp import wrap_mcp_toolset
from hexgate.mcp import MCPServerConfig, MCPToolProxy


# ---- helpers ---------------------------------------------------------------


def _text_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)


class _FakeMCPClient:
    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._next: CallToolResult | Exception = _text_result("default")

    def returns(self, result: CallToolResult) -> None:
        self._next = result

    def raises(self, exc: Exception) -> None:
        self._next = exc

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, arguments))
        if isinstance(self._next, Exception):
            raise self._next
        return self._next


def _slack_config() -> MCPServerConfig:
    return MCPServerConfig(name="slack", transport="stdio", command="slack-mcp")


def _mcp_tool(
    name: str, *, description: str = "", schema: dict | None = None
) -> MCPTool:
    return MCPTool(
        name=name,
        description=description or None,
        inputSchema=schema or {"type": "object", "properties": {}},
    )


def _toolset_with(*proxies: MCPToolProxy) -> Any:
    class _FakeToolset:
        pass

    fake = _FakeToolset()
    fake.proxies = list(proxies)
    return fake


def _build_proxy(client: _FakeMCPClient, mcp_tool: MCPTool) -> MCPToolProxy:
    from hexgate.mcp.proxy import _ToolsetState
    from hexgate.mcp.proxy import _build_proxy as build

    return build(_ToolsetState(client), client.config, mcp_tool)  # type: ignore[arg-type]


# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_pydantic_tool_per_proxy() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy_a = _build_proxy(client, _mcp_tool("send"))
    proxy_b = _build_proxy(client, _mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(_toolset_with(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, Tool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the Pydantic AI wrapping unchanged so policy YAML references
    resolve at enforcement time."""
    client = _FakeMCPClient(_slack_config())
    [wrapped] = wrap_mcp_toolset(_toolset_with(_build_proxy(client, _mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, _mcp_tool("send", description="Post a message"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))
    assert wrapped.description == "Post a message"


# ---- function_schema.call roundtrip ---------------------------------------


@pytest.mark.asyncio
async def test_call_returns_ok_envelope() -> None:
    """End-to-end: pydantic_ai's function_schema.call(args_dict, ctx) →
    proxy.call(**args) → envelope. Args are unpacked from the dict."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("sent"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.function_schema.call({"channel": "#dev", "text": "hi"}, None)

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_call_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} — does NOT
    bubble as ModelRetry or a raised exception. Consistent with the
    other adapters' MCP wrap behavior."""
    client = _FakeMCPClient(_slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.function_schema.call({"channel": "#dev", "text": "hi"}, None)

    assert result["ok"] is False
    assert "simulated failure" in result["error"]["message"]


@pytest.mark.asyncio
async def test_call_returns_schema_validation_error_for_bad_args_from_proxy_layer() -> (
    None
):
    """Even if pydantic_ai's outer validator lets an arg dict through,
    our proxy's own validator rejects malformed args BEFORE the server
    round-trip. That layer is exercised by feeding an unvalidated
    partial dict directly — as would happen if pydantic_ai's model
    were permissive on that field."""
    schema = {
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "text": {"type": "string"},
        },
        "required": ["channel", "text"],
    }
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, _mcp_tool("send", schema=schema))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    # Bypass pydantic_ai's outer validation by calling proxy.call
    # directly through the Tool — this exercises the inner defence.
    result = await wrapped.function_schema.call({"channel": "#dev"}, None)

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []
