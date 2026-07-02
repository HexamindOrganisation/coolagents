"""Tests for the Google ADK adapter's MCP tool-set wrapper.

Framework-agnostic behavior (envelope shape, schema validation,
lifecycle, use-after-close) is exercised against
:class:`MCPToolProxy` directly in ``tests/mcp/test_proxy_core.py``.
This file covers only the ``MCPToolProxy → BaseTool`` conversion:
metadata + JSON-Schema passthrough via ``_get_declaration``, and
envelope roundtrip via ``run_async``.
"""

from __future__ import annotations

from typing import Any

import pytest
from google.adk.tools import BaseTool
from mcp.types import CallToolResult, TextContent, Tool as MCPTool

from hexgate.adapters.google.mcp import wrap_mcp_toolset
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


def test_wrap_returns_a_base_tool_per_proxy() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy_a = _build_proxy(client, _mcp_tool("send"))
    proxy_b = _build_proxy(client, _mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(_toolset_with(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, BaseTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the ADK wrapping unchanged so policy YAML references resolve at
    enforcement time."""
    client = _FakeMCPClient(_slack_config())
    [wrapped] = wrap_mcp_toolset(_toolset_with(_build_proxy(client, _mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, _mcp_tool("send", description="Post a message"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))
    assert wrapped.description == "Post a message"


# ---- _get_declaration — the JSON Schema bridge -----------------------------


def test_declaration_carries_raw_json_schema() -> None:
    """ADK's :class:`FunctionTool` derives its schema from the callable's
    signature and can't express partial ``required`` / ``anyOf`` /
    nested-object shapes MCP servers advertise. Our BaseTool subclass
    bypasses that by returning a FunctionDeclaration with the raw
    JSON Schema via ``parametersJsonSchema`` — verified here so a future
    ADK refactor that stops honoring that alias would break loudly."""
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

    declaration = wrapped._get_declaration()

    assert declaration.name == "mcp-slack-send"
    # ADK uses camelCase alias on construction but attribute access is
    # snake_case (pydantic model convention).
    assert declaration.parameters_json_schema == schema


def test_declaration_preserves_empty_input_schema() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) must
    reach ADK unchanged — otherwise the LLM sees a spec the server
    didn't ask for."""
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, MCPTool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.parameters_json_schema == {}


# ---- run_async roundtrip ---------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_returns_ok_envelope() -> None:
    """End-to-end: ADK's run_async(args=<dict>, tool_context=...) →
    proxy.call(**args) → envelope. Consistent across every adapter."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("sent"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.run_async(
        args={"channel": "#dev", "text": "hi"}, tool_context=None
    )

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_run_async_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} — never
    bubbles out as a raised exception, matching the other adapters."""
    client = _FakeMCPClient(_slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.run_async(
        args={"channel": "#dev", "text": "hi"}, tool_context=None
    )

    assert result["ok"] is False
    assert "simulated failure" in result["error"]["message"]


@pytest.mark.asyncio
async def test_run_async_returns_schema_validation_error_for_bad_args() -> None:
    """Missing required args are rejected by proxy.call's validator
    BEFORE the server round-trip — the ADK layer just forwards the
    envelope back to the LLM."""
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

    result = await wrapped.run_async(args={"channel": "#dev"}, tool_context=None)

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []


@pytest.mark.asyncio
async def test_run_async_tolerates_none_args() -> None:
    """A tool call with ADK passing ``args=None`` (an empty invocation)
    must map to ``{}`` on the way in, not crash inside ``**None``."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("pong"))
    proxy = _build_proxy(client, _mcp_tool("ping"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.run_async(args=None, tool_context=None)  # type: ignore[arg-type]

    assert result == {"ok": True, "content": "pong"}
    assert client.calls == [("ping", {})]
