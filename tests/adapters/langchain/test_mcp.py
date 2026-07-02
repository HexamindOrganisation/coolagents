"""Tests for the LangChain adapter's MCP tool-set wrapper.

The framework-agnostic behavior (envelope shaping, schema validation,
lifecycle, use-after-close, etc.) lives in ``tests/mcp/test_proxy_core.py``
and is exercised there against :class:`MCPToolProxy` directly. This file
covers only the thin ``MCPToolProxy → BaseTool`` conversion: the
LangChain-facing metadata (name, description, args_schema) must reach
the tool intact and ``ainvoke`` must roundtrip the envelope back to the
caller unchanged.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import BaseTool
from mcp.types import CallToolResult, TextContent, Tool

from hexgate.adapters.langchain.mcp import wrap_mcp_toolset
from hexgate.mcp import MCPServerConfig, MCPToolProxy


# ---- helpers ---------------------------------------------------------------


def _text_result(text: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=False)


class _FakeMCPClient:
    """Minimal client shim mirroring the one in test_proxy_core."""

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


def _mcp_tool(name: str, *, description: str = "", schema: dict | None = None) -> Tool:
    return Tool(
        name=name,
        description=description or None,
        inputSchema=schema or {"type": "object", "properties": {}},
    )


def _toolset_with(*proxies: MCPToolProxy) -> Any:
    """A stand-in for MCPToolset that only exposes what wrap_mcp_toolset reads."""

    class _FakeToolset:
        pass

    fake = _FakeToolset()
    fake.proxies = list(proxies)
    return fake


def _build_proxy(client: _FakeMCPClient, mcp_tool: Tool) -> MCPToolProxy:
    """Build a real MCPToolProxy backed by the fake client."""
    from hexgate.mcp.proxy import _build_proxy as build, _ToolsetState

    return build(_ToolsetState(client), client.config, mcp_tool)  # type: ignore[arg-type]


# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_langchain_base_tool_per_proxy() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy_a = _build_proxy(client, _mcp_tool("send"))
    proxy_b = _build_proxy(client, _mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(_toolset_with(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, BaseTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the LangChain wrapping unchanged so policy YAML references resolve."""
    client = _FakeMCPClient(_slack_config())
    [wrapped] = wrap_mcp_toolset(_toolset_with(_build_proxy(client, _mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description_and_schema() -> None:
    """description + args_schema must reach the LangChain tool intact so
    the LLM sees the same contract the MCP server advertised."""
    schema = {
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "text": {"type": "string"},
        },
        "required": ["channel", "text"],
    }
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(
        client, _mcp_tool("send", description="Post a message", schema=schema)
    )
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    assert wrapped.description == "Post a message"
    assert wrapped.args_schema == schema


def test_wrap_preserves_empty_input_schema() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) must
    reach LangChain as ``args_schema={}``, not as the type=object
    fallback — otherwise LangChain would enforce a spec the server
    didn't ask for."""
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, Tool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))
    assert wrapped.args_schema == {}


# ---- wrap_mcp_toolset — ainvoke roundtrip ----------------------------------


@pytest.mark.asyncio
async def test_wrapped_tool_ainvoke_returns_ok_envelope() -> None:
    """The end-to-end LangChain path: ainvoke → proxy.call → envelope."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("sent"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.ainvoke({"channel": "#dev", "text": "hi"})

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_wrapped_tool_ainvoke_returns_error_envelope() -> None:
    """A provider exception surfaces as {"ok": False, ...} through ainvoke,
    not as a raised exception — same contract native @agent_tool has."""
    client = _FakeMCPClient(_slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.ainvoke({"channel": "#dev", "text": "hi"})

    assert result["ok"] is False
    assert "simulated failure" in result["error"]["message"]


# ---- MCPToolset.tools back-compat shortcut --------------------------------


@pytest.mark.asyncio
async def test_mcp_toolset_tools_shortcut_returns_langchain_tools(monkeypatch) -> None:
    """``MCPToolset.tools`` is documented public API — it must still return
    LangChain tools by delegating to ``wrap_mcp_toolset`` internally, so
    pre-adapter-split code (``mcp.tools``) keeps working unchanged."""
    from hexgate.mcp import MCPToolset

    class _NoopClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_NoopClient":
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            pass

        async def list_tools(self) -> list[Tool]:
            return [_mcp_tool("ping")]

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _NoopClient)

    async with MCPToolset(_slack_config()) as mcp:
        tools = mcp.tools
        assert len(tools) == 1
        assert isinstance(tools[0], BaseTool)
        assert tools[0].name == "mcp-slack-ping"
