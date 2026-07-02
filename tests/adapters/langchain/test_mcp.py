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
from mcp.types import Tool

from hexgate.adapters.langchain.mcp import wrap_mcp_toolset
from hexgate.mcp import MCPServerConfig
from tests.mcp.conftest import (
    FakeMCPClient,
    build_proxy,
    mcp_tool,
    slack_config,
    text_result,
    toolset_stub,
)


# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_langchain_base_tool_per_proxy() -> None:
    client = FakeMCPClient(slack_config())
    proxy_a = build_proxy(client, mcp_tool("send"))
    proxy_b = build_proxy(client, mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(toolset_stub(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, BaseTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the LangChain wrapping unchanged so policy YAML references resolve."""
    client = FakeMCPClient(slack_config())
    [wrapped] = wrap_mcp_toolset(toolset_stub(build_proxy(client, mcp_tool("send"))))
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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(
        client, mcp_tool("send", description="Post a message", schema=schema)
    )
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    assert wrapped.description == "Post a message"
    assert wrapped.args_schema == schema


def test_wrap_preserves_empty_input_schema() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) must
    reach LangChain as ``args_schema={}``, not as the type=object
    fallback — otherwise LangChain would enforce a spec the server
    didn't ask for."""
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, Tool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))
    assert wrapped.args_schema == {}


# ---- wrap_mcp_toolset — ainvoke roundtrip ----------------------------------


@pytest.mark.asyncio
async def test_wrapped_tool_ainvoke_returns_ok_envelope() -> None:
    """The end-to-end LangChain path: ainvoke → proxy.call → envelope."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("sent"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.ainvoke({"channel": "#dev", "text": "hi"})

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_wrapped_tool_ainvoke_returns_error_envelope() -> None:
    """A provider exception surfaces as {"ok": False, ...} through ainvoke,
    not as a raised exception — same contract native @agent_tool has."""
    client = FakeMCPClient(slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

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
            return [mcp_tool("ping")]

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _NoopClient)

    async with MCPToolset(slack_config()) as mcp:
        tools = mcp.tools
        assert len(tools) == 1
        assert isinstance(tools[0], BaseTool)
        assert tools[0].name == "mcp-slack-ping"
