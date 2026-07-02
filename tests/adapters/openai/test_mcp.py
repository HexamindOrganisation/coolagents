"""Tests for the OpenAI Agents adapter's MCP tool-set wrapper.

Framework-agnostic behavior (envelope shape, schema validation,
lifecycle, use-after-close) is exercised against
:class:`MCPToolProxy` directly in ``tests/mcp/test_proxy_core.py``.
This file covers only the ``MCPToolProxy → FunctionTool`` conversion:
metadata passthrough, JSON-input parsing, and envelope roundtrip via
``on_invoke_tool``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents import FunctionTool
from mcp.types import CallToolResult, TextContent, Tool

from hexgate.adapters.openai.mcp import _parse_args, wrap_mcp_toolset
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
    from hexgate.mcp.proxy import _ToolsetState
    from hexgate.mcp.proxy import _build_proxy as build

    return build(_ToolsetState(client), client.config, mcp_tool)  # type: ignore[arg-type]


# ---- _parse_args -----------------------------------------------------------


def test_parse_args_empty_returns_empty_dict() -> None:
    """No payload → empty dict; the proxy's validator then decides
    whether that satisfies the tool's schema."""
    assert _parse_args("") == {}


def test_parse_args_invalid_json_returns_empty_dict() -> None:
    """Junk payload → empty dict, not an exception — matches the
    tolerance of the native OpenAI wrap so schema validation is the
    single rejection point."""
    assert _parse_args("not json") == {}


def test_parse_args_non_object_json_returns_empty_dict() -> None:
    """Lists and scalars aren't valid tool argument payloads → drop
    them so downstream never sees a non-dict."""
    assert _parse_args("[1, 2]") == {}
    assert _parse_args("42") == {}
    assert _parse_args('"hi"') == {}


def test_parse_args_object_payload_round_trips() -> None:
    assert _parse_args('{"channel": "#dev", "text": "hi"}') == {
        "channel": "#dev",
        "text": "hi",
    }


# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_function_tool_per_proxy() -> None:
    client = _FakeMCPClient(_slack_config())
    proxy_a = _build_proxy(client, _mcp_tool("send"))
    proxy_b = _build_proxy(client, _mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(_toolset_with(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, FunctionTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the OpenAI wrapping unchanged so policy YAML references resolve."""
    client = _FakeMCPClient(_slack_config())
    [wrapped] = wrap_mcp_toolset(_toolset_with(_build_proxy(client, _mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description_and_schema() -> None:
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
    assert wrapped.params_json_schema == schema


def test_wrap_disables_openai_strict_json_schema() -> None:
    """MCP servers routinely advertise schemas that don't meet OpenAI's
    strict-mode requirements (partial ``required``, ``anyOf``, etc.).
    Wrapping with ``strict_json_schema=True`` would reject legitimate
    tools at wrap time; disable it and let our own validator carry the
    load."""
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))
    assert wrapped.strict_json_schema is False


def test_wrap_preserves_empty_input_schema() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) must
    reach OpenAI as ``params_json_schema={}``, not the type=object
    fallback — otherwise the LLM sees a spec the server didn't ask for."""
    client = _FakeMCPClient(_slack_config())
    proxy = _build_proxy(client, Tool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))
    assert wrapped.params_json_schema == {}


# ---- on_invoke_tool roundtrip ---------------------------------------------


@pytest.mark.asyncio
async def test_on_invoke_tool_returns_ok_envelope() -> None:
    """End-to-end: on_invoke_tool(ctx, raw JSON) → proxy.call → envelope."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("sent"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.on_invoke_tool(
        None, json.dumps({"channel": "#dev", "text": "hi"})
    )

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_on_invoke_tool_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} through
    on_invoke_tool — never bubbles up as a raised exception."""
    client = _FakeMCPClient(_slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = _build_proxy(client, _mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.on_invoke_tool(
        None, json.dumps({"channel": "#dev", "text": "hi"})
    )

    assert result["ok"] is False
    assert "simulated failure" in result["error"]["message"]


@pytest.mark.asyncio
async def test_on_invoke_tool_returns_schema_validation_error_for_bad_args() -> None:
    """Missing required args are rejected by proxy.call's validator
    BEFORE the server round-trip — must reach the LLM as a structured
    envelope, not the LLM getting whatever the server sends back."""
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

    result = await wrapped.on_invoke_tool(None, json.dumps({"channel": "#dev"}))

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []


@pytest.mark.asyncio
async def test_on_invoke_tool_handles_empty_raw_payload() -> None:
    """An empty raw payload becomes ``{}`` and reaches proxy.call as
    such. Whether it's accepted depends on the tool's schema — for a
    no-required-args tool it should succeed."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("pong"))
    proxy = _build_proxy(client, _mcp_tool("ping"))
    [wrapped] = wrap_mcp_toolset(_toolset_with(proxy))

    result = await wrapped.on_invoke_tool(None, "")

    assert result == {"ok": True, "content": "pong"}
    assert client.calls == [("ping", {})]
