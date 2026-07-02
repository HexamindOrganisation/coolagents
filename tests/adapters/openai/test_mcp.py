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

import pytest
from agents import FunctionTool
from mcp.types import Tool

from hexgate.adapters.openai.mcp import _parse_args, wrap_mcp_toolset
from tests.mcp.conftest import (
    FakeMCPClient,
    build_proxy,
    mcp_tool,
    slack_config,
    text_result,
    toolset_stub,
)


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
    client = FakeMCPClient(slack_config())
    proxy_a = build_proxy(client, mcp_tool("send"))
    proxy_b = build_proxy(client, mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(toolset_stub(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, FunctionTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the OpenAI wrapping unchanged so policy YAML references resolve."""
    client = FakeMCPClient(slack_config())
    [wrapped] = wrap_mcp_toolset(toolset_stub(build_proxy(client, mcp_tool("send"))))
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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(
        client, mcp_tool("send", description="Post a message", schema=schema)
    )
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    assert wrapped.description == "Post a message"
    assert wrapped.params_json_schema == schema


def test_wrap_disables_openai_strict_json_schema() -> None:
    """MCP servers routinely advertise schemas that don't meet OpenAI's
    strict-mode requirements (partial ``required``, ``anyOf``, etc.).
    Wrapping with ``strict_json_schema=True`` would reject legitimate
    tools at wrap time; disable it and let our own validator carry the
    load."""
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))
    assert wrapped.strict_json_schema is False


def test_wrap_preserves_empty_input_schema() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) must
    reach OpenAI as ``params_json_schema={}``, not the type=object
    fallback — otherwise the LLM sees a spec the server didn't ask for."""
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, Tool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))
    assert wrapped.params_json_schema == {}


# ---- on_invoke_tool roundtrip ---------------------------------------------


@pytest.mark.asyncio
async def test_on_invoke_tool_returns_ok_envelope() -> None:
    """End-to-end: on_invoke_tool(ctx, raw JSON) → proxy.call → envelope."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("sent"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.on_invoke_tool(
        None, json.dumps({"channel": "#dev", "text": "hi"})
    )

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_on_invoke_tool_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} through
    on_invoke_tool — never bubbles up as a raised exception."""
    client = FakeMCPClient(slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", schema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.on_invoke_tool(None, json.dumps({"channel": "#dev"}))

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []


@pytest.mark.asyncio
async def test_on_invoke_tool_handles_empty_raw_payload() -> None:
    """An empty raw payload becomes ``{}`` and reaches proxy.call as
    such. Whether it's accepted depends on the tool's schema — for a
    no-required-args tool it should succeed."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("pong"))
    proxy = build_proxy(client, mcp_tool("ping"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.on_invoke_tool(None, "")

    assert result == {"ok": True, "content": "pong"}
    assert client.calls == [("ping", {})]
