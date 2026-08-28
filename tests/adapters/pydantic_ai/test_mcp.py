"""Tests for the Pydantic AI adapter's MCP tool-set wrapper.

Framework-agnostic behavior (envelope shape, schema validation,
lifecycle, use-after-close) is exercised against
:class:`MCPToolProxy` directly in ``tests/mcp/test_proxy_core.py``.
This file covers only the ``MCPToolProxy → Tool`` conversion:
metadata passthrough and envelope roundtrip via
``function_schema.call``.
"""

from __future__ import annotations

import pytest
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai.mcp import wrap_mcp_toolset
from tests.mcp.conftest import (
    FakeMCPClient,
    build_proxy,
    mcp_tool,
    slack_config,
    text_result,
    toolset_stub,
)

# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_pydantic_tool_per_proxy() -> None:
    client = FakeMCPClient(slack_config())
    proxy_a = build_proxy(client, mcp_tool("send"))
    proxy_b = build_proxy(client, mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(toolset_stub(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, Tool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the Pydantic AI wrapping unchanged so policy YAML references
    resolve at enforcement time."""
    client = FakeMCPClient(slack_config())
    [wrapped] = wrap_mcp_toolset(toolset_stub(build_proxy(client, mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description() -> None:
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", description="Post a message"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))
    assert wrapped.description == "Post a message"


# ---- function_schema.call roundtrip ---------------------------------------


@pytest.mark.asyncio
async def test_call_returns_ok_envelope() -> None:
    """End-to-end: pydantic_ai's function_schema.call(args_dict, ctx) →
    proxy.call(**args) → envelope. Args are unpacked from the dict."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("sent"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.function_schema.call({"channel": "#dev", "text": "hi"}, None)

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_call_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} — does NOT
    bubble as ModelRetry or a raised exception. Consistent with the
    other adapters' MCP wrap behavior."""
    client = FakeMCPClient(slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", schema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    # Bypass pydantic_ai's outer validation by calling proxy.call
    # directly through the Tool — this exercises the inner defence.
    result = await wrapped.function_schema.call({"channel": "#dev"}, None)

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []
