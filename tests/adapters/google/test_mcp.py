"""Tests for the Google ADK adapter's MCP tool-set wrapper.

Framework-agnostic behavior (envelope shape, schema validation,
lifecycle, use-after-close) is exercised against
:class:`MCPToolProxy` directly in ``tests/mcp/test_proxy_core.py``.
This file covers only the ``MCPToolProxy → BaseTool`` conversion:
metadata + JSON-Schema passthrough via ``_get_declaration``, and
envelope roundtrip via ``run_async``.
"""

from __future__ import annotations

import pytest
from google.adk.tools import BaseTool
from mcp.types import Tool as MCPTool

from hexgate.adapters.google.mcp import wrap_mcp_toolset
from tests.mcp.conftest import (
    FakeMCPClient,
    build_proxy,
    mcp_tool,
    slack_config,
    text_result,
    toolset_stub,
)


# ---- wrap_mcp_toolset — shape ---------------------------------------------


def test_wrap_returns_a_base_tool_per_proxy() -> None:
    client = FakeMCPClient(slack_config())
    proxy_a = build_proxy(client, mcp_tool("send"))
    proxy_b = build_proxy(client, mcp_tool("list_channels"))

    tools = wrap_mcp_toolset(toolset_stub(proxy_a, proxy_b))

    assert len(tools) == 2
    for tool in tools:
        assert isinstance(tool, BaseTool)


def test_wrap_preserves_qualified_name() -> None:
    """The qualified name is the LLM-visible identifier — must survive
    the ADK wrapping unchanged so policy YAML references resolve at
    enforcement time."""
    client = FakeMCPClient(slack_config())
    [wrapped] = wrap_mcp_toolset(toolset_stub(build_proxy(client, mcp_tool("send"))))
    assert wrapped.name == "mcp-slack-send"


def test_wrap_preserves_description() -> None:
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", description="Post a message"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))
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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", schema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.name == "mcp-slack-send"
    # ADK uses camelCase alias on construction but attribute access is
    # snake_case (pydantic model convention).
    assert declaration.parameters_json_schema == schema


def test_declaration_coerces_empty_input_schema_to_minimal_object() -> None:
    """An MCP tool advertising ``inputSchema={}`` (accept anything) is
    a valid JSON Schema, but Gemini's FunctionDeclaration validator
    rejects declarations whose ``parametersJsonSchema`` has no top-level
    ``type`` — the tool would silently vanish from the model's
    available toolset. Coerce ``{}`` to the minimal object schema
    Gemini accepts. LangChain and OpenAI Agents don't need this
    (they tolerate ``{}`` unchanged); the coercion is Google-specific."""
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, MCPTool(name="freeform", inputSchema={}))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.parameters_json_schema == {
        "type": "object",
        "properties": {},
    }


def test_declaration_coerces_non_empty_schema_missing_type() -> None:
    """Regression for post-review finding: the old ``or {...}`` guard
    only fired on falsy dicts. A non-empty schema missing a top-level
    ``type`` (e.g. ``{"properties": {...}}`` or ``{"anyOf": [...]}``)
    passed through unchanged and hit the exact Gemini rejection the
    guard claimed to prevent. Now we inject ``type: "object"`` whenever
    it's absent, keeping the caller's other keys."""
    schema = {"properties": {"channel": {"type": "string"}}}
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, MCPTool(name="partial", inputSchema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.parameters_json_schema["type"] == "object"
    # Caller's `properties` map is preserved verbatim.
    assert declaration.parameters_json_schema["properties"] == {
        "channel": {"type": "string"}
    }


def test_declaration_coerces_schema_that_only_has_anyof() -> None:
    """Second flavor of the type-missing case — a bare ``anyOf`` schema
    still needs a top-level ``type`` for Gemini, and the caller's
    ``anyOf`` must survive the coercion."""
    schema = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, MCPTool(name="nullable", inputSchema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.parameters_json_schema["type"] == "object"
    assert declaration.parameters_json_schema["anyOf"] == schema["anyOf"]


def test_declaration_leaves_schema_with_explicit_type_alone() -> None:
    """A well-formed schema (with a top-level ``type``) must NOT be
    coerced or have its fields rewritten — otherwise a caller who
    picked a non-object top-level (rare but valid) would be silently
    overridden."""
    schema = {
        "type": "object",
        "properties": {"foo": {"type": "string"}},
        "required": ["foo"],
    }
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, MCPTool(name="fine", inputSchema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    declaration = wrapped._get_declaration()

    assert declaration.parameters_json_schema == schema


# ---- run_async roundtrip ---------------------------------------------------


@pytest.mark.asyncio
async def test_run_async_returns_ok_envelope() -> None:
    """End-to-end: ADK's run_async(args=<dict>, tool_context=...) →
    proxy.call(**args) → envelope. Consistent across every adapter."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("sent"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.run_async(
        args={"channel": "#dev", "text": "hi"}, tool_context=None
    )

    assert result == {"ok": True, "content": "sent"}
    assert client.calls == [("send", {"channel": "#dev", "text": "hi"})]


@pytest.mark.asyncio
async def test_run_async_returns_error_envelope_on_provider_exception() -> None:
    """A provider exception surfaces as {"ok": False, ...} — never
    bubbles out as a raised exception, matching the other adapters."""
    client = FakeMCPClient(slack_config())
    client.raises(RuntimeError("simulated failure"))
    proxy = build_proxy(client, mcp_tool("send"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

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
    client = FakeMCPClient(slack_config())
    proxy = build_proxy(client, mcp_tool("send", schema=schema))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.run_async(args={"channel": "#dev"}, tool_context=None)

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    assert client.calls == []


@pytest.mark.asyncio
async def test_run_async_tolerates_none_args() -> None:
    """A tool call with ADK passing ``args=None`` (an empty invocation)
    must map to ``{}`` on the way in, not crash inside ``**None``."""
    client = FakeMCPClient(slack_config())
    client.returns(text_result("pong"))
    proxy = build_proxy(client, mcp_tool("ping"))
    [wrapped] = wrap_mcp_toolset(toolset_stub(proxy))

    result = await wrapped.run_async(args=None, tool_context=None)  # type: ignore[arg-type]

    assert result == {"ok": True, "content": "pong"}
    assert client.calls == [("ping", {})]
