"""Framework-agnostic tests for the MCP proxy layer.

Uses a hand-rolled fake :class:`MCPClient` to exercise the proxy without
spawning a real subprocess. The end-to-end transport (stdio + http) is
covered by the official ``mcp`` SDK's own tests; what we own here is the
qualified-naming, schema passthrough, call-forwarding, envelope shape,
structured-output handling, schema validation, and lifecycle behavior
of our wrapper.

LangChain-specific wrapping is covered in
``tests/adapters/langchain/test_mcp.py``; this file drives
:class:`MCPToolProxy` directly via its async ``call(**kwargs)`` so the
assertions don't depend on any agent framework.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.types import (
    CallToolResult,
    EmbeddedResource,
    TextContent,
    TextResourceContents,
    Tool,
)

from hexgate.mcp import MCPServerConfig, MCPToolProxy, MCPToolset
from hexgate.mcp.client import MCPConnectionError
from hexgate.mcp.proxy import (
    _build_proxy,
    _result_to_envelope,
    _ToolsetState,
)


# ---- helpers ---------------------------------------------------------------


def _text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)], isError=is_error
    )


class _FakeMCPClient:
    """Minimal stand-in for :class:`MCPClient` — records calls, scripts results.

    Implements just the subset _build_proxy reads: ``config`` (for the
    qualified name) and ``call_tool``. Each call appends to ``self.calls``.
    """

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._next_result: CallToolResult | Exception = _text_result("default")

    def returns(self, result: CallToolResult) -> None:
        self._next_result = result

    def raises(self, exc: Exception) -> None:
        self._next_result = exc

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, arguments))
        if isinstance(self._next_result, Exception):
            raise self._next_result
        return self._next_result


def _slack_config(**overrides: Any) -> MCPServerConfig:
    base: dict[str, Any] = {
        "name": "slack",
        "transport": "stdio",
        "command": "slack-mcp",
    }
    base.update(overrides)
    return MCPServerConfig(**base)


def _tool(name: str, *, description: str = "", schema: dict | None = None) -> Tool:
    return Tool(
        name=name,
        description=description or None,
        inputSchema=schema or {"type": "object", "properties": {}},
    )


def _state(client: _FakeMCPClient | Any) -> _ToolsetState:
    """Build the proxy state shim the proxy closure consumes."""
    return _ToolsetState(client)  # type: ignore[arg-type]


# ---- _result_to_envelope ---------------------------------------------------


def test_envelope_wraps_text_content_as_ok() -> None:
    """Native @agent_tool returns {"ok": True, "content": ...} — MCP proxy
    must match so callers can discriminate uniformly across origins."""
    result = CallToolResult(
        content=[
            TextContent(type="text", text="line one"),
            TextContent(type="text", text="line two"),
        ],
        isError=False,
    )
    env = _result_to_envelope("mcp-slack-send", result)
    assert env == {"ok": True, "content": "line one\nline two"}


def test_envelope_marks_isError_as_not_ok() -> None:
    """MCP's isError=true is a deterministic tool-level failure — surface
    it as {"ok": False, "error": ...} so the agent doesn't treat it as
    success just because a payload came back."""
    result = CallToolResult(
        content=[TextContent(type="text", text="channel not found")],
        isError=True,
    )
    env = _result_to_envelope("mcp-slack-send", result)
    assert env["ok"] is False
    assert env["error"]["type"] == "tool_error"
    assert "channel not found" in env["error"]["message"]


def test_envelope_includes_structured_content() -> None:
    """structuredContent is MCP's first-class typed-return path — must be
    surfaced so the LLM sees typed data even without a content block."""
    result = CallToolResult(
        content=[],
        structuredContent={"channel_id": "C123", "ts": "1700000000.001"},
        isError=False,
    )
    env = _result_to_envelope("mcp-slack-send", result)
    assert env["ok"] is True
    # JSON serialization is stable (sort_keys) so callers can substring-check.
    assert '"channel_id": "C123"' in env["content"]
    assert '"ts": "1700000000.001"' in env["content"]


def test_envelope_extracts_text_from_embedded_resource() -> None:
    """EmbeddedResource wrapping a text-typed resource must reach the LLM."""
    resource = TextResourceContents(
        uri="file:///tmp/x.txt", mimeType="text/plain", text="embedded body"
    )
    block = EmbeddedResource(type="resource", resource=resource)
    result = CallToolResult(content=[block], isError=False)
    env = _result_to_envelope("mcp-fs-read", result)
    assert env == {"ok": True, "content": "embedded body"}


def test_envelope_falls_back_to_placeholder_for_empty_content() -> None:
    """A tool that returns nothing usable (no text, no structuredContent)
    must not surface an empty LLM message — the LLM needs SOMETHING to
    react to."""
    result = CallToolResult(content=[], isError=False)
    env = _result_to_envelope("mcp-noop-ping", result)
    assert env == {"ok": True, "content": "(no textual content)"}


# ---- _build_proxy — descriptor shape ---------------------------------------


def test_proxy_returns_mcp_tool_proxy() -> None:
    """_build_proxy produces an MCPToolProxy dataclass — the canonical
    descriptor every adapter reads."""
    proxy = _build_proxy(
        _state(_FakeMCPClient(_slack_config())),
        _slack_config(),
        _tool("send_message"),
    )
    assert isinstance(proxy, MCPToolProxy)


def test_proxy_uses_qualified_name() -> None:
    """LLM-visible name must be ``mcp-<server>-<tool>`` so it can't collide
    with native tools or with another MCP server exposing the same tool."""
    proxy = _build_proxy(
        _state(_FakeMCPClient(_slack_config())),
        _slack_config(),
        _tool("send_message"),
    )
    assert proxy.qualified_name == "mcp-slack-send_message"


def test_proxy_passes_through_description_and_schema() -> None:
    """MCP's description + inputSchema must reach the LLM unchanged so it
    knows when + how to call the tool."""
    schema = {
        "type": "object",
        "properties": {
            "channel": {"type": "string", "description": "Slack channel ID"},
            "text": {"type": "string"},
        },
        "required": ["channel", "text"],
    }
    cfg = _slack_config()
    proxy = _build_proxy(
        _state(_FakeMCPClient(cfg)),
        cfg,
        _tool("send_message", description="Post a message to a channel", schema=schema),
    )
    assert proxy.description == "Post a message to a channel"
    assert proxy.input_schema == schema


def test_proxy_falls_back_to_default_description() -> None:
    """A tool with no description shouldn't produce an empty descriptor —
    adapters that require non-empty descriptions (LangChain) would
    otherwise refuse to build a tool. Fall back to the qualified name so
    the LLM at least sees a label."""
    cfg = _slack_config()
    proxy = _build_proxy(_state(_FakeMCPClient(cfg)), cfg, _tool("list_channels"))
    assert proxy.description
    assert "mcp-slack-list_channels" in proxy.description


def test_proxy_preserves_empty_input_schema() -> None:
    """A server that advertises inputSchema={} (valid JSON Schema meaning
    "accept anything") must NOT be silently replaced with the
    type=object fallback — that narrows the spec the LLM sees. Falsy-or
    bug; only `is None` should trigger the fallback."""
    cfg = _slack_config()
    # MCP's `Tool.inputSchema` default-factories to {}, so we get that
    # naturally by omitting it — same shape as the live failure path.
    tool = Tool(name="freeform", description="anything goes", inputSchema={})
    proxy = _build_proxy(_state(_FakeMCPClient(cfg)), cfg, tool)
    # The exact dict the server sent should reach the descriptor unchanged.
    assert proxy.input_schema == {}


# ---- proxy.call() forwarding -----------------------------------------------


@pytest.mark.asyncio
async def test_proxy_call_forwards_with_server_local_name() -> None:
    """The proxy must call ``client.call_tool(inner_name, ...)`` — NOT the
    qualified name — because the server only knows its local tool names."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("ok"))
    proxy = _build_proxy(_state(client), _slack_config(), _tool("send_message"))

    result = await proxy.call(channel="#dev", text="hi")

    assert client.calls == [("send_message", {"channel": "#dev", "text": "hi"})]
    assert result == {"ok": True, "content": "ok"}


@pytest.mark.asyncio
async def test_proxy_call_returns_error_envelope_on_provider_exception() -> None:
    """Provider RuntimeErrors (e.g. SDK output-schema validation failures)
    must surface as a {"ok": False, "error": ...} envelope — never bubble
    up and abort the agent run."""
    client = _FakeMCPClient(_slack_config())
    client.raises(RuntimeError("simulated SDK output-schema violation"))
    proxy = _build_proxy(_state(client), _slack_config(), _tool("send_message"))

    result = await proxy.call(channel="#dev", text="hi")

    assert result["ok"] is False
    assert "simulated SDK output-schema violation" in result["error"]["message"]
    assert result["error"]["tool_name"] == "mcp-slack-send_message"


@pytest.mark.asyncio
async def test_proxy_call_returns_error_envelope_on_not_connected() -> None:
    """An MCPConnectionError (use-after-close at the client level) must
    also produce an envelope — never raise out of the proxy."""
    client = _FakeMCPClient(_slack_config())
    client.raises(MCPConnectionError("session torn down"))
    proxy = _build_proxy(_state(client), _slack_config(), _tool("send_message"))

    result = await proxy.call(channel="#dev", text="hi")

    assert result["ok"] is False
    assert result["error"]["type"] == "not_connected"


# ---- schema validation -----------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_rejects_missing_required_arg_before_round_trip() -> None:
    """An LLM call that omits a required arg must NOT reach the server —
    return a structured validation error envelope instead."""
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
        _state(client), _slack_config(), _tool("send_message", schema=schema)
    )

    result = await proxy.call(channel="#dev")  # missing "text"

    assert result["ok"] is False
    assert result["error"]["type"] == "schema_validation_error"
    # The server was never called.
    assert client.calls == []


@pytest.mark.asyncio
async def test_proxy_accepts_valid_args_through_schema_validation() -> None:
    """Schema validation must be opt-in to passing args — once they match
    the inputSchema, the proxy forwards as usual."""
    schema = {
        "type": "object",
        "properties": {"channel": {"type": "string"}},
        "required": ["channel"],
    }
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("sent"))
    proxy = _build_proxy(
        _state(client), _slack_config(), _tool("send_message", schema=schema)
    )

    result = await proxy.call(channel="#dev")

    assert client.calls == [("send_message", {"channel": "#dev"})]
    assert result == {"ok": True, "content": "sent"}


# ---- use-after-close guard -------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_post_close_returns_clear_error_envelope() -> None:
    """If the toolset has been torn down, the proxy must NOT raise the
    cryptic 'use async with MCPClient(...)' error from the underlying
    client — the user never instantiated an MCPClient (they used
    MCPToolset)."""
    state = _state(_FakeMCPClient(_slack_config()))
    proxy = _build_proxy(state, _slack_config(), _tool("send_message"))

    # Simulate the toolset's __aexit__ marking the state closed.
    state.open = False

    result = await proxy.call(channel="#dev", text="hi")

    assert result["ok"] is False
    assert result["error"]["type"] == "use_after_close"
    # Must point at MCPToolset specifically, not at MCPClient.
    assert "MCPToolset" in result["error"]["message"]


# ---- MCPToolset construction + dedup ---------------------------------------


def test_toolset_requires_at_least_one_config() -> None:
    with pytest.raises(ValueError, match="at least one"):
        MCPToolset()


def test_toolset_rejects_duplicate_server_names() -> None:
    """OpenAI's function-calling API rejects duplicate function names —
    catch the construction-time mistake with a clear message rather than
    surfacing it as a BadRequestError on the first ainvoke."""
    cfg = MCPServerConfig(name="slack", transport="stdio", command="x")
    with pytest.raises(ValueError, match="duplicate server name"):
        MCPToolset(cfg, cfg)


# ---- MCPToolset lifecycle --------------------------------------------------


@pytest.mark.asyncio
async def test_toolset_opens_then_closes_clients(monkeypatch) -> None:
    """The toolset must call __aenter__ on every client at entry and
    __aexit__ on every client at exit — otherwise stdio subprocesses leak."""
    opened: list[str] = []
    closed: list[str] = []

    class _TrackingClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_TrackingClient":
            opened.append(self.config.name)
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            closed.append(self.config.name)

        async def list_tools(self) -> list[Tool]:
            return [_tool("ping")]

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _TrackingClient)

    a = MCPServerConfig(name="a", transport="stdio", command="x")
    b = MCPServerConfig(name="b", transport="stdio", command="y")

    async with MCPToolset(a, b) as mcp:
        assert opened == ["a", "b"]
        assert closed == []  # nothing closed yet
        assert [p.qualified_name for p in mcp.proxies] == [
            "mcp-a-ping",
            "mcp-b-ping",
        ]

    # Exit closes in reverse order — symmetric teardown via AsyncExitStack.
    assert closed == ["b", "a"]


@pytest.mark.asyncio
async def test_toolset_cleans_up_on_partial_open_failure(monkeypatch) -> None:
    """If the second server fails to connect, the first must still be
    closed — otherwise a single bad MCP server leaks the others' transports."""
    opened: list[str] = []
    closed: list[str] = []

    class _MaybeFailingClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_MaybeFailingClient":
            if self.config.name == "b":
                raise RuntimeError("simulated connect failure on b")
            opened.append(self.config.name)
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            closed.append(self.config.name)

        async def list_tools(self) -> list[Tool]:
            return []

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _MaybeFailingClient)

    a = MCPServerConfig(name="a", transport="stdio", command="x")
    b = MCPServerConfig(name="b", transport="stdio", command="y")

    with pytest.raises(RuntimeError, match="simulated connect failure"):
        async with MCPToolset(a, b):
            pass  # pragma: no cover — entry should have raised

    # The first client was opened and must have been closed during teardown.
    assert opened == ["a"]
    assert closed == ["a"]


@pytest.mark.asyncio
async def test_proxy_returns_transport_error_envelope_on_httpx_error() -> None:
    """HTTP transport errors (network blip, 5xx) must surface as a
    retryable=True envelope so the agent can decide to back off — not
    abort the run."""
    import httpx

    client = _FakeMCPClient(_slack_config())
    client.raises(httpx.ConnectError("connection refused"))
    proxy = _build_proxy(_state(client), _slack_config(), _tool("send_message"))

    result = await proxy.call(channel="#dev", text="hi")

    assert result["ok"] is False
    assert result["error"]["type"] == "transport_error"
    assert result["error"]["retryable"] is True


@pytest.mark.asyncio
async def test_proxy_skips_validation_for_tool_with_no_input_schema() -> None:
    """An MCP tool whose inputSchema can't build a validator must still
    accept calls — fall back to accepting anything rather than refusing
    to invoke."""
    client = _FakeMCPClient(_slack_config())
    client.returns(_text_result("ok"))
    cfg = _slack_config()
    bad_schema = {"type": "object", "properties": {"x": {"type": "not-a-real-type"}}}
    proxy = _build_proxy(_state(client), cfg, _tool("ping", schema=bad_schema))

    # Must not raise — validator fallback returns None on schema error.
    result = await proxy.call(x=1)
    assert result == {"ok": True, "content": "ok"}


def test_render_structured_falls_back_to_repr_on_unserializable() -> None:
    """A structuredContent payload with non-JSON-serializable values (e.g.
    a class instance the server returned by mistake) must still produce
    a string the LLM can read, not crash the proxy."""
    from hexgate.mcp.proxy import _render_structured

    class _Unserializable:
        pass

    obj = _Unserializable()
    out = _render_structured(obj)
    # repr() is the fallback — must be a non-empty string.
    assert isinstance(out, str)
    assert "_Unserializable" in out


def test_iter_text_blocks_skips_non_text_content() -> None:
    """Content blocks without `.text` (images, binary resources) must be
    silently skipped, not produce ``None`` strings or crash."""
    from types import SimpleNamespace

    from hexgate.mcp.proxy import _iter_text_blocks

    blocks = [
        SimpleNamespace(text="hello"),
        SimpleNamespace(),  # no text attr
        SimpleNamespace(text=None),  # text set but not a string (image data)
        SimpleNamespace(text="world"),
    ]
    assert list(_iter_text_blocks(blocks)) == ["hello", "world"]


def test_error_envelope_only_transport_error_is_retryable() -> None:
    """Only transport-level failures (network blip, 5xx) are retryable.
    MCP's isError=true is a deterministic application error (permissions,
    not-found, bad-input-past-schema) — retrying will reproduce it.
    Aligns with native Decision.as_error_payload (always retryable=False)."""
    from hexgate.mcp.proxy import _error_envelope

    transport = _error_envelope("transport_error", "connection reset", "mcp-x-y")
    tool_err = _error_envelope("tool_error", "permission denied", "mcp-x-y")
    closed = _error_envelope("use_after_close", "closed", "mcp-x-y")
    schema_err = _error_envelope("schema_validation_error", "bad args", "mcp-x-y")
    assert transport["error"]["retryable"] is True
    assert tool_err["error"]["retryable"] is False
    assert closed["error"]["retryable"] is False
    assert schema_err["error"]["retryable"] is False


@pytest.mark.asyncio
async def test_toolset_flips_state_to_closed_on_exit(monkeypatch) -> None:
    """After exiting the with block, proxies built from this toolset must
    see ``state.open == False`` so they return a clear error envelope
    rather than calling into a torn-down client."""
    captured_states: list[Any] = []

    class _RecordingClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_RecordingClient":
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            pass

        async def list_tools(self) -> list[Tool]:
            return [_tool("ping")]

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _RecordingClient)

    cfg = MCPServerConfig(name="a", transport="stdio", command="x")
    toolset = MCPToolset(cfg)
    async with toolset as mcp:
        captured_states = list(mcp._states)  # noqa: SLF001 — invariant under test
        assert all(s.open for s in captured_states)

    assert all(not s.open for s in captured_states)


@pytest.mark.asyncio
async def test_toolset_clears_states_and_proxies_on_exit(monkeypatch) -> None:
    """Both ``_proxies`` and ``_states`` must be cleared on exit — leaving
    ``_states`` populated would let a re-entered toolset accumulate
    phantom state objects from earlier sessions, and any code that
    iterates ``mcp._states`` would see stale closed entries."""

    class _NoopClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_NoopClient":
            return self

        async def __aexit__(self, *exc_info: Any) -> None:
            pass

        async def list_tools(self) -> list[Tool]:
            return [_tool("ping"), _tool("pong")]

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _NoopClient)

    cfg = MCPServerConfig(name="a", transport="stdio", command="x")
    toolset = MCPToolset(cfg)
    async with toolset as mcp:
        assert len(mcp._states) == 1  # noqa: SLF001
        assert len(mcp._proxies) == 1 * 2  # noqa: SLF001 — 2 tools returned

    # Both internal lists are flushed — no phantom entries left behind.
    assert toolset._states == []  # noqa: SLF001
    assert toolset._proxies == []  # noqa: SLF001


@pytest.mark.asyncio
async def test_toolset_aexit_forwards_suppression_return(monkeypatch) -> None:
    """If an inner CM in the exit stack returns truthy from __aexit__
    (i.e. suppresses the exception), the toolset's __aexit__ must forward
    that — discarding the return would silently override the suppression
    decision and let the exception propagate when it shouldn't."""

    class _SuppressingClient:
        def __init__(self, config: MCPServerConfig) -> None:
            self.config = config

        async def __aenter__(self) -> "_SuppressingClient":
            return self

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
            # Claim suppression of any exception that propagates through us.
            return True

        async def list_tools(self) -> list[Tool]:
            return []

    monkeypatch.setattr("hexgate.mcp.proxy.MCPClient", _SuppressingClient)

    cfg = MCPServerConfig(name="a", transport="stdio", command="x")
    # Inner CM says "I handled it" — the with block must NOT re-raise.
    async with MCPToolset(cfg):
        raise RuntimeError("inner CM should suppress this")
