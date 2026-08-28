"""Shared test fixtures for the MCP proxy layer and every per-adapter
wrapper suite.

Before this file, `_FakeMCPClient`, `_slack_config`, `_mcp_tool`,
`_toolset_with`, `_build_proxy`, and `_text_result` were copy-pasted
into five test modules (~50 lines apiece). Small drifts already
appeared (``_next_result`` vs ``_next``) making shared assertions
brittle. Consolidated here and re-exported via a stable module path so
adapter tests can `from tests.mcp.conftest import ...`.

Kept module-level (not pytest fixtures) so tests can build multiple
clients/proxies per case without decorator ceremony. These helpers
have no per-test state; they're just builders.
"""

from __future__ import annotations

from typing import Any

from mcp.types import CallToolResult, TextContent, Tool

from hexgate.mcp import MCPServerConfig, MCPToolProxy


def text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    """A `CallToolResult` with a single text block."""
    return CallToolResult(
        content=[TextContent(type="text", text=text)], isError=is_error
    )


class FakeMCPClient:
    """Minimal stand-in for :class:`MCPClient`.

    Implements just the subset _build_proxy reads: ``config`` (for the
    qualified name) and ``call_tool``. Every call appends to
    ``self.calls`` so tests can assert forwarding shape.
    """

    def __init__(self, config: MCPServerConfig) -> None:
        self.config = config
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._next: CallToolResult | Exception = text_result("default")

    def returns(self, result: CallToolResult) -> None:
        self._next = result

    def raises(self, exc: Exception) -> None:
        self._next = exc

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallToolResult:
        self.calls.append((name, arguments))
        if isinstance(self._next, Exception):
            raise self._next
        return self._next


def slack_config(**overrides: Any) -> MCPServerConfig:
    """A stdio MCPServerConfig with sensible defaults for tests."""
    base: dict[str, Any] = {
        "name": "slack",
        "transport": "stdio",
        "command": "slack-mcp",
    }
    base.update(overrides)
    return MCPServerConfig(**base)


def mcp_tool(name: str, *, description: str = "", schema: dict | None = None) -> Tool:
    """A minimal MCP `Tool` — description defaults to unset so proxy's
    "no description provided" fallback path is exercised too."""
    return Tool(
        name=name,
        description=description or None,
        inputSchema=schema or {"type": "object", "properties": {}},
    )


def toolset_stub(*proxies: MCPToolProxy) -> Any:
    """A stand-in for :class:`MCPToolset` that only exposes what
    adapter `wrap_mcp_toolset` functions read (`.proxies`)."""

    class _Stub:
        pass

    stub = _Stub()
    stub.proxies = list(proxies)
    return stub


def build_proxy(client: FakeMCPClient, tool: Tool) -> MCPToolProxy:
    """Build a real :class:`MCPToolProxy` backed by ``client``.

    Imports `_build_proxy` and `_ToolsetState` lazily so this module
    stays cheap when a test only wants the fake client.
    """
    from hexgate.mcp.proxy import _build_proxy as build
    from hexgate.mcp.proxy import _ToolsetState

    return build(_ToolsetState(client), client.config, tool)  # type: ignore[arg-type]
