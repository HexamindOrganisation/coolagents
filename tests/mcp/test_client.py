"""Tests for :class:`MCPClient` — the real lifecycle, with the transport
and JSON-RPC session boundaries faked.

The existing tests in ``test_proxy.py`` substitute a fake MCPClient
entirely, which leaves the wrapper's own lifecycle logic (transport
opening, env passthrough, pagination, timeout building, error
preservation on partial-open failure) uncovered. This file fills that
gap by monkeypatching the SDK's :class:`ClientSession`, ``stdio_client``,
and ``streamablehttp_client`` with controllable stand-ins, then running
the real :class:`MCPClient` against them.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import timedelta
from typing import Any

import pytest
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

from hexgate.mcp import MCPServerConfig
from hexgate.mcp.client import MCPClient, MCPConnectionError

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _FakeSession:
    """Stand-in for :class:`mcp.ClientSession`.

    Provides the async-context-manager + ``initialize``/``list_tools``/
    ``call_tool`` surface that ``MCPClient`` consumes. Tests inject
    behavior via ``queue_*`` / ``raise_on_initialize`` etc.
    """

    def __init__(self, read: Any = None, write: Any = None, **_kwargs: Any) -> None:
        self.read = read
        self.write = write
        # Scripted behavior:
        self._initialize_error: BaseException | None = None
        self._tools_pages: list[ListToolsResult] = []
        self._call_results: dict[str, CallToolResult | BaseException] = {}
        # Recorded observations:
        self.initialize_called = False
        self.list_calls: list[str | None] = []
        self.call_calls: list[tuple[str, dict, timedelta | None]] = []
        self.aexit_exc_type: type[BaseException] | None | object = _UNSET

    # --- scripting helpers ---

    def raise_on_initialize(self, exc: BaseException) -> None:
        self._initialize_error = exc

    def queue_tools_page(self, tools: list[Tool], *, next_cursor: str | None) -> None:
        self._tools_pages.append(ListToolsResult(tools=tools, nextCursor=next_cursor))

    def script_call(self, name: str, result: CallToolResult | BaseException) -> None:
        self._call_results[name] = result

    # --- ClientSession surface ---

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.aexit_exc_type = exc_type

    async def initialize(self) -> None:
        self.initialize_called = True
        if self._initialize_error is not None:
            raise self._initialize_error

    async def list_tools(self, cursor: str | None = None) -> ListToolsResult:
        self.list_calls.append(cursor)
        if not self._tools_pages:
            return ListToolsResult(tools=[], nextCursor=None)
        return self._tools_pages.pop(0)

    async def call_tool(
        self,
        name: str,
        arguments: dict,
        read_timeout_seconds: timedelta | None = None,
        **_kwargs: Any,
    ) -> CallToolResult:
        self.call_calls.append((name, dict(arguments), read_timeout_seconds))
        result = self._call_results.get(name)
        if isinstance(result, BaseException):
            raise result
        if result is None:
            return CallToolResult(
                content=[TextContent(type="text", text="default")], isError=False
            )
        return result


_UNSET = object()


class _StdioParamsRecorder:
    """Captures whatever ``StdioServerParameters(...)`` is called with."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return ("STDIO_PARAMS", kwargs)


def _patch_transports(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: _FakeSession,
    stdio_recorder: _StdioParamsRecorder | None = None,
    http_recorder: list[dict[str, Any]] | None = None,
    transport_aexit_error: BaseException | None = None,
) -> None:
    """Replace ClientSession, stdio_client, streamablehttp_client, and
    StdioServerParameters so MCPClient runs against in-memory fakes."""

    def _session_factory(read: Any, write: Any) -> _FakeSession:
        session.read = read
        session.write = write
        return session

    monkeypatch.setattr("hexgate.mcp.client.ClientSession", _session_factory)

    @contextlib.asynccontextmanager
    async def _fake_stdio_client(params: Any):
        try:
            yield ("READ", "WRITE")
        finally:
            if transport_aexit_error is not None:
                raise transport_aexit_error

    @contextlib.asynccontextmanager
    async def _fake_http_client(
        url: str, headers: dict | None = None, **_kwargs: Any
    ) -> Any:
        if http_recorder is not None:
            http_recorder.append({"url": url, "headers": headers})
        yield ("READ", "WRITE", lambda: None)

    monkeypatch.setattr("hexgate.mcp.client.stdio_client", _fake_stdio_client)
    monkeypatch.setattr("hexgate.mcp.client.streamablehttp_client", _fake_http_client)
    if stdio_recorder is not None:
        monkeypatch.setattr("hexgate.mcp.client.StdioServerParameters", stdio_recorder)


# ---------------------------------------------------------------------------
# Happy-path lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aenter_runs_initialize_and_caches_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    async with MCPClient(cfg) as client:
        assert client.config is cfg
        assert session.initialize_called is True


@pytest.mark.asyncio
async def test_aexit_forwards_suppression_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If a transport's __aexit__ returns truthy (claims to suppress the
    exception), MCPClient must forward that truth so the with-block sees
    suppression. Dropping the return value would silently override the
    transport's decision."""

    class _SuppressingSession(_FakeSession):
        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
            await super().__aexit__(exc_type, exc, tb)
            return True  # claim suppression

    session = _SuppressingSession()
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    # The session claims suppression — the RuntimeError must NOT escape.
    async with MCPClient(cfg):
        raise RuntimeError("should be suppressed by the inner CM")


@pytest.mark.asyncio
async def test_aexit_forwards_exc_info_to_inner_stack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stdio transport branches between graceful-close and SIGKILL
    based on whether its __aexit__ sees an exception. Dropping exc_info
    was finding #9 in the code review — pin the forwarding here."""
    session = _FakeSession()
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    with pytest.raises(RuntimeError, match="boom"):
        async with MCPClient(cfg):
            raise RuntimeError("boom")

    assert session.aexit_exc_type is RuntimeError


# ---------------------------------------------------------------------------
# __aenter__ failure paths (findings #8, partial-open teardown)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_aenter_wraps_initialize_failure_as_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    session.raise_on_initialize(RuntimeError("bad protocol version"))
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="myserver", transport="stdio", command="srv")

    with pytest.raises(MCPConnectionError, match="myserver") as exc_info:
        async with MCPClient(cfg):
            pass

    # The original is chained, not masked.
    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert "bad protocol version" in str(exc_info.value.__cause__)


@pytest.mark.asyncio
async def test_aenter_preserves_original_when_transport_teardown_also_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding #8: if cleanup itself raises during partial-open teardown,
    the secondary error must NOT mask the real connection failure."""
    session = _FakeSession()
    session.raise_on_initialize(RuntimeError("real reason: handshake rejected"))
    _patch_transports(
        monkeypatch,
        session=session,
        transport_aexit_error=BrokenPipeError("cleanup broke too"),
    )
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    with pytest.raises(MCPConnectionError) as exc_info:
        async with MCPClient(cfg):
            pass

    # The user sees the connection error with the REAL reason chained,
    # not the BrokenPipeError from the secondary teardown failure.
    assert "real reason" in str(exc_info.value.__cause__)


@pytest.mark.asyncio
async def test_aenter_propagates_cancelled_error_unwrapped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CancelledError must NOT be wrapped in MCPConnectionError — async
    cancellation depends on the bare exception type propagating."""
    session = _FakeSession()
    session.raise_on_initialize(asyncio.CancelledError())
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    with pytest.raises(asyncio.CancelledError):
        async with MCPClient(cfg):
            pass


# ---------------------------------------------------------------------------
# list_tools pagination (finding #6)
# ---------------------------------------------------------------------------


def _tool(name: str) -> Tool:
    return Tool(name=name, inputSchema={"type": "object", "properties": {}})


@pytest.mark.asyncio
async def test_list_tools_walks_next_cursor_until_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An MCP server that paginates `tools/list` (>page-size catalog)
    silently lost tools past page 1 before the fix — finding #6."""
    session = _FakeSession()
    session.queue_tools_page([_tool("a"), _tool("b")], next_cursor="page-2")
    session.queue_tools_page([_tool("c")], next_cursor="page-3")
    session.queue_tools_page([_tool("d")], next_cursor=None)
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    async with MCPClient(cfg) as client:
        names = [t.name for t in await client.list_tools()]

    assert names == ["a", "b", "c", "d"]
    assert session.list_calls == [None, "page-2", "page-3"]


@pytest.mark.asyncio
async def test_list_tools_single_page_makes_one_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    session.queue_tools_page([_tool("only")], next_cursor=None)
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    async with MCPClient(cfg) as client:
        names = [t.name for t in await client.list_tools()]

    assert names == ["only"]
    assert session.list_calls == [None]


# ---------------------------------------------------------------------------
# call_tool timeout (finding #5)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_passes_configured_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wedged server can't stall the agent indefinitely (finding #5).
    The config's call_timeout_seconds must reach the SDK as a timedelta."""
    session = _FakeSession()
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(
        name="x", transport="stdio", command="srv", call_timeout_seconds=2.5
    )

    async with MCPClient(cfg) as client:
        await client.call_tool("ping", {"a": 1})

    assert len(session.call_calls) == 1
    name, args, timeout = session.call_calls[0]
    assert name == "ping"
    assert args == {"a": 1}
    assert timeout == timedelta(seconds=2.5)


@pytest.mark.asyncio
async def test_call_tool_passes_none_when_timeout_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """call_timeout_seconds=None must reach the SDK as None — explicit
    'no timeout' is different from forgetting to pass one."""
    session = _FakeSession()
    _patch_transports(monkeypatch, session=session)
    cfg = MCPServerConfig(
        name="x", transport="stdio", command="srv", call_timeout_seconds=None
    )

    async with MCPClient(cfg) as client:
        await client.call_tool("ping", None)

    _name, args, timeout = session.call_calls[0]
    assert args == {}  # `None` normalized to empty dict
    assert timeout is None


# ---------------------------------------------------------------------------
# env semantics (finding #3) — the security-critical bit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stdio_env_none_passes_through_for_parent_inheritance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """env=None on the config → env=None on StdioServerParameters → SDK
    inherits the parent process env (default behavior)."""
    session = _FakeSession()
    recorder = _StdioParamsRecorder()
    _patch_transports(monkeypatch, session=session, stdio_recorder=recorder)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")

    async with MCPClient(cfg):
        pass

    assert len(recorder.calls) == 1
    assert recorder.calls[0]["env"] is None


@pytest.mark.asyncio
async def test_stdio_env_empty_dict_passes_through_as_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """env={} (explicit sandbox) MUST reach StdioServerParameters as {},
    not collapse to None. The collapse was finding #3 — a security
    regression that exposed PATH / AWS_* to the MCP subprocess despite
    the caller's explicit empty-env request."""
    session = _FakeSession()
    recorder = _StdioParamsRecorder()
    _patch_transports(monkeypatch, session=session, stdio_recorder=recorder)
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv", env={})

    async with MCPClient(cfg):
        pass

    assert len(recorder.calls) == 1
    assert recorder.calls[0]["env"] == {}  # NOT None


@pytest.mark.asyncio
async def test_stdio_env_explicit_dict_passes_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    recorder = _StdioParamsRecorder()
    _patch_transports(monkeypatch, session=session, stdio_recorder=recorder)
    cfg = MCPServerConfig(
        name="x",
        transport="stdio",
        command="srv",
        env={"SLACK_TOKEN": "abc", "DEBUG": "1"},
    )

    async with MCPClient(cfg):
        pass

    assert recorder.calls[0]["env"] == {"SLACK_TOKEN": "abc", "DEBUG": "1"}


@pytest.mark.asyncio
async def test_stdio_command_and_args_forwarded_to_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _FakeSession()
    recorder = _StdioParamsRecorder()
    _patch_transports(monkeypatch, session=session, stdio_recorder=recorder)
    cfg = MCPServerConfig(
        name="x",
        transport="stdio",
        command="myserver",
        args=("--verbose", "--port", "9000"),
    )

    async with MCPClient(cfg):
        pass

    params = recorder.calls[0]
    assert params["command"] == "myserver"
    assert params["args"] == ["--verbose", "--port", "9000"]


# ---------------------------------------------------------------------------
# http transport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_transport_forwards_url_and_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The streamable-HTTP transport must receive url + headers verbatim
    from the config — auth bearer tokens etc. ride on the headers dict."""
    session = _FakeSession()
    captured: list[dict[str, Any]] = []
    _patch_transports(monkeypatch, session=session, http_recorder=captured)
    cfg = MCPServerConfig(
        name="x",
        transport="http",
        url="https://mcp.example.com/v1",
        headers={"Authorization": "Bearer t"},
    )

    async with MCPClient(cfg):
        pass

    assert captured == [
        {"url": "https://mcp.example.com/v1", "headers": {"Authorization": "Bearer t"}}
    ]


# ---------------------------------------------------------------------------
# _require_session error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tools_before_aenter_raises_helpful_error() -> None:
    """Calling list_tools/call_tool on an unentered client must surface
    the 'use async with MCPClient(...)' hint, not a confusing AttributeError."""
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")
    client = MCPClient(cfg)
    with pytest.raises(MCPConnectionError, match="async with"):
        await client.list_tools()


@pytest.mark.asyncio
async def test_call_tool_before_aenter_raises_helpful_error() -> None:
    cfg = MCPServerConfig(name="x", transport="stdio", command="srv")
    client = MCPClient(cfg)
    with pytest.raises(MCPConnectionError, match="async with"):
        await client.call_tool("ping", {})
