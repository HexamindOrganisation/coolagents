"""End-to-end tests for the egress proxy over real loopback sockets.

Uses ``httpx.AsyncClient`` (awaited) for the plain-HTTP path and raw asyncio
streams for the CONNECT tunnel path. The proxy runs on the test's own event
loop, so every client must be async — a blocking sync request would deadlock.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from hexgate.egress.proxy import EgressProxy, egress_guard
from hexgate.runtime.context import HexgateContext
from hexgate.security.enforcer import build_enforcer
from hexgate.security.policy_set import load_policy_set_from_dict


def _enforcer(allowed_host: str):
    policy = load_policy_set_from_dict(
        {
            "roles": {
                "agent": {
                    "default_policy": {"mode": "deny"},
                    "tools": {
                        "net.http_request": {
                            "mode": "allow",
                            "constraints": [f'args.host == "{allowed_host}"'],
                        }
                    },
                }
            }
        }
    )
    return build_enforcer(policy, agent_name="test-egress")


def _proxy(allowed_host: str) -> EgressProxy:
    return EgressProxy(
        _enforcer(allowed_host), HexgateContext(user_id="u", user_roles=["agent"])
    )


async def _start_http_upstream() -> tuple[asyncio.AbstractServer, int]:
    """A minimal HTTP/1.1 server that answers every request with 'hello'."""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while await reader.readline() not in (b"\r\n", b""):
            pass
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _start_tcp_echo() -> tuple[asyncio.AbstractServer, int]:
    """A raw TCP echo server — stands in for a TLS origin behind CONNECT."""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while data := await reader.read(1024):
                writer.write(data)
                await writer.drain()
        except OSError:
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_http_forward_allowed() -> None:
    upstream, up_port = await _start_http_upstream()
    proxy = _proxy("127.0.0.1")
    await proxy.start()
    try:
        async with httpx.AsyncClient(
            proxy=f"http://127.0.0.1:{proxy.port}", trust_env=False, timeout=5
        ) as client:
            response = await client.get(f"http://127.0.0.1:{up_port}/")
        assert response.status_code == 200
        assert response.text == "hello"
    finally:
        await proxy.stop()
        upstream.close()
        await upstream.wait_closed()


async def _start_reflect_upstream() -> tuple[asyncio.AbstractServer, int]:
    """An HTTP server that echoes the request line it received in the body."""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request_line = await reader.readline()
        while await reader.readline() not in (b"\r\n", b""):
            pass
        body = request_line
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
            % (len(body), body)
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_http_forward_preserves_query() -> None:
    upstream, up_port = await _start_reflect_upstream()
    proxy = _proxy("127.0.0.1")
    await proxy.start()
    try:
        async with httpx.AsyncClient(
            proxy=f"http://127.0.0.1:{proxy.port}", trust_env=False, timeout=5
        ) as client:
            response = await client.get(f"http://127.0.0.1:{up_port}/search?q=hi&n=2")
        # The upstream echoes the origin-form request line it received.
        assert "/search?q=hi&n=2" in response.text
    finally:
        await proxy.stop()
        upstream.close()
        await upstream.wait_closed()


async def test_egress_guard_reentrancy_raises() -> None:
    enforcer = _enforcer("127.0.0.1")
    context = HexgateContext(user_id="u", user_roles=["agent"])
    async with egress_guard(enforcer, context):
        with pytest.raises(RuntimeError, match="already active"):
            async with egress_guard(enforcer, context):
                pass
    # The guard flag is released after the outer exits — a fresh guard works.
    async with egress_guard(enforcer, context):
        pass


async def test_http_forward_denied_returns_403() -> None:
    upstream, up_port = await _start_http_upstream()
    proxy = _proxy("allowed.example.com")  # upstream host 127.0.0.1 not allowed
    await proxy.start()
    try:
        async with httpx.AsyncClient(
            proxy=f"http://127.0.0.1:{proxy.port}", trust_env=False, timeout=5
        ) as client:
            response = await client.get(f"http://127.0.0.1:{up_port}/")
        assert response.status_code == 403
    finally:
        await proxy.stop()
        upstream.close()
        await upstream.wait_closed()


async def test_connect_allowed_tunnels_bytes() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy("127.0.0.1")
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"200" in status
        await asyncio.wait_for(reader.readline(), timeout=5)  # trailing blank line
        writer.write(b"ping")
        await writer.drain()
        echoed = await asyncio.wait_for(reader.readexactly(4), timeout=5)
        assert echoed == b"ping"
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_connect_denied_returns_403() -> None:
    proxy = _proxy("allowed.example.com")
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"CONNECT blocked.example.com:443 HTTP/1.1\r\n\r\n")
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"403" in status
        writer.close()
    finally:
        await proxy.stop()


async def test_malformed_request_line_returns_400() -> None:
    proxy = _proxy("anything")
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"GARBAGE\r\n\r\n")
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"400" in status
        writer.close()
    finally:
        await proxy.stop()


async def test_connect_upstream_unreachable_returns_502() -> None:
    # Grab a port, then close its server so the upstream connect is refused.
    dead, dead_port = await _start_tcp_echo()
    dead.close()
    await dead.wait_closed()
    proxy = _proxy("127.0.0.1")
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(f"CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        status = await asyncio.wait_for(reader.readline(), timeout=5)
        assert b"502" in status
        writer.close()
    finally:
        await proxy.stop()


async def test_stop_cancels_inflight_tunnel() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy("127.0.0.1")
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n\r\n".encode())
    await writer.drain()
    assert b"200" in await asyncio.wait_for(reader.readline(), timeout=5)
    await asyncio.wait_for(reader.readline(), timeout=5)  # trailing blank line
    try:
        # The tunnel is open. stop() must cancel the handler, not leave it
        # relaying — the client then sees EOF.
        await proxy.stop()
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        echo.close()
        await echo.wait_closed()


def test_port_before_start_raises() -> None:
    proxy = _proxy("anything")
    with pytest.raises(RuntimeError):
        _ = proxy.port
