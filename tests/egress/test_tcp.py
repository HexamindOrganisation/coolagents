"""End-to-end tests for the raw-TCP reachability gate over loopback sockets.

A TCP echo server stands in for the upstream service (a database, say). The
proxy runs on the test's own event loop, so every client is async.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from hexgate.egress.tcp import TcpEgressProxy, tcp_egress_guard
from hexgate.runtime.context import User
from hexgate.security.decision import Decision
from hexgate.security.enforcer import build_enforcer
from hexgate.security.policy_set import load_policy_set_from_dict


def _enforcer(*, mode="allow", constraints=(), observer=None):
    policy = load_policy_set_from_dict(
        {
            "roles": {
                "agent": {
                    "default_policy": {"mode": "deny"},
                    "tools": {
                        "net.tcp_connect": {
                            "mode": mode,
                            "constraints": list(constraints),
                        }
                    },
                }
            }
        }
    )
    return build_enforcer(policy, agent_name="test-tcp", decision_observer=observer)


async def _start_tcp_echo() -> tuple[asyncio.AbstractServer, int]:
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


def _proxy(enforcer, target, **kw) -> TcpEgressProxy:
    return TcpEgressProxy(
        enforcer, User(user_id="u", role="agent"), target=target, **kw
    )


async def test_allow_tunnels_bytes() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(constraints=['args.host == "127.0.0.1"']), ("127.0.0.1", echo_port)
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"ping")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(4), timeout=5) == b"ping"
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_deny_host_drops_connection() -> None:
    echo, echo_port = await _start_tcp_echo()
    # Policy allows a different host, so this target is denied.
    proxy = _proxy(
        _enforcer(constraints=['args.host == "db.internal"']), ("127.0.0.1", echo_port)
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        # Accepted, then dropped on deny -> the client sees EOF, no echo.
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_deny_port_drops_connection() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(constraints=['args.host == "127.0.0.1"', "args.port in [5432]"]),
        ("127.0.0.1", echo_port),  # echo_port is not 5432 -> deny
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_approval_bool_true_allows() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(mode="approval_required"),
        ("127.0.0.1", echo_port),
        approval_handler=True,
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"hi")
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(2), timeout=5) == b"hi"
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_approval_bool_false_denies() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(mode="approval_required"),
        ("127.0.0.1", echo_port),
        approval_handler=False,
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()


async def test_binds_identity_and_records_tcp_tool() -> None:
    seen: list[Decision] = []
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(constraints=['args.host == "127.0.0.1"'], observer=seen.append),
        ("127.0.0.1", echo_port),
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(b"x")
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(1), timeout=5)
        writer.close()
    finally:
        await proxy.stop()
        echo.close()
        await echo.wait_closed()
    assert len(seen) == 1
    assert seen[0].tool_name == "net.tcp_connect"
    assert seen[0].role == "agent"
    assert seen[0].arguments == {
        "host": "127.0.0.1",
        "port": echo_port,
        "protocol": "tcp",
    }


async def test_upstream_unreachable_drops_connection() -> None:
    dead, dead_port = await _start_tcp_echo()
    dead.close()
    await dead.wait_closed()
    proxy = _proxy(
        _enforcer(constraints=['args.host == "127.0.0.1"']), ("127.0.0.1", dead_port)
    )
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        await proxy.stop()


async def test_stop_cancels_inflight_tunnel() -> None:
    echo, echo_port = await _start_tcp_echo()
    proxy = _proxy(
        _enforcer(constraints=['args.host == "127.0.0.1"']), ("127.0.0.1", echo_port)
    )
    await proxy.start()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    writer.write(b"hello")
    await writer.drain()
    assert await asyncio.wait_for(reader.readexactly(5), timeout=5) == b"hello"
    try:
        await proxy.stop()  # must cancel the open tunnel, not leave it relaying
        assert await asyncio.wait_for(reader.read(100), timeout=5) == b""
        writer.close()
    finally:
        echo.close()
        await echo.wait_closed()


async def test_tcp_egress_guard_yields_running_proxy() -> None:
    echo, echo_port = await _start_tcp_echo()
    enforcer = _enforcer(constraints=['args.host == "127.0.0.1"'])
    try:
        async with tcp_egress_guard(
            enforcer, User(user_id="u", role="agent"), target=("127.0.0.1", echo_port)
        ) as proxy:
            reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
            writer.write(b"yo")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2), timeout=5) == b"yo"
            writer.close()
    finally:
        echo.close()
        await echo.wait_closed()


async def test_guard_redirects_env_to_proxy_and_removes_after() -> None:
    echo, echo_port = await _start_tcp_echo()
    enforcer = _enforcer(constraints=['args.host == "127.0.0.1"'])
    for var in ("PGHOST", "PGPORT"):
        os.environ.pop(var, None)  # start from a clean slate
    try:
        async with tcp_egress_guard(
            enforcer,
            User(user_id="u", role="agent"),
            target=("127.0.0.1", echo_port),
            env={"PGHOST": "{host}", "PGPORT": "{port}"},
        ) as proxy:
            assert os.environ["PGHOST"] == proxy.host
            assert os.environ["PGPORT"] == str(proxy.port)
        # Not set before the guard, so removed on exit.
        assert "PGHOST" not in os.environ
        assert "PGPORT" not in os.environ
    finally:
        for var in ("PGHOST", "PGPORT"):
            os.environ.pop(var, None)
        echo.close()
        await echo.wait_closed()


async def test_guard_restores_preexisting_env() -> None:
    echo, echo_port = await _start_tcp_echo()
    enforcer = _enforcer(constraints=['args.host == "127.0.0.1"'])
    os.environ["DATABASE_URL"] = "postgresql://real/db"
    try:
        async with tcp_egress_guard(
            enforcer,
            User(user_id="u", role="agent"),
            target=("127.0.0.1", echo_port),
            env={"DATABASE_URL": "postgresql://app@{host}:{port}/db"},
        ) as proxy:
            assert (
                os.environ["DATABASE_URL"]
                == f"postgresql://app@{proxy.host}:{proxy.port}/db"
            )
        # Restored to the prior value, not removed.
        assert os.environ["DATABASE_URL"] == "postgresql://real/db"
    finally:
        os.environ.pop("DATABASE_URL", None)
        echo.close()
        await echo.wait_closed()


def test_port_before_start_raises() -> None:
    proxy = _proxy(_enforcer(constraints=['args.host == "x"']), ("x", 1))
    with pytest.raises(RuntimeError):
        _ = proxy.port
