"""TCP egress reachability-gate demo — gate a DB-style connection by host/port.

No real database required: a local echo server stands in for the "database".
The first policy allows a raw TCP connection to it and the proxy tunnels the
bytes; the second policy only allows a different port, so the connection is
refused. Each decision is printed as it happens.

    python examples/tcp_egress_demo.py

The reachability gate decides host + port before any bytes flow, so it covers a
TLS'd database connection without inspecting it. It does not see the SQL sent
over the connection.
"""

from __future__ import annotations

import asyncio

from hexgate import HexgateContext, PolicyBuilder
from hexgate.egress import tcp_egress_guard
from hexgate.security.decision import Decision
from hexgate.security.enforcer import build_enforcer
from hexgate.security.policy_set import load_policy_set


def _print_decision(decision: Decision) -> None:
    mark = "✓" if decision.allowed else "✗"
    args = decision.arguments or {}
    print(
        f"  {mark} {decision.outcome.value:15} tcp {args.get('host')}:{args.get('port')}"
    )
    if not decision.allowed and decision.reason:
        print(f"      reason: {decision.reason}")


async def _start_mock_db() -> tuple[asyncio.AbstractServer, int]:
    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        while data := await reader.read(1024):
            writer.write(b"reply:" + data)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def _probe(policy, target: tuple[str, int]) -> None:
    enforcer = build_enforcer(
        load_policy_set(policy),
        agent_name="tcp-demo",
        decision_observer=_print_decision,
    )
    user = HexgateContext(user_id="demo", user_roles=["agent"])
    async with tcp_egress_guard(enforcer, user, target=target) as proxy:
        try:
            reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
            writer.write(b"SELECT 1")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(100), timeout=3)
            writer.close()
            print(f"  -> {data.decode() if data else 'connection dropped'}")
        except (OSError, asyncio.TimeoutError) as exc:
            print(f"  -> blocked: {type(exc).__name__}")


async def main() -> None:
    db, db_port = await _start_mock_db()
    try:
        print(f"\nallow tcp -> 127.0.0.1:{db_port}")
        await _probe(
            PolicyBuilder(default="deny")
            .net_tcp_allow(hosts=["127.0.0.1"], ports=[db_port])
            .build(),
            ("127.0.0.1", db_port),
        )
        print(f"\ndeny tcp -> 127.0.0.1:{db_port}  (policy only allows port 5432)")
        await _probe(
            PolicyBuilder(default="deny")
            .net_tcp_allow(hosts=["127.0.0.1"], ports=[5432])
            .build(),
            ("127.0.0.1", db_port),
        )
    finally:
        db.close()
        await db.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
