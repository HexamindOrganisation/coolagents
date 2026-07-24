"""Raw-TCP reachability gate — decide whether the agent may open a connection.

``TcpEgressProxy`` is the non-HTTP counterpart of :class:`~hexgate.egress.proxy.EgressProxy`.
It forwards one TCP target (a database, cache, broker, anything) and asks the
same :class:`~hexgate.egress.gate.Gate` — via the ``net.tcp_connect`` tool —
whether *this* caller may open the connection, before any bytes flow. On allow
it opens a raw tunnel and relays bytes untouched (TLS included, never decrypted);
on deny it drops the socket.

Routing differs from the HTTP proxy: a database driver speaks its own binary
protocol and ignores ``HTTP_PROXY``, so there is no env-var hook. The caller
points its connection string at ``proxy.host:proxy.port`` (or an OS-level
redirect forces traffic here). Like the HTTP proxy, that makes it intent-shaping
unless a sandbox forces all egress through it.

Scope: reachability only. It gates the destination host/port, not the SQL or
commands sent over the connection. Inspecting those would need a
protocol-aware, connection-terminating proxy per database, which this is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from hexgate.approvals import ApprovalHandler
from hexgate.egress.gate import Gate
from hexgate.egress.server import ProxyServer
from hexgate.egress.wire import close_writer, open_upstream, pipe
from hexgate.runtime.context import User
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.network import NET_TCP_CONNECT

_log = logging.getLogger(__name__)


class TcpEgressProxy(ProxyServer):
    """An asyncio TCP proxy that authorizes each connection to one target.

    One proxy forwards one ``(host, port)`` target; the ``user`` fixes the
    identity every decision is attributed to. Start it, point a client at
    ``proxy.host:proxy.port``, and each accepted connection is gated on
    ``net.tcp_connect`` before it is tunnelled to the target. Socket lifecycle
    (bind / accept / teardown) is inherited from :class:`ProxyServer`.
    """

    def __init__(
        self,
        enforcer: PolicyEnforcer,
        user: User,
        *,
        target: tuple[str, int],
        host: str = "127.0.0.1",
        port: int = 0,
        approval_handler: ApprovalHandler | None = None,
    ) -> None:
        super().__init__(host=host, port=port)
        self._gate = Gate(
            enforcer, user, tool=NET_TCP_CONNECT, approval_handler=approval_handler
        )
        self._target = target

    def _log_listening(self) -> None:
        _log.info(
            "tcp egress proxy on %s:%s -> %s:%s",
            self._host,
            self._port,
            *self._target,
        )

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        # Task tracking and the generic error-close are handled by ProxyServer.
        host, port = self._target
        result = await self._gate.check({"host": host, "port": port, "protocol": "tcp"})
        if not result.allowed:
            _log.info("tcp egress DENY %s:%s — %s", host, port, result.decision.reason)
            # Raw TCP has no error frame to send; drop the socket. The client
            # sees a closed connection, which its driver surfaces as an error.
            close_writer(writer)
            return
        try:
            upstream_reader, upstream_writer = await open_upstream(host, port)
        except (OSError, TimeoutError) as exc:
            _log.info(
                "tcp egress upstream connect failed for %s:%s: %s", host, port, exc
            )
            close_writer(writer)
            return
        await pipe(reader, writer, upstream_reader, upstream_writer)


@contextlib.asynccontextmanager
async def tcp_egress_guard(
    enforcer: PolicyEnforcer,
    user: User,
    *,
    target: tuple[str, int],
    host: str = "127.0.0.1",
    port: int = 0,
    approval_handler: ApprovalHandler | None = None,
) -> AsyncIterator[TcpEgressProxy]:
    """Start a :class:`TcpEgressProxy` for ``target`` and stop it on exit.

    Unlike :func:`~hexgate.egress.proxy.egress_guard`, there is no env-var hook
    to set (TCP clients don't read ``HTTP_PROXY``). The caller reads
    ``proxy.host`` / ``proxy.port`` from the yielded proxy and points its
    connection string there.

        async with tcp_egress_guard(enforcer, user, target=("db.internal", 5432)) as p:
            dsn = f"postgresql://user@{p.host}:{p.port}/app"
            ...
    """
    proxy = TcpEgressProxy(
        enforcer,
        user,
        target=target,
        host=host,
        port=port,
        approval_handler=approval_handler,
    )
    await proxy.start()
    try:
        yield proxy
    finally:
        await proxy.stop()
