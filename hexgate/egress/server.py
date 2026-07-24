"""Shared asyncio server lifecycle for the egress proxies.

Both the HTTP (:class:`~hexgate.egress.proxy.EgressProxy`) and raw-TCP
(:class:`~hexgate.egress.tcp.TcpEgressProxy`) proxies bind a local socket, track
in-flight connection handlers, and tear them down on ``stop()`` in a specific
order: cancel the handlers *before* ``wait_closed()``, because on Python 3.12+
``wait_closed()`` blocks until active connections finish, so an open tunnel would
otherwise deadlock it. That lifecycle lives here once; a subclass implements only
:meth:`_handle` for the per-connection logic.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from hexgate.egress.wire import close_writer

_log = logging.getLogger(__name__)


class ProxyServer:
    """Bind / accept / teardown for a local forwarding proxy.

    Subclass and implement :meth:`_handle`. The base owns the socket lifecycle
    and in-flight-connection bookkeeping so the tricky teardown exists once.
    """

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        self._host = host
        self._requested_port = port
        self._server: asyncio.AbstractServer | None = None
        self._port: int | None = None
        # In-flight connection-handler tasks, so stop() can cancel open tunnels
        # instead of leaving them relaying after the caller has moved on.
        self._conns: set[asyncio.Task[None]] = set()

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        """The bound port. Raises if the proxy has not been started."""
        if self._port is None:
            raise RuntimeError(
                f"{type(self).__name__} is not started; call start() first"
            )
        return self._port

    async def start(self) -> None:
        """Bind and begin accepting connections. Idempotent."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._serve, self._host, self._requested_port
        )
        self._port = self._server.sockets[0].getsockname()[1]
        self._log_listening()

    async def stop(self) -> None:
        """Stop accepting, cancel open connections, close the socket. Idempotent."""
        if self._server is None:
            return
        self._server.close()
        # Cancel in-flight handlers (e.g. an open tunnel) BEFORE wait_closed():
        # on Python 3.12+ wait_closed() blocks until active connections finish,
        # so an open tunnel would otherwise deadlock it.
        for task in list(self._conns):
            task.cancel()
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)
            self._conns.clear()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()
        self._server = None
        self._port = None

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Register the handler task, run :meth:`_handle`, always tear down."""
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
        try:
            await self._handle(reader, writer)
        except Exception:
            _log.exception("%s connection handler failed", type(self).__name__)
            close_writer(writer)
        finally:
            if task is not None:
                self._conns.discard(task)

    def _log_listening(self) -> None:
        """Log where the proxy bound. Override to add detail (e.g. the target)."""
        _log.info("%s listening on %s:%s", type(self).__name__, self._host, self._port)

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle one accepted connection. Implemented by the subclass."""
        raise NotImplementedError
