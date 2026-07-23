"""HTTP proxy transports — the swappable byte-plumbing layer.

A transport owns what happens after a client connects: turn the proxied
request into enforcer args, ask the :class:`~hexgate.egress.gate.Gate` for a
decision, and either relay bytes or refuse. The enforcement seam (``Gate``) is
transport-agnostic, so Tier 2 TLS interception can land later as a second
:class:`Transport` implementation without touching the policy path.

:class:`TunnelTransport` is Tier 1: it host-filters HTTPS via the ``CONNECT``
verb (no TLS interception — the tunnel relays ciphertext untouched) and sees
the full URL on plain-HTTP requests.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol

from hexgate.egress.gate import Gate
from hexgate.egress.model import connect_to_args, http_to_args
from hexgate.egress.wire import pipe, refuse, strip_proxy_headers

_log = logging.getLogger(__name__)


class Transport(Protocol):
    """What happens after a client connects to the proxy.

    Implementations own the bytes; the enforcement decision is delegated to
    ``gate``. A future ``MitmTransport`` implements these same two methods.
    """

    async def handle_connect(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        gate: Gate,
    ) -> None: ...

    async def handle_http(
        self,
        method: str,
        target: str,
        header_block: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        gate: Gate,
    ) -> None: ...


class TunnelTransport:
    """Tier 1 transport: host-level filtering, no TLS interception."""

    async def handle_connect(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        gate: Gate,
    ) -> None:
        result = await gate.check(connect_to_args(host, port))
        if not result.allowed:
            _log.info(
                "egress DENY CONNECT %s:%s — %s", host, port, result.decision.reason
            )
            await refuse(
                writer, 403, "Forbidden", result.decision.reason or "denied by policy"
            )
            return
        upstream = await _open(host, port, writer)
        if upstream is None:
            return
        upstream_reader, upstream_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await pipe(reader, writer, upstream_reader, upstream_writer)

    async def handle_http(
        self,
        method: str,
        target: str,
        header_block: bytes,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        gate: Gate,
    ) -> None:
        args = http_to_args(method, target)
        result = await gate.check(args)
        if not result.allowed:
            _log.info("egress DENY %s %s — %s", method, target, result.decision.reason)
            await refuse(
                writer, 403, "Forbidden", result.decision.reason or "denied by policy"
            )
            return
        host = str(args["host"])
        port = int(args["port"])
        if not host:
            await refuse(writer, 400, "Bad Request", "proxy request missing host")
            return
        upstream = await _open(host, port, writer)
        if upstream is None:
            return
        upstream_reader, upstream_writer = upstream
        # Rewrite the absolute-form request line to origin-form (keeping the
        # query string) and forward the client's headers minus proxy-scoped
        # hop-by-hop ones, then relay the response and close.
        request_target = args["path"]
        if args.get("query"):
            request_target = f"{request_target}?{args['query']}"
        origin_line = f"{method} {request_target} HTTP/1.1\r\n".encode("latin-1")
        upstream_writer.write(origin_line + strip_proxy_headers(header_block))
        await upstream_writer.drain()
        await pipe(reader, writer, upstream_reader, upstream_writer)


async def _open(
    host: str, port: int, writer: asyncio.StreamWriter
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open an upstream connection, or write a 502 and return ``None``."""
    try:
        return await asyncio.open_connection(host, port)
    except OSError as exc:
        _log.info("egress upstream connect failed for %s:%s: %s", host, port, exc)
        await refuse(writer, 502, "Bad Gateway", f"cannot reach {host}:{port}")
        return None
