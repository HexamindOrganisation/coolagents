"""Low-level HTTP/1.x wire helpers shared by the proxy and its transports.

Deliberately tiny and dependency-free — just enough to parse a proxied
request line, read a header block, relay bytes between two streams, and write
an error response. Not a general HTTP implementation.
"""

from __future__ import annotations

import asyncio
import contextlib

_CHUNK = 64 * 1024
_MAX_HEADER_BYTES = 64 * 1024


def parse_request_line(line: bytes) -> tuple[str, str]:
    """Parse ``b"METHOD target HTTP/1.1\\r\\n"`` into ``(method, target)``.

    Raises ``ValueError`` if the line is not three space-separated tokens, so
    the caller can fail the request closed with a 400.
    """
    try:
        text = line.decode("latin-1").rstrip("\r\n")
    except UnicodeDecodeError as exc:
        raise ValueError("non-latin1 request line") from exc
    parts = text.split(" ")
    if len(parts) != 3:
        raise ValueError(f"malformed request line: {text!r}")
    method, target, _version = parts
    return method.upper(), target


async def read_headers(reader: asyncio.StreamReader) -> bytes:
    """Read header lines through the terminating blank line; return them raw.

    The returned bytes include the final ``\\r\\n`` separator, so a plain-HTTP
    forwarder can concatenate a rewritten request line and send it verbatim.
    Raises ``ValueError`` (fail closed) if the client disconnects before the
    blank line, or if the block exceeds ``_MAX_HEADER_BYTES``, rather than
    forwarding a truncated request.
    """
    blocks: list[bytes] = []
    total = 0
    while True:
        line = await reader.readline()
        if line == b"":
            raise ValueError("connection closed before end of headers")
        blocks.append(line)
        if line in (b"\r\n", b"\n"):
            break
        total += len(line)
        if total > _MAX_HEADER_BYTES:
            raise ValueError("header block exceeds limit")
    return b"".join(blocks)


async def refuse(
    writer: asyncio.StreamWriter, status: int, phrase: str, detail: str
) -> None:
    """Write a short ``text/plain`` error response and close the connection."""
    body = detail.encode("utf-8", "replace")
    header = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("latin-1")
    with contextlib.suppress(OSError):
        writer.write(header + body)
        await writer.drain()
    close_writer(writer)


async def pipe(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    """Relay bytes both ways until either side closes, then tear both down.

    When one direction reaches EOF it half-closes the peer's write side
    (``write_eof``) so the peer observes the close and its own copy can finish
    — without this a keep-alive client would hang after the response arrives.
    """

    async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        # Catch Exception (not just OSError) so a relay hiccup ends this
        # direction cleanly instead of escaping through gather() and skipping
        # the teardown below. CancelledError is BaseException, so a genuine
        # cancellation still propagates and is handled by the finally.
        try:
            while data := await src.read(_CHUNK):
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(OSError):
                if dst.can_write_eof():
                    dst.write_eof()

    try:
        await asyncio.gather(
            copy(client_reader, upstream_writer),
            copy(upstream_reader, client_writer),
        )
    finally:
        # Always tear both sockets down — including on cancellation of pipe().
        close_writer(upstream_writer)
        close_writer(client_writer)


def strip_proxy_headers(header_block: bytes) -> bytes:
    """Drop proxy-scoped hop-by-hop headers before forwarding upstream.

    Removes ``Proxy-Connection`` / ``Proxy-Authorization`` (any ``Proxy-*``
    header) so they don't leak to the origin server (RFC 7230 §6.1). Other
    headers and the terminating blank line are preserved verbatim.
    """
    lines = header_block.split(b"\r\n")
    kept = [line for line in lines if not line.lower().startswith(b"proxy-")]
    return b"\r\n".join(kept)


_UPSTREAM_CONNECT_TIMEOUT = 10.0


async def open_upstream(
    host: str, port: int, *, timeout: float = _UPSTREAM_CONNECT_TIMEOUT
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP connection to an upstream, bounded by a connect timeout.

    Wraps :func:`asyncio.open_connection` in ``wait_for`` so a black-holed
    target (SYN dropped, no RST) can't hang the handler indefinitely. Raises
    ``OSError`` (refused / unreachable) or ``TimeoutError`` (no response within
    ``timeout``); callers treat both as "cannot reach upstream".
    """
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout)


def close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a stream writer, swallowing the error if it's already gone."""
    with contextlib.suppress(OSError):
        writer.close()
