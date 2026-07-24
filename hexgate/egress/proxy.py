"""In-process forward proxy that gates outbound egress through policy.

``EgressProxy`` is an optional second enforcement plane. Point an agent's
process at it (via ``HTTP_PROXY`` / ``HTTPS_PROXY``, which ``egress_guard``
sets for you) and every outbound HTTP(S) request is routed through the same
:class:`~hexgate.security.enforcer.PolicyEnforcer` that gates tool calls,
mapped to the synthetic ``net.http_request`` tool. See the network-egress
concept doc (``docs/concepts/egress.mdx``).

Scope (Tier 1): host-level filtering. HTTPS is gated on the ``CONNECT`` host;
the tunnel relays ciphertext untouched (no TLS interception). Like
``runtime/command_policy.py``, the env-proxy hookup is *intent-shaping, not a
hard boundary* — a tool that unsets the proxy env vars bypasses it. A sandbox
that forces all egress through the proxy is the hard-boundary follow-up.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator, Sequence

from hexgate.approvals import ApprovalHandler
from hexgate.egress.gate import Gate
from hexgate.egress.model import split_authority
from hexgate.egress.transport import Transport, TunnelTransport
from hexgate.egress.wire import close_writer, parse_request_line, read_headers, refuse
from hexgate.runtime.context import User
from hexgate.security.enforcer import PolicyEnforcer

_log = logging.getLogger(__name__)

_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
)

# Only one egress_guard may be live per process: it mutates global proxy env
# vars, so a second (nested or concurrent) guard would clobber the first's and
# restore stale values on exit. We fail loud rather than corrupt silently.
_guard_active = False


class EgressProxy:
    """An asyncio forward proxy that authorizes each request via ``Gate``.

    One proxy serves one agent run: the ``user`` fixes the identity every
    egress decision is attributed to. Start it, point the process's HTTP
    clients at ``http://{host}:{port}``, and every request is gated.
    """

    def __init__(
        self,
        enforcer: PolicyEnforcer,
        user: User,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        approval_handler: ApprovalHandler | None = None,
        transport: Transport | None = None,
    ) -> None:
        self._gate = Gate(enforcer, user, approval_handler=approval_handler)
        self._transport: Transport = (
            transport if transport is not None else TunnelTransport()
        )
        self._host = host
        self._requested_port = port
        self._server: asyncio.AbstractServer | None = None
        self._port: int | None = None
        # In-flight connection-handler tasks, so stop() can cancel open tunnels
        # instead of leaving them relaying after the guard restores env vars.
        self._conns: set[asyncio.Task[None]] = set()

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        """The bound port. Raises if the proxy has not been started."""
        if self._port is None:
            raise RuntimeError("EgressProxy is not started; call start() first")
        return self._port

    async def start(self) -> None:
        """Bind and begin accepting connections. Idempotent."""
        if self._server is not None:
            return
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._requested_port
        )
        self._port = self._server.sockets[0].getsockname()[1]
        _log.info("egress proxy listening on %s:%s", self._host, self._port)

    async def stop(self) -> None:
        """Stop accepting, cancel open connections, close the socket. Idempotent."""
        if self._server is None:
            return
        self._server.close()
        # Cancel handlers still relaying (e.g. an open CONNECT tunnel) BEFORE
        # wait_closed(): on Python 3.12+ wait_closed() blocks until active
        # connections finish, so an open tunnel would otherwise deadlock it.
        for task in list(self._conns):
            task.cancel()
        if self._conns:
            await asyncio.gather(*self._conns, return_exceptions=True)
            self._conns.clear()
        with contextlib.suppress(Exception):
            await self._server.wait_closed()
        self._server = None
        self._port = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._conns.add(task)
        try:
            request_line = await reader.readline()
            if not request_line:
                close_writer(writer)
                return
            method, target = parse_request_line(request_line)
            if method == "CONNECT":
                host, port = split_authority(target)
                await read_headers(reader)  # drain the CONNECT request headers
                await self._transport.handle_connect(
                    host, port, reader, writer, self._gate
                )
            else:
                header_block = await read_headers(reader)
                await self._transport.handle_http(
                    method, target, header_block, reader, writer, self._gate
                )
        except ValueError:
            # Malformed request line / CONNECT target / oversized headers.
            await refuse(writer, 400, "Bad Request", "malformed request")
        except Exception:
            _log.exception("egress proxy connection handler failed")
            close_writer(writer)
        finally:
            if task is not None:
                self._conns.discard(task)


@contextlib.asynccontextmanager
async def egress_guard(
    enforcer: PolicyEnforcer,
    user: User,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    approval_handler: ApprovalHandler | None = None,
    no_proxy: Sequence[str] = (),
) -> AsyncIterator[EgressProxy]:
    """Start an :class:`EgressProxy` and point this process's HTTP clients at it.

    Sets ``HTTP_PROXY`` / ``HTTPS_PROXY`` (both cases) for the duration of the
    block and restores the prior environment on exit. ``no_proxy`` hosts are
    added to ``NO_PROXY`` so they bypass the proxy — **always include the
    Hexgate control-plane host** (e.g. ``app.hexgate.ai``) when audit is
    enabled, otherwise the audit sender's own POSTs would route through the
    proxy and be denied (or recurse). Loopback is excluded by default.

    Only one guard may be live per process (it mutates global env vars) — a
    nested or concurrent :func:`egress_guard` raises ``RuntimeError`` rather
    than silently clobbering the outer guard's proxy configuration.

    Yields the running proxy (``proxy.port`` is the bound port).
    """
    global _guard_active
    if _guard_active:
        raise RuntimeError(
            "an egress_guard is already active in this process; nested or "
            "concurrent egress_guard is unsupported because it mutates global "
            "HTTP(S)_PROXY env vars. Use one guard per process, or drive "
            "EgressProxy directly with an explicitly-configured client."
        )
    _guard_active = True
    proxy = EgressProxy(
        enforcer, user, host=host, port=port, approval_handler=approval_handler
    )
    saved = {name: os.environ.get(name) for name in _PROXY_ENV_VARS}
    try:
        await proxy.start()
        url = f"http://{proxy.host}:{proxy.port}"
        bypass = ",".join(["127.0.0.1", "localhost", *no_proxy])
        os.environ.update(
            HTTP_PROXY=url,
            HTTPS_PROXY=url,
            http_proxy=url,
            https_proxy=url,
            NO_PROXY=bypass,
            no_proxy=bypass,
        )
        yield proxy
    finally:
        for name, previous in saved.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        await proxy.stop()
        _guard_active = False
