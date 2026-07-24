"""Map a proxied HTTP request onto the synthetic ``net.http_request`` tool call.

The egress proxy translates each outbound request into the same
``(tool_name, arguments)`` shape the
:class:`~hexgate.security.enforcer.PolicyEnforcer` already evaluates for tool
calls, so network egress is gated by the same policy engine, ``Decision``
type, and audit path as everything else. Network egress is just another gated
tool. See the network-egress concept doc (``docs/concepts/egress.mdx``).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from hexgate.security.network import NET_HTTP_REQUEST as NET_TOOL

__all__ = ["NET_TOOL", "connect_to_args", "http_to_args", "split_authority"]

# ``NET_TOOL`` is the synthetic tool name every egress request is attributed to.
# Its canonical definition lives in ``hexgate.security.network`` so the policy
# layer (``PolicyBuilder.net_allow``) and the proxy share one source of truth.
# Add a policy entry under this name to allow egress; without one,
# ``default_policy`` (deny-by-default) applies and all egress is denied.


def connect_to_args(host: str, port: int) -> dict[str, Any]:
    """Build enforcer args for an HTTPS ``CONNECT`` tunnel request.

    Only the host and port are visible before TLS begins — the path, headers,
    and body are encrypted end-to-end — so constraints on an HTTPS request are
    limited to ``args.host`` / ``args.port`` / ``args.scheme``.
    """
    display = f"[{host}]" if ":" in host else host  # bracket IPv6 literals in the URL
    return {
        "method": "CONNECT",
        "scheme": "https",
        "host": host,
        "port": port,
        "url": f"https://{display}:{port}",
    }


def http_to_args(method: str, absolute_uri: str) -> dict[str, Any]:
    """Build enforcer args for a plain-HTTP forward-proxy request.

    A forward-proxied HTTP request carries the absolute URI on the request
    line (``GET http://host/path?q=1 HTTP/1.1``), so the full URL — including
    ``args.path`` and ``args.query`` — is available to constraints on the
    plain-HTTP path (and both are needed to reconstruct the origin-form line
    without dropping the query string).
    """
    parts = urlsplit(absolute_uri)
    scheme = parts.scheme or "http"
    return {
        "method": method,
        "scheme": scheme,
        "host": parts.hostname or "",
        "port": parts.port or (443 if scheme == "https" else 80),
        "url": absolute_uri,
        "path": parts.path or "/",
        "query": parts.query,
    }


def split_authority(target: str) -> tuple[str, int]:
    """Split a ``CONNECT`` target into ``(host, port)``.

    Handles bracketed IPv6 literals (``[::1]`` / ``[2606:4700::1]:443``) as well
    as ``host`` / ``host:port``. Brackets are stripped so the host is directly
    usable with :func:`asyncio.open_connection`. Defaults to port 443 when the
    target omits it. Raises ``ValueError`` on a malformed target (unterminated
    bracket, junk after ``]``, non-integer port) so the proxy fails closed.
    """
    if target.startswith("["):
        end = target.index("]")  # ValueError if unterminated → refused as malformed
        host = target[1:end]
        rest = target[end + 1 :]
        if rest.startswith(":"):
            return host, int(rest[1:])
        if rest:
            raise ValueError(f"malformed IPv6 authority: {target!r}")
        return host, 443
    host, sep, port_str = target.rpartition(":")
    if not sep:
        return target, 443
    return host, int(port_str)
