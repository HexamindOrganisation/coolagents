"""Optional network-egress enforcement plane for Hexgate.

Routes an agent's outbound traffic through the same ``PolicyEnforcer`` that
gates tool calls. HTTP(S) egress maps to the synthetic ``net.http_request``
tool (``EgressProxy``); a raw-TCP connection maps to ``net.tcp_connect``
(``TcpEgressProxy``, the reachability gate for databases and other non-HTTP
services). A second enforcement plane alongside the declared-tool-call one: it
gates the *actual* destination a process reaches, not just the tool the model
asked for.

Framework-agnostic and base-install: stdlib ``asyncio`` plus the
framework-agnostic ``hexgate.security``, ``hexgate.runtime``, and
``hexgate.approvals`` modules (``hexgate.audit`` comes in transitively via the
enforcer). No agent framework is imported. See the network-egress concept doc
(``docs/concepts/egress.mdx``).

    from hexgate.egress import egress_guard
    from hexgate.runtime.context import HexgateContext

    async with egress_guard(enforcer, HexgateContext(user_id="u", user_roles=["agent"])):
        ...  # this process's HTTP(S) egress is now policy-gated
"""

from hexgate.egress.gate import Gate, GateResult
from hexgate.egress.model import (
    NET_TOOL,
    connect_to_args,
    http_to_args,
    split_authority,
)
from hexgate.egress.proxy import EgressProxy, egress_guard
from hexgate.egress.tcp import TcpEgressProxy, tcp_egress_guard
from hexgate.egress.transport import Transport, TunnelTransport

__all__ = [
    "NET_TOOL",
    "EgressProxy",
    "Gate",
    "GateResult",
    "TcpEgressProxy",
    "Transport",
    "TunnelTransport",
    "connect_to_args",
    "egress_guard",
    "http_to_args",
    "split_authority",
    "tcp_egress_guard",
]
