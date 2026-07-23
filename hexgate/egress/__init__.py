"""Optional network-egress enforcement plane for Hexgate.

Routes an agent's outbound HTTP(S) through the same ``PolicyEnforcer`` that
gates tool calls, mapped to the synthetic ``net.http_request`` tool. A second
enforcement plane alongside the declared-tool-call one: it gates the *actual*
destination a process reaches, not just the tool the model asked for.

Framework-agnostic and base-install — stdlib ``asyncio`` only, depends only on
``hexgate.security`` / ``hexgate.runtime`` / ``hexgate.audit``. See
``egress-proxy-plan.md``.

    from hexgate.egress import egress_guard
    from hexgate.runtime.context import User

    async with egress_guard(enforcer, User(user_id="u", role="agent")):
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
from hexgate.egress.transport import Transport, TunnelTransport

__all__ = [
    "NET_TOOL",
    "EgressProxy",
    "Gate",
    "GateResult",
    "Transport",
    "TunnelTransport",
    "connect_to_args",
    "egress_guard",
    "http_to_args",
    "split_authority",
]
