"""Egress proxy demo — gate outbound HTTP(S) by host, no API keys needed.

Builds a code-first policy with `PolicyBuilder.net_allow` that allows HTTPS to
`api.github.com` and denies everything else, starts the in-process egress proxy,
points this process's HTTP clients at it, and makes two requests through plain
`httpx` — one allowed, one denied — printing each policy decision as it happens.

    python examples/egress_demo.py

Note: the requests use ``httpx.AsyncClient`` (awaited), not the sync API,
because the proxy runs on this same event loop — a blocking sync call would
deadlock it. In a real deployment the agent's own async HTTP client picks up
the ``HTTPS_PROXY`` env var that ``egress_guard`` sets, with no code changes.
"""

from __future__ import annotations

import asyncio

import httpx

from hexgate import HexgateContext, PolicyBuilder
from hexgate.egress import egress_guard
from hexgate.security.decision import Decision
from hexgate.security.enforcer import build_enforcer
from hexgate.security.policy_set import load_policy_set


def _print_decision(decision: Decision) -> None:
    mark = "✓" if decision.allowed else "✗"
    url = (decision.arguments or {}).get("url", "?")
    print(f"  {mark} {decision.outcome.value:15} {url}")
    if not decision.allowed and decision.reason:
        print(f"      reason: {decision.reason}")


async def main() -> None:
    # Network egress is just another gated tool — deny by default, allow HTTPS to
    # one host. `net_allow` renders this into ordinary constraints on
    # `net.http_request`, so it works on both the pydantic and WASM engines.
    policy = PolicyBuilder(default="deny").net_allow(hosts=["api.github.com"]).build()
    enforcer = build_enforcer(
        load_policy_set(policy),
        agent_name="egress-demo",
        decision_observer=_print_decision,
    )
    context = HexgateContext(user_id="demo", user_roles=["agent"])

    # no_proxy would include the Hexgate control-plane host if audit were on,
    # so audit POSTs bypass the proxy. This demo runs without an API key.
    async with egress_guard(enforcer, context):
        async with httpx.AsyncClient(timeout=10) as client:
            for url in ("https://api.github.com/zen", "https://example.com/"):
                print(f"\nGET {url}")
                try:
                    response = await client.get(url)
                    print(f"  -> {response.status_code}")
                except httpx.HTTPError as exc:
                    print(f"  -> blocked: {type(exc).__name__}")


if __name__ == "__main__":
    asyncio.run(main())
