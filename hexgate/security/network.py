"""Network-egress policy contract — the synthetic tool name and constraint emitters.

Network egress is enforced as an ordinary tool call named ``net.http_request``:
the egress proxy maps each outbound HTTP(S) request onto it. This module is the
single source of truth for that name and for turning host/scheme/port allowlists
into constraint *strings* — the same grammar tool-call constraints use — so the
network rules compile to both engines (pydantic + WASM) with no special-casing.

Nothing here is a new enforcement path: it renders strings the existing
constraint parser (:mod:`hexgate.security.constraints`) and the Rego compiler
already accept.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

# The synthetic tool every egress request is attributed to. Defined here (not in
# hexgate.egress) so the policy layer (PolicyBuilder.net_allow) and the proxy
# share one definition — egress depends downward on security, never the reverse.
NET_HTTP_REQUEST = "net.http_request"


def host_match_constraint(
    hosts: Iterable[str] = (), subdomains: Iterable[str] = ()
) -> str | None:
    """Render one constraint matching an exact-host allowlist and/or domains.

    ``hosts`` match exactly. Each ``subdomains`` entry ``d`` matches both the
    apex ``d`` and any ``*.d`` — via ``endswith(args.host, ".d")``, whose leading
    dot stops ``d`` from also matching ``evil-d``. Terms are OR-ed into one
    expression so the whole host check is a single AND-clause in the tool's
    constraint list.

    Returns ``None`` when neither is given (no host restriction).
    """
    hosts = list(hosts)
    subdomains = list(subdomains)
    terms: list[str] = []
    if hosts:
        terms.append(f"args.host in {json.dumps(hosts)}")
    for domain in subdomains:
        terms.append(f"args.host == {json.dumps(domain)}")
        terms.append(f"endswith(args.host, {json.dumps('.' + domain)})")
    if not terms:
        return None
    return " or ".join(terms)


def net_constraints(
    *,
    hosts: Iterable[str] = (),
    subdomains: Iterable[str] = (),
    schemes: Iterable[str] = (),
    ports: Iterable[int] = (),
) -> list[str]:
    """Render the AND-ed constraint list for an egress rule.

    Each returned string is one clause (all must hold). Host/subdomain matching
    collapses to a single OR clause; ``schemes`` and ``ports`` become their own
    ``in`` clauses. An empty facet contributes no clause (no restriction on it).
    """
    constraints: list[str] = []
    host_clause = host_match_constraint(hosts, subdomains)
    if host_clause is not None:
        constraints.append(host_clause)
    schemes = list(schemes)
    if schemes:
        constraints.append(f"args.scheme in {json.dumps(schemes)}")
    ports = list(ports)
    if ports:
        constraints.append(f"args.port in {json.dumps(ports)}")
    return constraints
