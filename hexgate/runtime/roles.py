"""Role-set resolution — how a caller's asserted roles become a decision input.

``HexgateContext.user_roles`` is caller-supplied, and three surfaces act on it:
the enforcer (which evaluates every role), ``hexgate policy test`` (which
dry-runs the same decision), and token attenuation (which attests the set). They
need the same normalisation, so it lives here rather than three times over — a
dry-run that normalises differently from production is worse than no dry-run.

This module is deliberately in ``runtime``: it sits next to the model that owns
``user_roles``, and ``runtime`` imports neither ``security`` nor ``cloud``, so
all three consumers can share it without a package cycle.

Note the asymmetry the two entry points encode. :func:`resolve_role_set` caps
the count and never returns an empty sequence, because it feeds *authorisation*
— bounded work, and a caller with no roles must still be decided against the
``default`` policy. :func:`distinct_roles` does neither, because it feeds
*attestation*: a token should record what the caller claimed, and silently
dropping the tail of that claim would make the token disagree with the request.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

# Upper bound on the roles evaluated for one tool call. N roles cost N engine
# invocations (one WASM module call each) and the list is caller-supplied, so it
# needs a ceiling. Dropping the tail can only *narrow* a permissive union, which
# makes the cap fail-closed.
MAX_EVALUATED_ROLES = 32


def distinct_roles(roles: Iterable[str]) -> list[str]:
    """De-duplicate role names, preserving the caller's order.

    By *name*, not by resolved policy: two names can select the same policy and
    still differ in the ``role`` fact a constraint reads, so both are kept.
    Order matters because it decides which role is credited with an allow.
    """
    seen: list[str] = []
    for role in roles:
        if role not in seen:
            seen.append(role)
    return seen


def resolve_role_set(
    roles: Iterable[str],
    *,
    cap: int = MAX_EVALUATED_ROLES,
    on_truncate: Callable[[int, int], None] | None = None,
) -> list[str | None]:
    """The role sequence one decision evaluates: distinct, capped, never empty.

    Returns ``[None]`` for a caller carrying no roles. ``None`` is part of the
    engine contract (``PolicyEngine.evaluate`` takes ``str | None``) and both
    engines map it to the ``default`` policy, so the decision still happens; an
    empty sequence would instead leave the permissive union with nothing to fold,
    which it rejects outright rather than let a role-less caller skip evaluation.

    ``on_truncate(total, kept)`` fires when ``cap`` trims the list. Logging
    policy stays with the caller — the enforcer warns once per process, the CLI
    prints to stderr — because this function has no business choosing a channel.
    """
    distinct = distinct_roles(roles)
    if not distinct:
        return [None]
    if len(distinct) > cap:
        if on_truncate is not None:
            on_truncate(len(distinct), cap)
        distinct = distinct[:cap]
    return list(distinct)
