"""Role-set normalisation, shared by the enforcer, ``policy test``, and attenuation.

Lives in ``runtime`` (which imports neither ``security`` nor ``cloud``) because
``security -> cloud`` edges already exist, so a home in ``security`` would make a
package cycle.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

# N roles cost N engine invocations and the list is caller-supplied. Trimming can
# only narrow a permissive union, so the cap is fail-closed.
MAX_EVALUATED_ROLES = 32


def distinct_roles(roles: Iterable[str]) -> list[str]:
    """De-duplicate by name, preserving order.

    By name, not by resolved policy: two names can select the same policy and
    still differ in the ``role`` fact a constraint reads. Order decides which
    role is credited with an allow.

    Rejects a bare ``str``: it satisfies ``Iterable[str]`` and type-checks
    clean, but iterates per *character*, so ``"admin"`` would silently become
    five one-letter roles — attested in a token or evaluated as a role set.
    """
    if isinstance(roles, str):
        raise TypeError(
            f"roles must be a sequence of role names, not a bare str: {roles!r} "
            f"(did you mean [{roles!r}]?)"
        )
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
    """Distinct, capped, never empty — the sequence one decision evaluates.

    ``[None]`` for a caller with no roles: both engines map it to the ``default``
    policy, whereas an empty sequence would leave the union nothing to fold.
    ``on_truncate(total, kept)`` lets the caller pick a channel (the enforcer
    logs, the CLI prints).

    Contrast :func:`distinct_roles`, which neither caps nor substitutes a
    default: it feeds attestation, where the token must record what the caller
    claimed.
    """
    distinct = distinct_roles(roles)
    if not distinct:
        return [None]
    if len(distinct) > cap:
        if on_truncate is not None:
            on_truncate(len(distinct), cap)
        distinct = distinct[:cap]
    return list(distinct)
