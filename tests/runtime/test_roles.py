"""Role-set resolution — the one normalisation shared by every surface.

The enforcer, the ``hexgate policy test`` dry-run, and token attenuation all
read ``HexgateContext.user_roles``. These tests pin the rules once so a future
change can't quietly give one of those surfaces different semantics.
"""

from __future__ import annotations

from hexgate.runtime.roles import (
    MAX_EVALUATED_ROLES,
    distinct_roles,
    resolve_role_set,
)


# ---------------------------------------------------------------------------
# distinct_roles — dedup for attestation (no cap, no sentinel)
# ---------------------------------------------------------------------------


def test_distinct_roles_preserves_caller_order() -> None:
    """Order decides which role is credited with an allow, so it is kept."""
    assert distinct_roles(["support", "billing", "auditor"]) == [
        "support",
        "billing",
        "auditor",
    ]


def test_distinct_roles_drops_repeats_keeping_the_first() -> None:
    assert distinct_roles(["billing", "support", "billing"]) == ["billing", "support"]


def test_distinct_roles_of_nothing_is_empty() -> None:
    """No sentinel here: attestation of "no roles" means no facts at all."""
    assert distinct_roles([]) == []


def test_distinct_roles_does_not_cap() -> None:
    """A token records what the caller claimed; trimming it would make the
    token disagree with the request it authorises."""
    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES + 10)]

    assert distinct_roles(roles) == roles


# ---------------------------------------------------------------------------
# resolve_role_set — the authorisation input (capped, never empty)
# ---------------------------------------------------------------------------


def test_resolve_role_set_dedups_in_order() -> None:
    assert resolve_role_set(["billing", "support", "billing"]) == ["billing", "support"]


def test_resolve_no_roles_evaluates_the_default_policy() -> None:
    """``[None]`` rather than ``[]``: a role-less caller must still be decided.

    Both engines map ``None`` to the ``default`` policy. Returning an empty
    sequence would instead leave the permissive union with nothing to fold.
    """
    assert resolve_role_set([]) == [None]


def test_resolve_caps_the_role_count() -> None:
    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES + 5)]

    resolved = resolve_role_set(roles)

    assert len(resolved) == MAX_EVALUATED_ROLES
    assert resolved[0] == "role_0"  # the head is kept, not a sample
    assert resolved[-1] == f"role_{MAX_EVALUATED_ROLES - 1}"


def test_resolve_reports_truncation_to_the_caller() -> None:
    """The channel is the caller's choice — the enforcer logs, the CLI prints —
    so the function reports rather than deciding where the warning goes."""
    seen: list[tuple[int, int]] = []
    roles = [f"role_{index}" for index in range(MAX_EVALUATED_ROLES + 3)]

    resolve_role_set(roles, on_truncate=lambda total, kept: seen.append((total, kept)))

    assert seen == [(MAX_EVALUATED_ROLES + 3, MAX_EVALUATED_ROLES)]


def test_resolve_is_silent_when_nothing_is_truncated() -> None:
    seen: list[tuple[int, int]] = []

    resolve_role_set(["billing"], on_truncate=lambda *args: seen.append(args))  # type: ignore[arg-type]

    assert seen == []


def test_resolve_counts_distinct_roles_against_the_cap() -> None:
    """Duplicates are collapsed before the cap applies, so a caller repeating
    one name 100 times is not treated as 100 roles."""
    resolved = resolve_role_set(["billing"] * (MAX_EVALUATED_ROLES + 10))

    assert resolved == ["billing"]


def test_resolve_honours_an_explicit_cap() -> None:
    assert resolve_role_set(["a", "b", "c"], cap=2) == ["a", "b"]


def test_resolve_is_idempotent() -> None:
    """The CLI resolves an already-distinct list; that must be a no-op."""
    once = resolve_role_set(["billing", "support"])
    twice = resolve_role_set([role for role in once if role is not None])

    assert once == twice
