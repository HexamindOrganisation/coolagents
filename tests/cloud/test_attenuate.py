"""Tests for the SDK-side attenuation primitive.

The primitive lives in :mod:`hexgate.cloud.attenuate` and lets a dev's
backend (or the demo serve loop) append a user/scope/limit block to a
parent Hexgate token. The new envelope's signature chain still verifies
against the platform's root public key — biscuit handles the signature
linkage with an ephemeral keypair internally.
"""

from __future__ import annotations

import pytest
from biscuit_auth import BiscuitBuilder, KeyPair

from hexgate.cloud.attenuate import attenuate_for_user
from hexgate.cloud.biscuit import (
    TokenError,
    TokenSignatureError,
    extract_facts,
    parse_envelope,
    verify_biscuit,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    """Fresh Ed25519 keypair as raw bytes ``(priv, pub)``."""
    kp = KeyPair()
    return kp.private_key.to_bytes(), kp.public_key.to_bytes()


def _parent_envelope(
    priv: bytes,
    *,
    project: str = "acme",
    env: str = "live",
    facts: str = 'project("acme"); scope("read");',
) -> str:
    """Mint a parent ``fty_<env>_<project>_<biscuit>`` envelope to attenuate."""
    from biscuit_auth import Algorithm, PrivateKey

    pk = PrivateKey.from_bytes(priv, Algorithm.Ed25519)
    biscuit = BiscuitBuilder(facts).build(pk)
    return f"fty_{env}_{project}_{biscuit.to_base64()}"


def _biscuit_b64(envelope: str) -> str:
    return parse_envelope(envelope)[2]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_attenuate_adds_user_fact_and_chains(keys: tuple[bytes, bytes]) -> None:
    """A user-only attenuation yields an envelope that still verifies."""
    priv, pub = keys
    parent = _parent_envelope(priv)

    child = attenuate_for_user(parent, pub, user="alice")

    # Wire format unchanged
    assert child.startswith("fty_live_acme_")
    # Signature chain still verifies against the platform root pubkey
    verify_biscuit(_biscuit_b64(child), pub)
    # Facts dict shows both authority + attenuation
    assert extract_facts(_biscuit_b64(child), pub) == {
        "project": ["acme"],
        "scope": ["read"],
        "user": ["alice"],
    }


def test_attenuate_adds_role_fact(keys: tuple[bytes, bytes]) -> None:
    """The optional roles param stamps a ``role("...")`` fact."""
    priv, pub = keys
    parent = _parent_envelope(priv)

    child = attenuate_for_user(parent, pub, user="alice", roles=["billing"])
    facts = extract_facts(_biscuit_b64(child), pub)
    assert facts["user"] == ["alice"]
    assert facts["role"] == ["billing"]
    # Parent's facts still flow through
    assert facts["project"] == ["acme"]
    assert facts["scope"] == ["read"]


def test_attenuate_attests_every_role_in_the_set(keys: tuple[bytes, bytes]) -> None:
    """The enforcer evaluates every role, so the token attests every role —
    one fact each, all under one predicate."""
    priv, pub = keys
    parent = _parent_envelope(priv)

    child = attenuate_for_user(
        parent, pub, user="alice", roles=["support", "billing", "auditor"]
    )
    facts = extract_facts(_biscuit_b64(child), pub)
    assert sorted(facts["role"]) == ["auditor", "billing", "support"]


def test_attenuate_collapses_duplicate_roles(keys: tuple[bytes, bytes]) -> None:
    """Biscuit facts are a set, so a repeated name attests nothing extra."""
    priv, pub = keys
    parent = _parent_envelope(priv)

    child = attenuate_for_user(
        parent, pub, user="alice", roles=["billing", "billing", "support"]
    )
    facts = extract_facts(_biscuit_b64(child), pub)
    assert sorted(facts["role"]) == ["billing", "support"]


def test_attenuate_without_role_omits_role_fact(keys: tuple[bytes, bytes]) -> None:
    """No roles param means no ``role(...)`` fact in the attenuation block."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    child = attenuate_for_user(parent, pub, user="alice")
    facts = extract_facts(_biscuit_b64(child), pub)
    assert "role" not in facts


def test_attenuate_with_empty_role_list_omits_role_fact(
    keys: tuple[bytes, bytes],
) -> None:
    """Empty ``user_roles`` is the "no roles" case, not an error."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    child = attenuate_for_user(parent, pub, user="alice", roles=[])
    facts = extract_facts(_biscuit_b64(child), pub)
    assert "role" not in facts


def test_attenuate_with_ttl_inserts_time_check(keys: tuple[bytes, bytes]) -> None:
    """A TTL embeds a ``check if time(...)`` predicate; signature still chains."""
    from biscuit_auth import Algorithm, Biscuit, PublicKey

    priv, pub = keys
    parent = _parent_envelope(priv)
    child = attenuate_for_user(parent, pub, user="alice", ttl_seconds=3600)

    # Verify and inspect the new block's source for the check string
    public_key = PublicKey.from_bytes(pub, Algorithm.Ed25519)
    biscuit = Biscuit.from_base64(_biscuit_b64(child), public_key)
    block_source = biscuit.block_source(1)  # attenuation block
    assert "check if time($t)" in block_source
    assert "$t <" in block_source


def test_attenuate_stacks_multiple_times(keys: tuple[bytes, bytes]) -> None:
    """An already-attenuated token can be attenuated again — biscuit chains it."""
    priv, pub = keys
    parent = _parent_envelope(priv)

    first = attenuate_for_user(parent, pub, user="alice", roles=["support"])
    second = attenuate_for_user(first, pub, user="alice", roles=["billing"])

    facts = extract_facts(_biscuit_b64(second), pub)
    # `user("alice")` shows up twice (once per attenuation); UNION semantics.
    assert facts["user"] == ["alice", "alice"]
    # Both role values present — last-write doesn't override; the runtime
    # picks one. Biscuit's safety property: appending never elides prior facts.
    assert sorted(facts["role"]) == ["billing", "support"]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_attenuate_rejects_empty_role(keys: tuple[bytes, bytes]) -> None:
    """An empty role string is rejected — omit the entry instead."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    with pytest.raises(TokenError, match="role must be a non-empty"):
        attenuate_for_user(parent, pub, user="alice", roles=[""])


def test_attenuate_rejects_an_empty_role_among_valid_ones(
    keys: tuple[bytes, bytes],
) -> None:
    """One bad entry fails the whole attenuation: dropping it would attest a set
    the caller never asked for."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    with pytest.raises(TokenError, match="role must be a non-empty"):
        attenuate_for_user(parent, pub, user="alice", roles=["billing", ""])


def test_attenuate_rejects_a_bare_string_role(keys: tuple[bytes, bytes]) -> None:
    """``roles="admin"`` type-checks (str is a Sequence[str]) but iterates per
    character, so it would attest five one-letter roles and never ``admin``."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    with pytest.raises(TypeError, match="not a bare str"):
        attenuate_for_user(parent, pub, user="alice", roles="admin")  # type: ignore[arg-type]


def test_attenuate_rejects_non_positive_ttl(keys: tuple[bytes, bytes]) -> None:
    """TTL must be a positive int — 0 or negative is rejected."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    with pytest.raises(TokenError, match="positive int"):
        attenuate_for_user(parent, pub, user="alice", ttl_seconds=0)
    with pytest.raises(TokenError, match="positive int"):
        attenuate_for_user(parent, pub, user="alice", ttl_seconds=-30)


# ---------------------------------------------------------------------------
# Security guarantees
# ---------------------------------------------------------------------------


def test_attenuate_escapes_double_quote_in_user(keys: tuple[bytes, bytes]) -> None:
    """A user value with a stray ``"`` mustn't break out of the Datalog literal.

    The injection attempt ``alice\\"); user("eve`` would, unescaped, render as
    ``user("alice"); user("eve");`` — two facts where the attacker controls
    the second. Escaping renders it as a single fact whose value contains
    backslash + quote bytes. From the policy engine's perspective the
    important guarantee is that ``user("eve")`` is never a distinct fact.
    """
    priv, pub = keys
    parent = _parent_envelope(priv)
    child = attenuate_for_user(parent, pub, user='alice\\"); user("eve')

    facts = extract_facts(_biscuit_b64(child), pub)
    # The forged identity must never appear as a standalone fact value.
    assert "eve" not in facts.get("user", [])


def test_attenuate_rejects_tampered_parent(keys: tuple[bytes, bytes]) -> None:
    """A tampered parent envelope fails verification before any append."""
    priv, pub = keys
    good = _parent_envelope(priv)
    env, project, biscuit_b64 = parse_envelope(good)
    tampered = f"fty_{env}_{project}_{biscuit_b64[: len(biscuit_b64) - 6]}AAAA{biscuit_b64[-2:]}"
    with pytest.raises(TokenSignatureError):
        attenuate_for_user(tampered, pub, user="alice")


def test_attenuate_rejects_wrong_public_key(keys: tuple[bytes, bytes]) -> None:
    """Verifying the parent against the wrong pubkey rejects before append."""
    priv, _ = keys
    other_pub = KeyPair().public_key.to_bytes()
    parent = _parent_envelope(priv)
    with pytest.raises(TokenSignatureError):
        attenuate_for_user(parent, other_pub, user="alice")


def test_attenuate_rejects_malformed_public_key(keys: tuple[bytes, bytes]) -> None:
    """Garbage public key bytes are surfaced as TokenSignatureError."""
    priv, _ = keys
    parent = _parent_envelope(priv)
    with pytest.raises(TokenSignatureError, match="malformed public key"):
        attenuate_for_user(parent, b"too short", user="alice")


def test_attenuate_rejects_malformed_envelope(keys: tuple[bytes, bytes]) -> None:
    """A non-``fty_`` envelope is surfaced with the same clear error path."""
    _, pub = keys
    with pytest.raises(TokenError, match="malformed"):
        attenuate_for_user("not_an_envelope_at_all", pub, user="alice")


# ---------------------------------------------------------------------------
# Empty / default arguments
# ---------------------------------------------------------------------------


def test_attenuate_user_only_is_minimum_required(
    keys: tuple[bytes, bytes],
) -> None:
    """The simplest call shape: just bind a user, nothing else."""
    priv, pub = keys
    parent = _parent_envelope(priv)
    child = attenuate_for_user(parent, pub, user="alice")
    facts = extract_facts(_biscuit_b64(child), pub)
    assert facts["user"] == ["alice"]
    assert "role" not in facts
