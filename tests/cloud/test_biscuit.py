"""Tests for the SDK-side Biscuit verification helpers."""

from __future__ import annotations

import pytest
from biscuit_auth import Algorithm, BiscuitBuilder, BlockBuilder, KeyPair, PrivateKey

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


def _mint_biscuit(priv_bytes: bytes, source: str = 'project("test");') -> str:
    """Mint a base64 Biscuit signed with ``priv_bytes``.

    Bypasses the platform's biscuits.py wrapper so SDK tests don't depend on
    platform code. Just enough to produce a valid token to verify against.
    """
    pk = PrivateKey.from_bytes(priv_bytes, Algorithm.Ed25519)
    return BiscuitBuilder(source).build(pk).to_base64()


def _mint_attenuated(priv_bytes: bytes, authority: str, *blocks: str) -> str:
    """Mint a multi-block biscuit: authority signed by ``priv_bytes``, then
    each block in ``blocks`` appended in order. Block signers are ephemeral
    keypairs managed internally by biscuit-python."""
    pk = PrivateKey.from_bytes(priv_bytes, Algorithm.Ed25519)
    biscuit = BiscuitBuilder(authority).build(pk)
    for source in blocks:
        biscuit = biscuit.append(BlockBuilder(source))
    return biscuit.to_base64()


# ---------------------------------------------------------------------------
# parse_envelope
# ---------------------------------------------------------------------------


def test_parse_envelope_returns_three_parts() -> None:
    """fty_<env>_<project>_<biscuit> → (env, project, biscuit)."""
    env, project, biscuit = parse_envelope("fty_live_support-bot_abc123")
    assert env == "live"
    assert project == "support-bot"
    assert biscuit == "abc123"


def test_parse_envelope_preserves_underscores_in_biscuit() -> None:
    """The biscuit b64 commonly contains `_` (URL-safe alphabet)."""
    biscuit_with_underscores = "EqQC_with_under_scores_in_payload"
    full = f"fty_live_proj_{biscuit_with_underscores}"
    _, _, parsed = parse_envelope(full)
    assert parsed == biscuit_with_underscores


def test_parse_envelope_preserves_hyphens_in_project_id() -> None:
    """Project ids commonly use hyphens (kebab-case)."""
    full = "fty_live_my-project-id_BISCUIT"
    _, project, _ = parse_envelope(full)
    assert project == "my-project-id"


def test_parse_envelope_supports_test_env() -> None:
    """The env segment isn't restricted to `live` — `test` works too."""
    env, _, _ = parse_envelope("fty_test_proj_BISCUIT")
    assert env == "test"


def test_parse_envelope_rejects_missing_fty_prefix() -> None:
    """An envelope without `fty_` is not a Hexgate token."""
    with pytest.raises(TokenError):
        parse_envelope("not_live_proj_biscuit")


def test_parse_envelope_rejects_too_few_segments() -> None:
    """Envelopes that don't have all four underscore segments are malformed."""
    with pytest.raises(TokenError):
        parse_envelope("fty_live_onlythree")


def test_parse_envelope_rejects_empty_string() -> None:
    """An empty input is not a valid envelope."""
    with pytest.raises(TokenError):
        parse_envelope("")


# ---------------------------------------------------------------------------
# verify_biscuit
# ---------------------------------------------------------------------------


def test_verify_accepts_token_signed_by_matching_key(keys: tuple[bytes, bytes]) -> None:
    """A token signed by the private key verifies with its public key."""
    priv, pub = keys
    biscuit = _mint_biscuit(priv)
    verify_biscuit(biscuit, pub)  # no exception


def test_verify_rejects_token_signed_by_other_key(keys: tuple[bytes, bytes]) -> None:
    """A token signed by one key must not verify against another."""
    priv, _ = keys
    other_pub = KeyPair().public_key.to_bytes()
    biscuit = _mint_biscuit(priv)
    with pytest.raises(TokenSignatureError):
        verify_biscuit(biscuit, other_pub)


def test_verify_rejects_malformed_public_key(keys: tuple[bytes, bytes]) -> None:
    """Wrong-length public key bytes are rejected with a clean error."""
    priv, _ = keys
    biscuit = _mint_biscuit(priv)
    with pytest.raises(TokenSignatureError, match="malformed public key"):
        verify_biscuit(biscuit, b"too short")


def test_verify_rejects_garbage_token(keys: tuple[bytes, bytes]) -> None:
    """Random non-base64 bytes don't get accepted as a token."""
    _, pub = keys
    with pytest.raises(TokenSignatureError):
        verify_biscuit("not even base64 ! @#$", pub)


def test_verify_rejects_tampered_payload(keys: tuple[bytes, bytes]) -> None:
    """Flipping a few bytes of the encoded biscuit breaks verification."""
    priv, pub = keys
    good = _mint_biscuit(priv)
    # Tamper near the end (avoiding base64 padding) — keeps the b64 valid
    # so the failure surfaces from signature check, not malformed payload.
    tampered = good[: len(good) - 6] + "AAAA" + good[-2:]
    with pytest.raises(TokenSignatureError):
        verify_biscuit(tampered, pub)


# ---------------------------------------------------------------------------
# extract_facts
# ---------------------------------------------------------------------------


def test_extract_facts_returns_authority_facts(keys: tuple[bytes, bytes]) -> None:
    """Single-block (authority-only) tokens yield their flat facts."""
    priv, pub = keys
    token = _mint_biscuit(
        priv,
        'project("acme"); scope("read"); refund_limit(50);',
    )
    assert extract_facts(token, pub) == {
        "project": ["acme"],
        "scope": ["read"],
        "refund_limit": [50],
    }


def test_extract_facts_unions_across_blocks(keys: tuple[bytes, bytes]) -> None:
    """Authority + attenuation blocks contribute to the same dict (UNION)."""
    priv, pub = keys
    token = _mint_attenuated(
        priv,
        'project("acme"); scope("read");',
        'user("alice"); scope("write");',
    )
    facts = extract_facts(token, pub)
    assert facts["project"] == ["acme"]
    assert facts["user"] == ["alice"]
    # source order across all blocks → ["read", "write"]
    assert facts["scope"] == ["read", "write"]


def test_extract_facts_accepts_integer_values(keys: tuple[bytes, bytes]) -> None:
    """Bare integer facts decode as int, not str — needed for numeric limits."""
    priv, pub = keys
    token = _mint_biscuit(priv, "refund_limit(50); max_tokens(1000); negative(-5);")
    facts = extract_facts(token, pub)
    assert facts == {
        "refund_limit": [50],
        "max_tokens": [1000],
        "negative": [-5],
    }
    assert all(isinstance(v, int) for vs in facts.values() for v in vs)


def test_extract_facts_skips_checks_and_rules(keys: tuple[bytes, bytes]) -> None:
    """Checks and rules belong to the authorizer, not the structured policy."""
    priv, pub = keys
    token = _mint_attenuated(
        priv,
        'user("alice"); refund_limit(50);',
        # A check (skipped) and a rule (skipped); the bare facts pass through.
        "check if time($t), $t < 2027-01-01T00:00:00Z;"
        ' admin($u) <- user($u), role("admin");'
        ' scope("read");',
    )
    facts = extract_facts(token, pub)
    assert facts == {
        "user": ["alice"],
        "refund_limit": [50],
        "scope": ["read"],
    }


def test_extract_facts_silently_skips_multi_arg_facts(
    keys: tuple[bytes, bytes],
) -> None:
    """M1 only consumes single-arity facts; multi-arg shapes are skipped."""
    priv, pub = keys
    token = _mint_biscuit(
        priv,
        'user("alice"); pair("x", "y"); refund_limit(50);',
    )
    facts = extract_facts(token, pub)
    assert "pair" not in facts
    assert facts["user"] == ["alice"]
    assert facts["refund_limit"] == [50]


def test_extract_facts_returns_empty_dict_when_no_facts(
    keys: tuple[bytes, bytes],
) -> None:
    """A check-only block still yields a verified token with empty facts."""
    priv, pub = keys
    token = _mint_biscuit(priv, "check if time($t), $t < 2027-01-01T00:00:00Z;")
    assert extract_facts(token, pub) == {}


def test_extract_facts_repeated_predicate_preserves_order(
    keys: tuple[bytes, bytes],
) -> None:
    """``scope("read"); scope("write"); scope("admin");`` → list in source order."""
    priv, pub = keys
    token = _mint_biscuit(priv, 'scope("read"); scope("write"); scope("admin");')
    assert extract_facts(token, pub) == {"scope": ["read", "write", "admin"]}


def test_extract_facts_rejects_tampered_token(keys: tuple[bytes, bytes]) -> None:
    """Tampered token must surface as TokenSignatureError before any parse."""
    priv, pub = keys
    good = _mint_biscuit(priv, 'user("alice");')
    tampered = good[: len(good) - 6] + "AAAA" + good[-2:]
    with pytest.raises(TokenSignatureError):
        extract_facts(tampered, pub)


def test_extract_facts_rejects_wrong_public_key(keys: tuple[bytes, bytes]) -> None:
    """Verifying against a different pubkey must fail before fact extraction."""
    priv, _ = keys
    other_pub = KeyPair().public_key.to_bytes()
    token = _mint_biscuit(priv, 'user("alice");')
    with pytest.raises(TokenSignatureError):
        extract_facts(token, other_pub)


def test_extract_facts_rejects_malformed_public_key(
    keys: tuple[bytes, bytes],
) -> None:
    """Garbage public key bytes raise a clean TokenSignatureError."""
    priv, _ = keys
    token = _mint_biscuit(priv, 'user("alice");')
    with pytest.raises(TokenSignatureError, match="malformed public key"):
        extract_facts(token, b"too short")


def test_extract_facts_preserves_underscores_in_predicate_names(
    keys: tuple[bytes, bytes],
) -> None:
    """Predicate names may contain underscores (refund_limit, max_tokens, ...)."""
    priv, pub = keys
    token = _mint_biscuit(priv, "refund_limit(50); max_token_count(1000);")
    assert extract_facts(token, pub) == {
        "refund_limit": [50],
        "max_token_count": [1000],
    }
