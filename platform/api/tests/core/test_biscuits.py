"""Tests for the Biscuit mint / verify / attenuate / authorize wrapper."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from biscuit_auth import KeyPair

from hexgate_api.core.biscuits import (
    MintRequest,
    TokenAuthorizationError,
    TokenError,
    TokenSignatureError,
    attenuate_token,
    authorize_token,
    make_envelope,
    mint_token,
    parse_envelope,
    verify_token,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    """A fresh Ed25519 keypair as raw bytes ``(priv, pub)``."""
    kp = KeyPair()
    return kp.private_key.to_bytes(), kp.public_key.to_bytes()


def _mint(
    priv: bytes,
    *,
    project_id: str = "support-bot",
    token_id: str = "tok_abc123",
    name: str = "test-token",
    scopes: list[str] | None = None,
    env: str = "live",
    ttl_seconds: int | None = None,
) -> str:
    return mint_token(
        priv,
        MintRequest(
            project_id=project_id,
            token_id=token_id,
            name=name,
            scopes=scopes if scopes is not None else ["mint_user_token"],
            env=env,
            ttl_seconds=ttl_seconds,
        ),
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Mint / verify
# ---------------------------------------------------------------------------


def test_mint_then_verify_roundtrip(keys: tuple[bytes, bytes]) -> None:
    """A token signed with the private key verifies with its public key."""
    priv, pub = keys
    token = _mint(priv)
    biscuit = verify_token(token, pub)
    assert biscuit.block_count() == 1


def test_verify_rejects_wrong_pubkey(keys: tuple[bytes, bytes]) -> None:
    """A token signed by one key must not verify against another key."""
    priv, _ = keys
    other = KeyPair().public_key.to_bytes()
    token = _mint(priv)
    with pytest.raises(TokenSignatureError):
        verify_token(token, other)


def test_verify_rejects_malformed_pubkey(keys: tuple[bytes, bytes]) -> None:
    """Wrong-length public key bytes are rejected with a clean error."""
    priv, _ = keys
    token = _mint(priv)
    with pytest.raises(TokenSignatureError, match="malformed public key"):
        verify_token(token, b"too short")


def test_verify_rejects_garbage_token(keys: tuple[bytes, bytes]) -> None:
    """Random non-base64 bytes don't get accepted as a token."""
    _, pub = keys
    with pytest.raises(TokenSignatureError):
        verify_token("not even base64 ! @#$", pub)


# ---------------------------------------------------------------------------
# Authorize via top-level scope facts
# ---------------------------------------------------------------------------


def test_authorize_grants_when_scope_matches(keys: tuple[bytes, bytes]) -> None:
    """Scopes live in the root block — visible to top-level policy."""
    priv, pub = keys
    token = _mint(priv, scopes=["mint_user_token"])
    biscuit = verify_token(token, pub)
    authorize_token(
        biscuit,
        facts=f"time({_now_iso()})",
        policies='allow if scope("mint_user_token")',
    )


def test_authorize_rejects_when_scope_missing(keys: tuple[bytes, bytes]) -> None:
    """A scope the token doesn't grant must not authorize."""
    priv, pub = keys
    token = _mint(priv, scopes=["read_audit"])
    biscuit = verify_token(token, pub)
    with pytest.raises(TokenAuthorizationError):
        authorize_token(
            biscuit,
            facts=f"time({_now_iso()})",
            policies='allow if scope("delete_project")',
        )


# ---------------------------------------------------------------------------
# TTL caveat
# ---------------------------------------------------------------------------


def test_ttl_caveat_passes_within_window(keys: tuple[bytes, bytes]) -> None:
    """A 1-hour TTL accepts authorizer time within the window."""
    priv, pub = keys
    token = _mint(priv, ttl_seconds=3600)
    biscuit = verify_token(token, pub)
    authorize_token(
        biscuit,
        facts=f"time({_now_iso()})",
        policies='allow if scope("mint_user_token")',
    )


def test_ttl_caveat_rejects_after_expiry(keys: tuple[bytes, bytes]) -> None:
    """A 60-second TTL rejects authorizer time well past expiry."""
    priv, pub = keys
    token = _mint(priv, ttl_seconds=60)
    biscuit = verify_token(token, pub)
    far_future = (datetime.now(timezone.utc) + timedelta(days=365)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    with pytest.raises(TokenAuthorizationError):
        authorize_token(
            biscuit,
            facts=f"time({far_future})",
            policies='allow if scope("mint_user_token")',
        )


# ---------------------------------------------------------------------------
# Attenuation
# ---------------------------------------------------------------------------


def test_attenuate_returns_strictly_longer_token(keys: tuple[bytes, bytes]) -> None:
    """Adding a block grows the encoded token."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, 'check if user("alice");')
    assert len(child) > len(parent)


def test_attenuated_token_still_chains_to_root(keys: tuple[bytes, bytes]) -> None:
    """The attenuated token still verifies against the same public key."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, 'check if user("alice");')
    biscuit = verify_token(child, pub)
    assert biscuit.block_count() == 2


def test_attenuated_check_passes_with_matching_authorizer_fact(
    keys: tuple[bytes, bytes],
) -> None:
    """Authorizer fact ``user("alice")`` satisfies the attenuation's check."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, 'check if user("alice");')
    biscuit = verify_token(child, pub)
    authorize_token(
        biscuit,
        facts=f'time({_now_iso()}); user("alice")',
        policies='allow if scope("mint_user_token")',
    )


def test_attenuated_check_rejects_non_matching_authorizer_fact(
    keys: tuple[bytes, bytes],
) -> None:
    """A different user fails the attenuation block's check."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, 'check if user("alice");')
    biscuit = verify_token(child, pub)
    with pytest.raises(TokenAuthorizationError):
        authorize_token(
            biscuit,
            facts=f'time({_now_iso()}); user("bob")',
            policies='allow if scope("mint_user_token")',
        )


def test_attenuation_amount_caveat_under_limit(keys: tuple[bytes, bytes]) -> None:
    """Numeric caveat with $a <= 50 accepts amount(40)."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, "check if amount($a), $a <= 50;")
    biscuit = verify_token(child, pub)
    authorize_token(
        biscuit,
        facts=f"time({_now_iso()}); amount(40)",
        policies='allow if scope("mint_user_token")',
    )


def test_attenuation_amount_caveat_over_limit(keys: tuple[bytes, bytes]) -> None:
    """Numeric caveat with $a <= 50 rejects amount(75)."""
    priv, pub = keys
    parent = _mint(priv)
    child = attenuate_token(parent, pub, "check if amount($a), $a <= 50;")
    biscuit = verify_token(child, pub)
    with pytest.raises(TokenAuthorizationError):
        authorize_token(
            biscuit,
            facts=f"time({_now_iso()}); amount(75)",
            policies='allow if scope("mint_user_token")',
        )


# ---------------------------------------------------------------------------
# Envelope wire format
# ---------------------------------------------------------------------------


def test_envelope_make_then_parse_is_lossless() -> None:
    """make_envelope then parse_envelope returns the exact original parts."""
    payload = "EsECCt0123_ABC-XYZ"  # base64 with underscore (legal URL-safe)
    env = make_envelope("live", "support-bot", payload)
    parsed_env, parsed_proj, parsed_payload = parse_envelope(env)
    assert parsed_env == "live"
    assert parsed_proj == "support-bot"
    assert parsed_payload == payload


def test_envelope_preserves_underscores_in_biscuit_payload() -> None:
    """Biscuit b64 contains underscores; the parser must keep them intact."""
    biscuit_with_underscores = "abc_def_ghi_jkl_with_lots_of_underscores"
    env = make_envelope("test", "my-project", biscuit_with_underscores)
    _, _, parsed = parse_envelope(env)
    assert parsed == biscuit_with_underscores


def test_envelope_preserves_hyphens_in_project_id() -> None:
    """Project ids with hyphens (the common case) round-trip cleanly."""
    env = make_envelope("live", "support-bot-v2", "BISCUIT")
    _, project, _ = parse_envelope(env)
    assert project == "support-bot-v2"


def test_parse_envelope_rejects_missing_fty_prefix() -> None:
    """Envelopes without the fty_ prefix are not Hexgate tokens."""
    with pytest.raises(TokenError):
        parse_envelope("notfty_live_project_biscuit")


def test_parse_envelope_rejects_too_few_segments() -> None:
    """Envelopes that don't have all 4 underscore segments are malformed."""
    with pytest.raises(TokenError):
        parse_envelope("fty_live_only-three")


def test_parse_envelope_rejects_empty_string() -> None:
    """An empty input is not a valid envelope."""
    with pytest.raises(TokenError):
        parse_envelope("")
