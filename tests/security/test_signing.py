"""Tests for the Ed25519 signing primitives (M2 phase 6).

Pure crypto — no opa, no platform. These exercise the round-trip and
the failure modes that matter for bundle verification: tampered
payloads, wrong keys, malformed inputs.
"""

from __future__ import annotations

import pytest

from hexgate.security import (
    SignatureError,
    decode_key,
    encode_key,
    generate_keypair,
    public_key_for,
    sign_bytes,
    verify_bytes,
)

# ---------------------------------------------------------------------------
# Keygen
# ---------------------------------------------------------------------------


def test_generate_keypair_returns_raw_32_byte_keys() -> None:
    """Keys are raw 32-byte Ed25519 — matches the platform keystore format."""
    private_raw, public_raw = generate_keypair()
    assert len(private_raw) == 32
    assert len(public_raw) == 32


def test_generate_keypair_is_random() -> None:
    """Two calls produce different keys."""
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    assert a_priv != b_priv
    assert a_pub != b_pub


def test_public_key_for_derives_matching_public_key() -> None:
    """The public key derived from a private key matches keygen's output."""
    private_raw, public_raw = generate_keypair()
    assert public_key_for(private_raw) == public_raw


# ---------------------------------------------------------------------------
# Sign / verify round-trip
# ---------------------------------------------------------------------------


def test_sign_returns_64_byte_signature() -> None:
    private_raw, _ = generate_keypair()
    sig = sign_bytes(b"payload", private_raw)
    assert len(sig) == 64


def test_verify_accepts_valid_signature() -> None:
    private_raw, public_raw = generate_keypair()
    data = b"the manifest bytes"
    sig = sign_bytes(data, private_raw)
    verify_bytes(data, sig, public_raw)  # no raise == pass


def test_verify_rejects_tampered_payload() -> None:
    private_raw, public_raw = generate_keypair()
    sig = sign_bytes(b"original", private_raw)
    with pytest.raises(SignatureError, match="does not match"):
        verify_bytes(b"tampered", sig, public_raw)


def test_verify_rejects_wrong_public_key() -> None:
    """A signature from key A doesn't verify under key B."""
    a_priv, _ = generate_keypair()
    _, b_pub = generate_keypair()
    sig = sign_bytes(b"payload", a_priv)
    with pytest.raises(SignatureError):
        verify_bytes(b"payload", sig, b_pub)


def test_verify_rejects_corrupted_signature() -> None:
    private_raw, public_raw = generate_keypair()
    sig = bytearray(sign_bytes(b"payload", private_raw))
    sig[0] ^= 0xFF  # flip a byte
    with pytest.raises(SignatureError):
        verify_bytes(b"payload", bytes(sig), public_raw)


# ---------------------------------------------------------------------------
# Malformed inputs
# ---------------------------------------------------------------------------


def test_sign_rejects_malformed_private_key() -> None:
    with pytest.raises(SignatureError, match="invalid private key"):
        sign_bytes(b"payload", b"too short")


def test_verify_rejects_malformed_public_key() -> None:
    sig = sign_bytes(b"payload", generate_keypair()[0])
    with pytest.raises(SignatureError, match="invalid public key"):
        verify_bytes(b"payload", sig, b"not a key")


# ---------------------------------------------------------------------------
# base64url encoding (matches platform JWKS + HEXGATE_PUBLIC_KEY wire format)
# ---------------------------------------------------------------------------


def test_encode_decode_round_trip() -> None:
    _, public_raw = generate_keypair()
    assert decode_key(encode_key(public_raw)) == public_raw


def test_encode_strips_padding() -> None:
    """base64url output has no '=' padding — matches the platform's keys."""
    _, public_raw = generate_keypair()
    assert "=" not in encode_key(public_raw)


def test_decode_tolerates_missing_padding() -> None:
    """A key string minted without padding still decodes (platform compat)."""
    _, public_raw = generate_keypair()
    encoded = encode_key(public_raw)  # already unpadded
    assert decode_key(encoded) == public_raw


def test_decode_rejects_non_base64() -> None:
    with pytest.raises(SignatureError, match="not valid base64url"):
        decode_key("!!!not base64!!!")
