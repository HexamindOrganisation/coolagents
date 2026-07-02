"""Tests for the file-backed Ed25519 keystore."""

from __future__ import annotations

import re
import threading
from pathlib import Path

import pytest

from hexgate_api.core.keystore import (
    PRIVATE_KEY_FILENAME,
    PUBLIC_KEY_FILENAME,
    FileKeyStore,
    resolve_keystore_dir,
)


# ---------------------------------------------------------------------------
# First-run generation
# ---------------------------------------------------------------------------


def test_first_run_generates_keypair_and_persists_both_halves(tmp_path: Path) -> None:
    """First call to ensure_keypair() writes both private and public files."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()

    assert (tmp_path / PRIVATE_KEY_FILENAME).exists()
    assert (tmp_path / PUBLIC_KEY_FILENAME).exists()
    assert len(ks.public_key_bytes()) == 32
    assert len(ks._private_key_bytes()) == 32


def test_fingerprint_format_is_stable(tmp_path: Path) -> None:
    """Fingerprint matches sha256:<16 hex chars>."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()
    assert re.match(r"^sha256:[0-9a-f]{16}$", ks.fingerprint())


def test_private_key_has_0600_permissions(tmp_path: Path) -> None:
    """Private key file must be readable only by owner."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()

    mode = (tmp_path / PRIVATE_KEY_FILENAME).stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Idempotent reload
# ---------------------------------------------------------------------------


def test_second_run_reloads_same_keypair(tmp_path: Path) -> None:
    """Second invocation reads the existing key — never regenerates silently."""
    ks1 = FileKeyStore(base_dir=tmp_path)
    ks1.ensure_keypair()
    fp1 = ks1.fingerprint()
    pub1 = ks1.public_key_bytes()

    ks2 = FileKeyStore(base_dir=tmp_path)
    ks2.ensure_keypair()

    assert ks2.fingerprint() == fp1
    assert ks2.public_key_bytes() == pub1


def test_repeated_ensure_keypair_is_idempotent(tmp_path: Path) -> None:
    """ensure_keypair() called twice on the same instance is a no-op."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()
    fp1 = ks.fingerprint()
    ks.ensure_keypair()
    assert ks.fingerprint() == fp1


# ---------------------------------------------------------------------------
# Refuse to regenerate from a corrupted file
# ---------------------------------------------------------------------------


def test_corrupted_private_key_refuses_to_regenerate(tmp_path: Path) -> None:
    """A truncated key file raises rather than silently generating a new one.

    Silent regeneration would invalidate every token already minted, which is
    catastrophic — much worse than refusing to start.
    """
    FileKeyStore(base_dir=tmp_path).ensure_keypair()
    (tmp_path / PRIVATE_KEY_FILENAME).write_bytes(b"too short")

    ks = FileKeyStore(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="corrupted"):
        ks.ensure_keypair()


def test_oversized_private_key_refuses_to_load(tmp_path: Path) -> None:
    """The same loud refusal applies for any non-32-byte private key file."""
    FileKeyStore(base_dir=tmp_path).ensure_keypair()
    (tmp_path / PRIVATE_KEY_FILENAME).write_bytes(b"x" * 64)

    ks = FileKeyStore(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="corrupted"):
        ks.ensure_keypair()


# ---------------------------------------------------------------------------
# Pre-init usage rejected
# ---------------------------------------------------------------------------


def test_sign_before_init_raises(tmp_path: Path) -> None:
    """Calling sign() before ensure_keypair() must fail explicitly."""
    ks = FileKeyStore(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="not initialised"):
        ks.sign(b"payload")


def test_public_key_before_init_raises(tmp_path: Path) -> None:
    """public_key_bytes before init has no key material to return."""
    ks = FileKeyStore(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="not initialised"):
        ks.public_key_bytes()


def test_private_key_bytes_before_init_raises(tmp_path: Path) -> None:
    """The biscuit-bridge accessor refuses pre-init too."""
    ks = FileKeyStore(base_dir=tmp_path)
    with pytest.raises(RuntimeError, match="not initialised"):
        ks._private_key_bytes()


# ---------------------------------------------------------------------------
# Signing properties
# ---------------------------------------------------------------------------


def test_signing_is_deterministic_per_key(tmp_path: Path) -> None:
    """Ed25519 sigs are deterministic — same key + same payload → same sig."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()

    sig1 = ks.sign(b"hello")
    sig2 = ks.sign(b"hello")
    assert sig1 == sig2
    assert len(sig1) == 64


def test_signing_changes_with_payload(tmp_path: Path) -> None:
    """Different payloads produce different signatures."""
    ks = FileKeyStore(base_dir=tmp_path)
    ks.ensure_keypair()
    assert ks.sign(b"a") != ks.sign(b"b")


# ---------------------------------------------------------------------------
# Different stores produce different keys
# ---------------------------------------------------------------------------


def test_different_keystores_produce_different_keys(tmp_path: Path) -> None:
    """Two fresh keystores in separate dirs must not collide."""
    a = FileKeyStore(base_dir=tmp_path / "a")
    b = FileKeyStore(base_dir=tmp_path / "b")
    a.ensure_keypair()
    b.ensure_keypair()

    assert a.fingerprint() != b.fingerprint()
    assert a.public_key_bytes() != b.public_key_bytes()


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def test_resolve_keystore_dir_respects_env_var(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HEXGATE_KEYSTORE_PATH env var overrides the default directory."""
    custom = tmp_path / "custom_keys"
    monkeypatch.setenv("HEXGATE_KEYSTORE_PATH", str(custom))
    assert resolve_keystore_dir() == custom.resolve()


def test_resolve_keystore_dir_default_when_env_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the env var, fall back to the default directory."""
    monkeypatch.delenv("HEXGATE_KEYSTORE_PATH", raising=False)
    resolved = resolve_keystore_dir()
    # The default is platform/api/data/, resolved.
    assert resolved.name == "data"


# ---------------------------------------------------------------------------
# Race-safety
# ---------------------------------------------------------------------------


def test_concurrent_first_runs_resolve_to_one_keypair(tmp_path: Path) -> None:
    """Two threads bootstrapping at once must both end up with the same key.

    The O_CREAT|O_EXCL guard means at most one thread wins the file create;
    the other catches FileExistsError and falls back to load(). Either way,
    both threads see the same fingerprint.
    """
    barrier = threading.Barrier(4)
    fingerprints: list[str] = []
    errors: list[BaseException] = []

    def bootstrap() -> None:
        try:
            barrier.wait()
            ks = FileKeyStore(base_dir=tmp_path)
            ks.ensure_keypair()
            fingerprints.append(ks.fingerprint())
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=bootstrap) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(fingerprints) == 4
    assert len(set(fingerprints)) == 1
