"""Root signing keypair for the Hexgate control plane.

Every Biscuit token and every signed policy bundle is signed by this keypair.
Once minted, tokens carry a signature chain that verifies all the way back to
the *public* half of this key — which is embedded in the SDK package.

Bootstrap behaviour:

- On first launch, generate a fresh Ed25519 keypair and persist it to
  ``platform/api/data/hexgate.priv`` (private, ``0600``) and
  ``platform/api/data/hexgate.pub`` (public, ``0644``).
  A loud, one-shot warning is logged so operators back it up.

- On subsequent launches, load the existing pair. Cheap, idempotent.

The path is overridable via ``HEXGATE_KEYSTORE_PATH`` so prod can point at
``/var/lib/hexgate/keys`` (or wherever the operator stores secrets). The
location is a directory; we always look for ``hexgate.priv`` and
``hexgate.pub`` inside it.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hexgate_api import API_ROOT

logger = logging.getLogger(__name__)

PRIVATE_KEY_FILENAME = "hexgate.priv"
PUBLIC_KEY_FILENAME = "hexgate.pub"
DEFAULT_KEYSTORE_DIR = API_ROOT / "data"


class KeyStore(Protocol):
    """Abstract signing surface — file-backed today, KMS-backed eventually."""

    def sign(self, payload: bytes) -> bytes:
        """Return an Ed25519 signature over ``payload``."""

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key."""

    def fingerprint(self) -> str:
        """Return a short, stable identifier for the public key."""


def resolve_keystore_dir() -> Path:
    """Locate the keystore directory from env or fall back to the default."""
    raw = os.environ.get("HEXGATE_KEYSTORE_PATH")
    if raw:
        return Path(raw).expanduser().resolve()
    return DEFAULT_KEYSTORE_DIR.resolve()


class FileKeyStore:
    """Filesystem-backed Ed25519 keystore.

    Generates a fresh keypair on first use and reloads it on subsequent
    starts. Multi-process race protection: the private key file is created
    with ``O_CREAT | O_EXCL`` so two simultaneous starts can't both win.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        """Initialise paths only — no filesystem access yet.

        Pass an explicit ``base_dir`` to override ``HEXGATE_KEYSTORE_PATH``
        (useful for tests). The keypair is not loaded or generated until
        :meth:`ensure_keypair` is called, so constructing the keystore is
        cheap and side-effect-free.
        """
        self._base_dir = (base_dir or resolve_keystore_dir()).resolve()
        self._private_path = self._base_dir / PRIVATE_KEY_FILENAME
        self._public_path = self._base_dir / PUBLIC_KEY_FILENAME
        self._private_key: Ed25519PrivateKey | None = None
        self._public_key: Ed25519PublicKey | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def ensure_keypair(self) -> None:
        """Generate-or-load. Idempotent, safe to call on every startup."""
        self._base_dir.mkdir(parents=True, exist_ok=True)
        if self._private_path.exists():
            self._load()
            logger.info(
                "loaded hexgate keypair from %s (fingerprint=%s)",
                self._private_path,
                self.fingerprint(),
            )
            return
        self._generate_and_persist()
        self._announce_first_run()

    # ------------------------------------------------------------------
    # KeyStore protocol
    # ------------------------------------------------------------------

    def sign(self, payload: bytes) -> bytes:
        """Return a 64-byte Ed25519 signature over ``payload``.

        Raises if the keypair hasn't been loaded yet — call
        :meth:`ensure_keypair` once at startup before any signing happens.
        """
        if self._private_key is None:
            raise RuntimeError("keystore not initialised; call ensure_keypair() first")
        return self._private_key.sign(payload)

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key.

        Used by the JWKS endpoint, the dashboard's fingerprint display, and
        anywhere we need to hand the public key to verifiers. Returns the
        unwrapped 32 bytes (not PEM/DER) so callers can reformat as they
        please.
        """
        if self._public_key is None:
            raise RuntimeError("keystore not initialised; call ensure_keypair() first")
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def _private_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 private key.

        Internal only. Exposed so signing libraries that need their own
        ``PrivateKey`` objects (e.g. ``biscuit_auth.PrivateKey``) can
        construct one from the same key material. Never log, serialize, or
        transmit these bytes — callers should hand the result straight
        into the signing library and discard.

        A future ``KMSKeyStore`` would not implement this method; callers
        that target multiple keystore backends should use ``sign()`` instead.
        """
        if self._private_key is None:
            raise RuntimeError("keystore not initialised; call ensure_keypair() first")
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def fingerprint(self) -> str:
        """Return a short stable identifier for the public key.

        Format: ``sha256:<first 16 hex chars of SHA-256(pubkey_bytes)>``.
        Two SDK builds embedding the same public key will produce the same
        fingerprint — useful for sanity-checking that an SDK's embedded
        key matches what the platform is actually signing with.
        """
        digest = hashlib.sha256(self.public_key_bytes()).hexdigest()
        return f"sha256:{digest[:16]}"

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Read and parse an existing private key from disk.

        Raises with a loud message if the file is the wrong size — silently
        regenerating in that case would invalidate every token already
        minted, which is much worse than a startup failure.
        """
        private_bytes = self._private_path.read_bytes()
        if len(private_bytes) != 32:
            raise RuntimeError(
                f"corrupted private key at {self._private_path} "
                f"(expected 32 bytes, got {len(private_bytes)}). "
                f"Refusing to silently regenerate — this would invalidate every token in the wild."
            )
        self._private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        self._public_key = self._private_key.public_key()

    def _generate_and_persist(self) -> None:
        """Generate a fresh keypair and write both halves to disk atomically.

        Race protection uses the write-temp-then-link pattern so a
        concurrent reader never observes the canonical file in a
        partially-written state:

          1. Write the private bytes to a uniquely-named temp file in the
             same directory.
          2. Atomically link the temp into the canonical path via
             ``os.link``. POSIX link is atomic and refuses to clobber an
             existing target — ``FileExistsError`` is the signal that
             another process won the race.
          3. Always unlink the temp.

        The previous implementation called ``os.open(... O_CREAT|O_EXCL)``
        directly on the canonical path. That made the file visible to
        readers immediately, but empty, until ``os.write`` completed —
        opening a window in which a concurrent ``_load()`` would observe
        a zero-byte file and raise "corrupted private key". The bug was
        invisible on macOS dev boxes (scheduling rarely hit the window
        with only a handful of threads) but reproduced on slower Linux
        CI runners.
        """
        private_key = Ed25519PrivateKey.generate()
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Temp file in the same directory so ``os.link`` stays intra-FS
        # (links across mounts fail with EXDEV). Random suffix so two
        # concurrent threads pick non-colliding names.
        tmp_path = self._private_path.with_name(
            f".{self._private_path.name}.tmp.{secrets.token_hex(8)}"
        )
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, private_bytes)
        finally:
            os.close(fd)

        try:
            os.link(tmp_path, self._private_path)
        except FileExistsError:
            # Another thread already linked the canonical path — adopt
            # their keypair instead of overwriting it.
            tmp_path.unlink(missing_ok=True)
            self._load()
            return
        finally:
            # Always clean up the temp, whether link succeeded or raced.
            tmp_path.unlink(missing_ok=True)

        self._public_path.write_bytes(public_bytes)
        try:
            os.chmod(self._public_path, 0o644)
        except OSError:
            pass

        self._private_key = private_key
        self._public_key = private_key.public_key()

    def _announce_first_run(self) -> None:
        """Log a loud, one-shot warning after generating a fresh keypair.

        Operators should back up the file before issuing any tokens. We
        only emit this on first generation — subsequent boots stay quiet
        with a debug-level "loaded keypair" line instead.
        """
        bar = "=" * 72
        logger.warning(
            "\n%s\n"
            "GENERATED HEXGATE ROOT KEYPAIR\n"
            "   path:        %s\n"
            "   fingerprint: %s\n\n"
            "This key signs every Biscuit token and policy bundle this platform\n"
            "issues. If you lose it:\n"
            "  - every minted token becomes unverifiable\n"
            "  - every deployed SDK rejects your bundles as tampered\n\n"
            "Back it up before anything else. Keep the file at chmod 0600.\n"
            "Never commit it to version control.\n"
            "%s",
            bar,
            self._private_path,
            self.fingerprint(),
            bar,
        )


# Process-wide signing keystore singleton. Construction is side-effect-free
# (no filesystem access until ensure_keypair()); the app lifespan calls
# ensure_keypair() at startup. Readers import this name lazily at call time so
# a test swap of ``core.keystore.keystore`` is picked up.
keystore = FileKeyStore()
