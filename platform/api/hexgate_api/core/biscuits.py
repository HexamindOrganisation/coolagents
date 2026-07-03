"""Mint, verify, attenuate, and authorize Hexgate dev/user tokens.

Every Hexgate token is a Biscuit (https://www.biscuitsec.org/) — a Datalog-
based capability token signed by the platform's root keypair. The shape of
the claims we put in is intentionally flat:

    project("support-bot");
    token_id("tok_abc123");
    name("ci-deploy");
    scope("mint_user_token");
    scope("read_audit");
    env("live");
    issued_at(2026-05-06T...Z);
    check if time($t), $t < 2027-05-06T...Z;     // optional TTL

Verification uses the platform's public key — anyone holding it can prove
the token was signed by Hexgate. Attenuation lets the dev's backend add
narrowing checks (``user("alice")``, ``refund_limit(50)``, …) without ever
seeing the platform's private key.

This module is a thin wrapper over ``biscuit-python``. It exists so the
rest of the codebase doesn't have to import ``biscuit_auth`` directly and
so we can swap implementations later without rippling through every caller.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from biscuit_auth import (
    Algorithm,
    AuthorizationError,
    Authorizer,
    AuthorizerBuilder,
    Biscuit,
    BiscuitBuilder,
    BiscuitValidationError,
    BlockBuilder,
    PrivateKey,
    PublicKey,
)


class TokenError(RuntimeError):
    """Base class for token-related failures."""


class TokenSignatureError(TokenError):
    """Raised when a Biscuit's signature does not chain to the expected key."""


class TokenAuthorizationError(TokenError):
    """Raised when an Authorizer rejects a token (caveat fail, no policy match)."""


class MintRequest:
    """Inputs for minting a fresh dev/user token.

    Kept as a small data holder rather than a Pydantic model because this
    is wire-internal — it never leaves the API process.
    """

    __slots__ = ("project_id", "token_id", "name", "scopes", "env", "ttl_seconds")

    def __init__(
        self,
        *,
        project_id: str,
        token_id: str,
        name: str,
        scopes: Iterable[str],
        env: str,
        ttl_seconds: int | None = None,
    ) -> None:
        self.project_id = project_id
        self.token_id = token_id
        self.name = name
        self.scopes = tuple(scopes)
        self.env = env
        self.ttl_seconds = ttl_seconds


# ---------------------------------------------------------------------------
# Mint
# ---------------------------------------------------------------------------


def mint_token(private_key_bytes: bytes, request: MintRequest) -> str:
    """Sign a fresh Biscuit with ``private_key_bytes`` and return base64.

    The 32-byte raw Ed25519 private key (from ``keystore._private_key_bytes()``)
    is converted to a ``biscuit_auth.PrivateKey`` and used to seal the root
    block. The returned string is URL-safe base64; it goes straight into the
    ``fty_<env>_<project>_<biscuit>`` token format we hand to operators.

    Time facts use UTC ISO-8601. TTL is encoded as a ``check if time($t), $t < ...``
    block-level constraint so the verifier rejects expired tokens during
    authorize() — no separate expiry check needed.
    """
    priv = PrivateKey.from_bytes(private_key_bytes, Algorithm.Ed25519)

    issued_at = datetime.now(timezone.utc)
    facts = [
        f'project("{_escape(request.project_id)}")',
        f'token_id("{_escape(request.token_id)}")',
        f'name("{_escape(request.name)}")',
        f'env("{_escape(request.env)}")',
        f"issued_at({_datalog_datetime(issued_at)})",
    ]
    facts.extend(f'scope("{_escape(s)}")' for s in request.scopes)

    builder_source = "; ".join(facts) + ";"
    if request.ttl_seconds is not None:
        expires_at = issued_at.timestamp() + request.ttl_seconds
        expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc)
        builder_source += f" check if time($t), $t < {_datalog_datetime(expires_iso)};"

    biscuit = BiscuitBuilder(builder_source).build(priv)
    return biscuit.to_base64()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def verify_token(token_b64: str, public_key_bytes: bytes) -> Biscuit:
    """Parse and verify a Biscuit's signature chain.

    Raises :class:`TokenSignatureError` if the signature was made by a
    different key, the bytes are corrupted, or the encoded structure is
    invalid. Successful verification means *the token was signed by the
    holder of the private key matching* ``public_key_bytes`` — it does
    NOT mean any specific policy permits it. Authorize separately.
    """
    try:
        pub = PublicKey.from_bytes(public_key_bytes, Algorithm.Ed25519)
    except (ValueError, TypeError) as exc:
        raise TokenSignatureError(f"malformed public key: {exc}") from exc
    try:
        return Biscuit.from_base64(token_b64, pub)
    except BiscuitValidationError as exc:
        raise TokenSignatureError(str(exc)) from exc


# ---------------------------------------------------------------------------
# Attenuate (no signing key needed)
# ---------------------------------------------------------------------------


def attenuate_token(
    token_b64: str,
    public_key_bytes: bytes,
    block_source: str,
) -> str:
    """Append a narrowing block to a token and return base64.

    Express attenuations as **``check if`` rules**, not bare facts: by
    Biscuit's scoping rules, facts in non-authority blocks aren't visible
    to the authorizer's top-level policy unless you explicitly trust the
    block's signing key. Checks, on the other hand, are evaluated *with*
    the authorizer's facts in scope, which is exactly what we want for
    runtime enforcement.

    Typical use from a dev's backend at user-login time::

        attenuate_token(
            dev_token_b64,
            HEXGATE_PUBLIC_KEY,
            'check if user("alice");'
            'check if amount($a), $a <= 50;',
        )

    Then at runtime the agent's authorizer asserts ``user("alice")`` and
    ``amount(40)`` as facts; both checks pass, the token authorizes.
    Asserting ``user("bob")`` or ``amount(75)`` makes a check fail and
    authorization is rejected.

    The Biscuit library generates an ephemeral keypair for this block, so
    no long-lived secret is needed on the attenuating side. Verification
    still chains back to the platform's root public key. The original
    token is unchanged; this returns a new (longer) base64 string.
    """
    parent = verify_token(token_b64, public_key_bytes)
    attenuated = parent.append(BlockBuilder(block_source))
    return attenuated.to_base64()


# ---------------------------------------------------------------------------
# Authorize (apply a policy and check caveats)
# ---------------------------------------------------------------------------


def authorize_token(
    biscuit: Biscuit,
    *,
    facts: str = "",
    policies: str,
) -> Authorizer:
    """Run authorization against a verified ``Biscuit``.

    ``facts`` is request-time context the authorizer needs to evaluate
    checks — e.g. ``'time({now}); operation("read")'``. ``policies`` is one
    or more Datalog ``allow if ...`` / ``deny if ...`` rules that the
    authorizer evaluates after collecting all facts and checks. Raises
    :class:`TokenAuthorizationError` if no allow rule fires or any check
    fails.
    """
    source = "; ".join(s for s in (facts, policies) if s.strip()) + ";"
    authorizer = AuthorizerBuilder(source).build(biscuit)
    try:
        authorizer.authorize()
    except AuthorizationError as exc:
        raise TokenAuthorizationError(str(exc)) from exc
    return authorizer


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

ENVELOPE_PREFIX = "fty"


def make_envelope(env: str, project_id: str, biscuit_b64: str) -> str:
    """Wrap a base64 Biscuit in the human-readable Hexgate envelope.

    Format: ``fty_<env>_<project>_<biscuit_b64>``. The ``fty`` prefix and
    project id are duplicated outside the Biscuit (for grep / GitHub
    secret-scanning); the source of truth lives inside the Biscuit's claims.
    """
    return f"{ENVELOPE_PREFIX}_{env}_{project_id}_{biscuit_b64}"


def parse_envelope(envelope: str) -> tuple[str, str, str]:
    """Parse ``fty_<env>_<project>_<biscuit_b64>`` into ``(env, project, biscuit_b64)``.

    The biscuit base64 itself contains underscores (URL-safe), so we split
    on the first three underscores only — anything after the project segment
    is the Biscuit payload.
    """
    parts = envelope.split("_", 3)
    if len(parts) != 4 or parts[0] != ENVELOPE_PREFIX:
        raise TokenError(
            f"malformed Hexgate token envelope (expected '{ENVELOPE_PREFIX}_<env>_<project>_<biscuit>')"
        )
    env, project_id, biscuit_b64 = parts[1], parts[2], parts[3]
    return env, project_id, biscuit_b64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _escape(value: str) -> str:
    """Escape a string for safe inclusion in a Datalog fact literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _datalog_datetime(value: datetime) -> str:
    """Render a UTC datetime as a Biscuit-recognized RFC3339 literal."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    # Biscuit accepts RFC3339 with `Z` suffix for UTC.
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
