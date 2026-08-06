"""Biscuit verification helpers for the SDK side.

The platform mints Biscuit tokens signed by its root Ed25519 keypair. The
SDK verifies them locally before trusting them for any call. We deliberately
mirror only the *verify-side* of the platform's wrapper — minting and
attenuation are platform/dev concerns and don't belong in the SDK runtime.

Three responsibilities live here:

1. Parse the human-readable envelope ``fty_<env>_<project>_<biscuit_b64>``
   into its parts. The Biscuit payload itself contains underscores
   (URL-safe base64), so the parser splits on the first three only.

2. Verify the signature chain against an expected public key. A token
   that was tampered with, signed by a different key, or just garbled
   raises :class:`TokenSignatureError`.

3. Extract single-arity facts from every block of a verified token, so the
   policy engine can read user attribution / scope / numeric-limit metadata
   stamped in by the dev's backend during attenuation.

Defense in depth — the platform also verifies on the bearer-auth path,
but verifying client-side catches misconfiguration at startup instead of
on the first failed API call.
"""

from __future__ import annotations

import re

ENVELOPE_PREFIX = "fty"


class TokenError(RuntimeError):
    """Base class for token-related failures."""


class TokenSignatureError(TokenError):
    """Raised when a Biscuit's signature does not chain to the expected key."""


# Matches a single-arity Datalog fact `predicate(value);` where value is either
# a double-quoted string or a bare integer literal. Multi-arg facts, dates,
# bytes, sets, and rules are intentionally skipped — M1's policy engine only
# needs flat user / scope / limit metadata. The full Datalog grammar is biscuit-
# python's job; we just want the cheap, common shape here.
_FACT_LINE_RE = re.compile(
    r"""
    ^\s*                            # leading whitespace
    (?P<name>[a-z][a-zA-Z0-9_]*)    # predicate name (Datalog convention: lowercase head)
    \s*\(\s*                        # opening paren
    (?:
        "(?P<str>(?:[^"\\]|\\.)*)"  # double-quoted string (with \" / \\ escapes)
      |
        (?P<int>-?\d+)              # bare integer
    )
    \s*\)\s*;                       # closing paren + semicolon
    \s*$                            # trailing whitespace
    """,
    re.VERBOSE,
)


# Matches a two-arity Datalog fact `attr("key", value);` where value is a
# double-quoted string, a bare integer, or a Datalog boolean. This is the
# reserved shape the SDK's signed-attribute (ABAC trusted tier) convention
# uses — deliberately distinct from the single-arity `_FACT_LINE_RE` so the
# identity/limit extractor and the attribute extractor never fight over the
# same lines.
_ATTR_LINE_RE = re.compile(
    r"""
    ^\s*attr\s*\(\s*
    "(?P<key>(?:[^"\\]|\\.)*)"       # attribute key (quoted string)
    \s*,\s*
    (?:
        "(?P<str>(?:[^"\\]|\\.)*)"   # string value (with \" / \\ escapes)
      | (?P<bool>true|false)         # datalog boolean
      | (?P<int>-?\d+)               # bare integer
    )
    \s*\)\s*;\s*$
    """,
    re.VERBOSE,
)


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


def verify_biscuit(token_b64: str, public_key_bytes: bytes) -> None:
    """Verify a Biscuit's signature against ``public_key_bytes``.

    Raises :class:`TokenSignatureError` on tamper, malformed key, or
    corrupt payload. Returns nothing on success — verification means *the
    token was signed by the holder of the matching private key*, not that
    any specific policy permits it. The platform decides the latter.

    ``biscuit-python`` is imported lazily so importing this module doesn't
    pay the native-library load cost when the SDK is used purely offline
    (e.g., loading local agents without ``HEXGATE_API_KEY``).
    """
    from biscuit_auth import (
        Algorithm,
        Biscuit,
        BiscuitValidationError,
        PublicKey,
    )

    try:
        pub = PublicKey.from_bytes(public_key_bytes, Algorithm.Ed25519)
    except (ValueError, TypeError) as exc:
        raise TokenSignatureError(f"malformed public key: {exc}") from exc
    try:
        Biscuit.from_base64(token_b64, pub)
    except BiscuitValidationError as exc:
        raise TokenSignatureError(str(exc)) from exc


def extract_facts(
    token_b64: str, public_key_bytes: bytes
) -> dict[str, list[str | int]]:
    """Verify ``token_b64`` and return single-arity facts across every block.

    Returns ``{predicate: [value, ...]}`` where each value is a ``str`` or
    ``int``, in source order, unioned across the authority block and all
    attenuation blocks. The same predicate appearing in multiple blocks (e.g.
    ``scope("read")`` in the authority and ``scope("write")`` in a child
    block) accumulates — Datalog's natural union semantics, and the safety
    property that prevents an attenuator from "removing" a prior fact.

    Multi-arg facts, rules, checks, and non-string/non-integer literals are
    silently skipped: M1's structured policy predicates only consume the
    common ``name("value")`` / ``name(N)`` shape. The full Datalog surface
    is left to biscuit-python's own authorizer once we move to Datalog-native
    policy rules in M2.

    Raises :class:`TokenSignatureError` for the same reasons as
    :func:`verify_biscuit` — we re-verify here so callers never use facts
    from an untrusted token by mistake.
    """
    from biscuit_auth import (
        Algorithm,
        Biscuit,
        BiscuitValidationError,
        PublicKey,
    )

    try:
        pub = PublicKey.from_bytes(public_key_bytes, Algorithm.Ed25519)
    except (ValueError, TypeError) as exc:
        raise TokenSignatureError(f"malformed public key: {exc}") from exc
    try:
        biscuit = Biscuit.from_base64(token_b64, pub)
    except BiscuitValidationError as exc:
        raise TokenSignatureError(str(exc)) from exc

    facts: dict[str, list[str | int]] = {}
    for idx in range(biscuit.block_count()):
        source = biscuit.block_source(idx)
        if source is None:
            continue
        for line in source.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if stripped.startswith("check ") or "<-" in stripped:
                # checks and rules — biscuit's authorizer enforces these;
                # the SDK policy engine only wants ground facts.
                continue
            match = _FACT_LINE_RE.match(line)
            if match is None:
                continue
            name = match.group("name")
            if match.group("str") is not None:
                # Biscuit string literals only define two escapes (\\" and \\\\);
                # unescape them directly. ``unicode_escape`` would re-decode the
                # bytes as Latin-1 and mangle multibyte UTF-8 (``café`` → ``cafÃ©``).
                value: str | int = re.sub(r'\\(["\\])', r"\1", match.group("str"))
            else:
                value = int(match.group("int"))
            facts.setdefault(name, []).append(value)
    return facts


def _unescape_datalog_string(raw: str) -> str:
    """Reverse ``_escape_datalog_string`` — collapse ``\\"`` / ``\\\\`` only."""
    return re.sub(r'\\(["\\])', r"\1", raw)


def extract_attr_facts(
    token_b64: str, public_key_bytes: bytes
) -> dict[str, str | int | bool]:
    """Verify ``token_b64`` and return its signed ``attr("key", value)`` facts.

    Returns ``{key: value}`` for every two-arity ``attr`` fact across all
    blocks, with the value typed back to ``str`` / ``int`` / ``bool`` from its
    Datalog literal. This is the SDK read-side of the signed trusted-attribute
    (ABAC) tier — the enforcer prefers these *verified* values over the
    spoofable ``HexgateContext.attributes`` bag for declared trusted keys.

    Duplicate keys across attenuation blocks resolve **last-writer-wins** (a
    later block may only narrow, never elide, so the most-attenuated value is
    the effective one). Single-arity facts, checks, rules, and non-``attr``
    predicates are ignored — :func:`extract_facts` owns the identity/limit
    shape.

    Raises :class:`TokenSignatureError` for the same reasons as
    :func:`verify_biscuit` — the token is re-verified here so callers never
    read attributes off an untrusted token by mistake.
    """
    from biscuit_auth import (
        Algorithm,
        Biscuit,
        BiscuitValidationError,
        PublicKey,
    )

    try:
        pub = PublicKey.from_bytes(public_key_bytes, Algorithm.Ed25519)
    except (ValueError, TypeError) as exc:
        raise TokenSignatureError(f"malformed public key: {exc}") from exc
    try:
        biscuit = Biscuit.from_base64(token_b64, pub)
    except BiscuitValidationError as exc:
        raise TokenSignatureError(str(exc)) from exc

    attrs: dict[str, str | int | bool] = {}
    for idx in range(biscuit.block_count()):
        source = biscuit.block_source(idx)
        if source is None:
            continue
        for line in source.splitlines():
            match = _ATTR_LINE_RE.match(line)
            if match is None:
                continue
            key = _unescape_datalog_string(match.group("key"))
            if match.group("str") is not None:
                value: str | int | bool = _unescape_datalog_string(match.group("str"))
            elif match.group("bool") is not None:
                value = match.group("bool") == "true"
            else:
                value = int(match.group("int"))
            attrs[key] = value
    return attrs
