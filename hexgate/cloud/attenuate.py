"""Attenuate a verified Hexgate token with user-scoped facts and checks.

An internal seam, not a call-site API: the runtime mints the per-request token
itself from the active :class:`~hexgate.runtime.context.HexgateContext` (see
``agents/factory.py``), taking the project-wide token from ``HEXGATE_API_KEY``
and appending a per-user block before invoking the agent. The new envelope still
chains to the platform's root public key — biscuit's ``append`` protocol handles
the signature linkage with an ephemeral keypair, so the dev never holds the
platform's private key.

The Playground demo drives the same code path from the dev's local
``hexgate --serve`` process: it receives the "act as alice" metadata over the
WebSocket from the dashboard and attenuates in-process. Same chain, different
trigger.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

from hexgate.cloud.biscuit import (
    TokenError,
    TokenSignatureError,
    parse_envelope,
)

# Dedup only, not ``resolve_role_set``: a token records what the caller claimed,
# so capping or substituting a default would make it disagree with the request.
from hexgate.runtime.roles import distinct_roles


def _escape_datalog_string(value: str) -> str:
    """Escape ``value`` for safe embedding inside a Biscuit string literal.

    Backslashes and double-quotes are the only metacharacters Biscuit's
    Datalog lexer treats specially inside ``"..."``. Escaping them prevents
    a user-supplied identifier from breaking out of the quote and injecting
    extra facts or checks into the attenuation block.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def attenuate_for_user(
    parent_envelope: str,
    public_key_bytes: bytes,
    *,
    user: str,
    roles: Sequence[str] | None = None,
    ttl_seconds: int | None = None,
) -> str:
    """Return a new envelope with a user-attribution block appended.

    Verifies ``parent_envelope`` against ``public_key_bytes`` first, then
    appends a Biscuit block carrying:

    * ``user("...")`` — the authenticated user id.
    * one ``role("...")`` fact per entry in ``roles`` — the whole set, since the
      runtime enforces every role; attesting one would leave the rest unsigned.
      Biscuit facts are multi-valued, so readers need no change.
    * ``check if time($t), $t < <now+ttl_seconds>`` when ``ttl_seconds`` is
      set, narrowing the parent's TTL (or adding one if the parent had none).

    The resulting envelope keeps the ``fty_<env>_<project>_<...>`` wire
    format unchanged — only the biscuit payload grows by one block.

    Capability granularity (which tools the user can call, with what
    constraints) is no longer carried in the token — it lives in the role's
    ``policy.yaml`` file the agent loads. Tokens carry identity facts;
    policies carry rules.

    Raises:
        TypeError: ``roles`` is a bare ``str`` rather than a sequence of names.
        TokenError: malformed envelope, a malformed role string, or non-positive
            ``ttl_seconds``.
        TokenSignatureError: malformed public key, or parent biscuit fails
            to verify (tampered / wrong key / corrupt payload).
    """
    from biscuit_auth import (
        Algorithm,
        Biscuit,
        BiscuitValidationError,
        BlockBuilder,
        PublicKey,
    )

    env, project_id, biscuit_b64 = parse_envelope(parent_envelope)

    try:
        pub = PublicKey.from_bytes(public_key_bytes, Algorithm.Ed25519)
    except (ValueError, TypeError) as exc:
        raise TokenSignatureError(f"malformed public key: {exc}") from exc
    try:
        parent = Biscuit.from_base64(biscuit_b64, pub)
    except BiscuitValidationError as exc:
        raise TokenSignatureError(str(exc)) from exc

    source_lines: list[str] = [f'user("{_escape_datalog_string(user)}");']
    for role in distinct_roles(roles or ()):
        if not isinstance(role, str) or not role:
            raise TokenError(f"role must be a non-empty string, got {role!r}")
        source_lines.append(f'role("{_escape_datalog_string(role)}");')
    if ttl_seconds is not None:
        if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise TokenError(f"ttl_seconds must be a positive int, got {ttl_seconds!r}")
        expiry = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        source_lines.append(
            f"check if time($t), $t < {expiry.strftime('%Y-%m-%dT%H:%M:%SZ')};"
        )

    block = BlockBuilder("\n".join(source_lines))
    child = parent.append(block)
    return f"fty_{env}_{project_id}_{child.to_base64()}"
