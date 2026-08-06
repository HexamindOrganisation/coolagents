"""Attenuate a verified Hexgate token with user-scoped facts and checks.

In production the dev's backend calls :func:`attenuate_for_user` on each
inbound request, taking the project-wide token from ``HEXGATE_API_KEY`` and
appending a per-user block before forwarding to the agent runner. The
new envelope still chains to the platform's root public key — biscuit's
``append`` protocol handles the signature linkage with an ephemeral
keypair, so the dev never holds the platform's private key.

For the Playground demo, the dev's local ``hexgate --serve`` process plays
the same role: it receives the "act as alice" metadata over the WebSocket
from the dashboard and runs the attenuation in-process before invoking
the agent. Same code path, same chain, different trigger.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from hexgate.cloud.biscuit import (
    TokenError,
    TokenSignatureError,
    parse_envelope,
)

# Scalar shapes a trusted attribute may carry into a signed ``attr`` fact.
# Mirrors ``hexgate.runtime.context.AttrValue`` minus ``list[str]`` — list-valued
# trusted attributes are rejected in v1 (kept advisory-only). Inlined rather than
# imported to avoid coupling the token layer to the runtime context module.
TrustedAttrValue = str | int | bool


def _escape_datalog_string(value: str) -> str:
    """Escape ``value`` for safe embedding inside a Biscuit string literal.

    Backslashes and double-quotes are the only metacharacters Biscuit's
    Datalog lexer treats specially inside ``"..."``. Escaping them prevents
    a user-supplied identifier from breaking out of the quote and injecting
    extra facts or checks into the attenuation block.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _render_attr_value(key: str, value: object) -> str:
    """Render a trusted attribute value as a typed Biscuit Datalog literal.

    ``bool`` is checked before ``int`` (``bool`` is an ``int`` subclass) so
    ``True`` renders as the Datalog boolean ``true``, not ``1``. Strings are
    escaped for injection safety; the type is preserved on the wire so
    ``extract_attr_facts`` reads back an ``int``/``bool``/``str``, and a
    numeric ``ctx.*`` comparison stays int-to-int on both engines.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return f'"{_escape_datalog_string(value)}"'
    if isinstance(value, list):
        raise TokenError(
            f"list-valued trusted attribute {key!r} is not supported yet; "
            "keep it advisory or use a scalar (str/int/bool)"
        )
    raise TokenError(
        f"trusted attribute {key!r} must be str/int/bool, got {type(value).__name__}"
    )


def attenuate_for_user(
    parent_envelope: str,
    public_key_bytes: bytes,
    *,
    user: str,
    role: str | None = None,
    ttl_seconds: int | None = None,
    attributes: Mapping[str, TrustedAttrValue] | None = None,
) -> str:
    """Return a new envelope with a user-attribution block appended.

    Verifies ``parent_envelope`` against ``public_key_bytes`` first, then
    appends a Biscuit block carrying:

    * ``user("...")`` — the authenticated user id.
    * ``role("...")`` — the user's role (when supplied), used by the agent
      runtime to pick the matching role policy file.
    * ``attr("<key>", <value>)`` for each entry in ``attributes`` — the
      *trusted* subset of the caller's ABAC bag, signed so the SDK can
      verify it rather than trust the spoofable contextvar value. The caller
      is responsible for passing only keys declared trusted by the policy;
      this function just signs what it's given. Values are typed literals
      (str/int/bool); list-valued attributes raise (see
      :func:`_render_attr_value`).
    * ``check if time($t), $t < <now+ttl_seconds>`` when ``ttl_seconds`` is
      set, narrowing the parent's TTL (or adding one if the parent had none).

    The resulting envelope keeps the ``fty_<env>_<project>_<...>`` wire
    format unchanged — only the biscuit payload grows by one block.

    Capability granularity (which tools the user can call, with what
    constraints) is no longer carried in the token — it lives in the role's
    ``policy.yaml`` file the agent loads. Tokens carry identity facts;
    policies carry rules.

    Raises:
        TokenError: malformed envelope, malformed role string, non-positive
            ``ttl_seconds``, or a trusted attribute with an unsupported
            (list / non-scalar) value.
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
    if role is not None:
        if not isinstance(role, str) or not role:
            raise TokenError(f"role must be a non-empty string, got {role!r}")
        source_lines.append(f'role("{_escape_datalog_string(role)}");')
    for key, value in (attributes or {}).items():
        if not isinstance(key, str) or not key:
            raise TokenError(
                f"trusted attribute key must be a non-empty string, got {key!r}"
            )
        rendered = _render_attr_value(key, value)
        source_lines.append(f'attr("{_escape_datalog_string(key)}", {rendered});')
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
