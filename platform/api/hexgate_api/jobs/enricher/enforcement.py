"""Authoritative server-side redaction + byte caps for decision payloads.

Same pipeline the SDK applies client-side (imported from hexgate.audit, not
copied — two implementations would drift), but here it is enforcement: the
batch inserts trust their input and never re-check, so this is the single
point where oversized or secret-bearing payloads get trimmed. Order and
gating mirror ``AuditEvent.as_payload``: arguments are redacted (substring
key match) then capped at 8 KiB; hint is capped at 4 KiB but never redacted
(policy config, not caller data); attributes are redacted (anchored key
match) then capped at 4 KiB, with a falsy bag normalised to None.
"""

from __future__ import annotations

from typing import Any

from hexgate.audit import (
    MAX_ARGS_BYTES,
    MAX_ATTRIBUTES_BYTES,
    MAX_HINT_BYTES,
    SENSITIVE_ARG_KEY_RE,
    SENSITIVE_ATTR_KEY_RE,
    bounded_violations,
    redact,
    truncate_json,
)


def capped_arguments(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return truncate_json(
        redact(value, pattern=SENSITIVE_ARG_KEY_RE), cap=MAX_ARGS_BYTES
    )


def capped_hint(value: dict[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return truncate_json(value, cap=MAX_HINT_BYTES)


def capped_attributes(value: dict[str, Any] | None) -> dict[str, Any] | None:
    # Falsy, not ``is not None`` — {} and None both store as absent downstream.
    if not value:
        return None
    return truncate_json(
        redact(value, pattern=SENSITIVE_ATTR_KEY_RE), cap=MAX_ATTRIBUTES_BYTES
    )


def capped_violations(values: list[str]) -> list[str]:
    return bounded_violations(values)
