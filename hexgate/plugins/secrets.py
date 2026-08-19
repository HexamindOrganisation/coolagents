"""Secret detection for the official guards.

One detector, shared by ``secret_guard`` (refuse), ``secret_redactor`` (strip),
and ``secret_watch`` (flag). It is deliberately conservative: a false positive on
a before-guard blocks a real tool call, so v1 matches only high-confidence
provider prefixes (the gitleaks / trufflehog approach). Catching unprefixed
secrets by entropy is deferred (see ``docs/adr/R-GUARD-005``): a per-string
entropy test cannot tell a base64 secret from a base64 hash, so on a fail-closed
guard it blocks legitimate calls.

The detector never surfaces a matched value. A :class:`SecretHit` carries the
category, the JSON path to the field, and a short SHA-256 ``fingerprint`` for
audit correlation, so a ``Halt.reason`` / ``Modification.summary`` built from hits
names *what* and *where*, never the secret itself.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# High-confidence provider patterns
# ---------------------------------------------------------------------------

# (category, compiled pattern). Anchored on the provider's own prefix + length,
# so a match is a strong signal on its own — no entropy check needed. Ordered
# most-specific first; every finditer match on a string leaf becomes a hit.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    # anthropic before openai: `sk-ant-…` matches both `sk-…` patterns, and the
    # first accepted span wins, so the more specific one must come first.
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}\b")),
    # fty_<env>_<project>_<biscuit_b64>, env in {test, live} (hexgate/cloud/
    # biscuit.py). The body carries `_`/`-` (url-safe base64), so the charset
    # after the env must include them — a plain [A-Za-z0-9] run stops at the
    # first `_` and never matches a real token.
    ("hexgate_token", re.compile(r"\bfty_(?:test|live)_[A-Za-z0-9_-]{24,}")),
    # Match the whole block so redaction strips the key material, not just the
    # header: to the END line when present, else (a truncated block) to the next
    # blank line or end of string. `(?: BLOCK)?` covers the PGP variant.
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )?PRIVATE KEY(?: BLOCK)?-----"
            r"|[\s\S]*?(?=\n[ \t]*\n|\Z))"
        ),
    ),
]

# ---------------------------------------------------------------------------
# Hit + string-level matching
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecretHit:
    """One detected secret, safe to log. ``field`` is the JSON path to the leaf
    (``""`` for a bare string); ``fingerprint`` is ``sha256(value)[:12]`` so two
    audit records can be correlated without either carrying the value."""

    category: str
    field: str
    fingerprint: str


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:12]


def _spans(s: str) -> list[tuple[int, int, str]]:
    """Return non-overlapping ``(start, end, category)`` provider-pattern matches
    in ``s``, in list order — a match from an earlier (more specific) pattern
    wins over a later one that overlaps it."""
    accepted: list[tuple[int, int, str]] = []
    for category, pattern in _PATTERNS:
        for m in pattern.finditer(s):
            start, end = m.start(), m.end()
            if not any(
                start < a_end and a_start < end for a_start, a_end, _ in accepted
            ):
                accepted.append((start, end, category))
    accepted.sort()
    return accepted


# ---------------------------------------------------------------------------
# Public API: scan and redact any JSON-ish value
# ---------------------------------------------------------------------------


def _join(path: str, key: str) -> str:
    return key if not path else f"{path}.{key}"


# A dict key is model-controlled and ends up in the field path, which is
# interpolated into safe_reason / safe_detail. Drop anything outside this tight
# allowlist so a crafted key can't inject text (newlines, quotes) into the
# model-facing refusal; `[REDACTED:x]` stays intact so a secret key still shows
# redacted, not verbatim.
_SEGMENT_DISALLOWED = re.compile(r"[^A-Za-z0-9_.:\[\]-]")


def _safe_segment(key: str) -> str:
    """A field-path segment safe to show: any secret in the key redacted, then
    allowlisted and length-bounded."""
    redacted, _ = _redact_str(key)
    return _SEGMENT_DISALLOWED.sub("", redacted)[:64]


def scan_secrets(value: Any, *, _path: str = "") -> list[SecretHit]:
    """Walk a JSON-ish ``value`` (mapping / sequence / string) and return every
    :class:`SecretHit`. Mapping keys are scanned as leaves too (a key can be a
    secret), and every path segment is sanitized (:func:`_safe_segment`) so an
    untrusted key never reaches the model-facing text raw. Opaque (non-JSON)
    leaves are skipped; ``bytes`` are not decoded, only ``str`` is scanned."""
    hits: list[SecretHit] = []
    if isinstance(value, str):
        for start, end, category in _spans(value):
            hits.append(SecretHit(category, _path, _fingerprint(value[start:end])))
    elif isinstance(value, Mapping):
        for key, sub in value.items():
            key_str = str(key)
            seg = _safe_segment(key_str)
            for start, end, category in _spans(key_str):
                hits.append(
                    SecretHit(
                        category, _join(_path, seg), _fingerprint(key_str[start:end])
                    )
                )
            hits.extend(scan_secrets(sub, _path=_join(_path, seg)))
    elif isinstance(value, (list, tuple)):
        for i, sub in enumerate(value):
            hits.extend(scan_secrets(sub, _path=f"{_path}[{i}]"))
    return hits


def _redact_str(s: str) -> tuple[str, list[tuple[int, int, str]]]:
    spans = _spans(s)
    if not spans:
        return s, []
    out, cursor = [], 0
    for start, end, category in spans:
        out.append(s[cursor:start])
        out.append(f"[REDACTED:{category}]")
        cursor = end
    out.append(s[cursor:])
    return "".join(out), spans


def redact_secrets(value: Any, *, _path: str = "") -> tuple[Any, list[SecretHit]]:
    """Return a copy of ``value`` with every detected secret replaced by a
    ``[REDACTED:<category>]`` marker, plus the hits. Rebuilds mappings and lists
    structurally (JSON-ish only); the input is never mutated."""
    if isinstance(value, str):
        redacted, spans = _redact_str(value)
        hits = [
            SecretHit(cat, _path, _fingerprint(value[start:end]))
            for start, end, cat in spans
        ]
        return redacted, hits
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        hits = []
        for key, sub in value.items():
            key_str = str(key)
            seg = _safe_segment(key_str)
            new_key, key_spans = _redact_str(key_str)
            # keep the original key object when it held no secret (preserves
            # non-str keys); use the redacted string only when we changed it.
            out_key = new_key if key_spans else key
            for start, end, cat in key_spans:
                hits.append(
                    SecretHit(cat, _join(_path, seg), _fingerprint(key_str[start:end]))
                )
            new_sub, sub_hits = redact_secrets(sub, _path=_join(_path, seg))
            out[out_key] = new_sub
            hits.extend(sub_hits)
        return out, hits
    if isinstance(value, (list, tuple)):
        out_seq: list[Any] = []
        hits = []
        for i, sub in enumerate(value):
            new_sub, sub_hits = redact_secrets(sub, _path=f"{_path}[{i}]")
            out_seq.append(new_sub)
            hits.extend(sub_hits)
        return out_seq, hits
    return value, []


# ---------------------------------------------------------------------------
# Model-facing and operator-facing text (never the value)
# ---------------------------------------------------------------------------


def safe_reason(hits: Sequence[SecretHit]) -> str:
    """The model-facing refusal: names the category and field, never the value,
    and stays actionable so the model reworks the call rather than looping."""
    cats = ", ".join(sorted({h.category for h in hits}))
    fields = ", ".join(f"`{f or 'argument'}`" for f in sorted({h.field for h in hits}))
    what = "a credential" if len(hits) == 1 else f"{len(hits)} credentials"
    return (
        f"Refused: {what} ({cats}) was found in the tool arguments "
        f"({fields}) and was not sent. Remove it and resend without the secret."
    )


def safe_detail(hits: Sequence[SecretHit]) -> str:
    """Operator-only detail for the audit / observer channel: category, field,
    and fingerprint (a hash) per hit — still never the value."""
    return "; ".join(f"{h.category}@{h.field or '.'}#{h.fingerprint}" for h in hits)


__all__ = [
    "SecretHit",
    "redact_secrets",
    "safe_detail",
    "safe_reason",
    "scan_secrets",
]
