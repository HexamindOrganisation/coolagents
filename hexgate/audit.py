"""Per-decision audit emission: one OTel span per decision, exported over
OTLP to the Hexgate Collector under instrumentation scope ``hexgate.audit``.

Fire-and-forget; batched in memory; drops on saturation.
Lifecycle: configure() per api_key, await shutdown() at process exit.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar
from uuid import UUID, uuid4

from hexgate.tracing import semconv
from hexgate.tracing._senders import AuditSender, get_or_create_sender
from hexgate.tracing._senders import get_sender as _get_sender
from hexgate.tracing._senders import shutdown as _shutdown_all

if TYPE_CHECKING:
    # Annotation-only: Decision is used solely as a type hint below, so it stays
    # out of the runtime import graph (PEP 563 keeps it lazy). audit.py is a
    # low-level module — importing it should not drag in the whole security
    # package. The audit → security → enforcer → audit cycle is independently
    # avoided (binding.py keeps its enforcer import under TYPE_CHECKING too), so
    # this is correctness-by-design, not a workaround — keep it here.
    from hexgate.security.decision import Decision

# Mirrors the platform's MAX_ARGS_BYTES (platform/api/audit.py). The platform
# rejects (413) rather than truncates, so an over-cap event would be lost
# entirely unless the SDK trims it first.
MAX_ARGS_BYTES = 8 * 1024

# Mirrors the platform's MAX_ATTRIBUTES_BYTES. Same reject-don't-truncate
# semantics as arguments; smaller because the ABAC bag holds caller facts
# (department, clearance level), not tool payloads.
MAX_ATTRIBUTES_BYTES = 4 * 1024

# Mirrors the platform's MAX_HINT_BYTES. Same reject-don't-truncate semantics.
# Only the audit copy is trimmed — ``Decision.as_error_payload`` still carries
# the intact hint, so the host's file-scope error message keeps its full
# allowed/denied path lists.
MAX_HINT_BYTES = 4 * 1024

# Mirrors the platform's ``DecisionEvent.violations`` bounds (list max_length +
# per-item StringConstraints). A multi-role deny unions one role's violations
# with the next, so a wide caller on the WASM engine can exceed the list cap and
# lose the audit record for a *denied* call — the outcome most worth keeping.
MAX_VIOLATIONS = 64
MAX_VIOLATION_CHARS = 1024

# Keys whose values are stripped from the audit copy of ``arguments`` before
# transmission. Substring match: tool inputs are arbitrary caller data, so a
# key merely *containing* a secret-ish word is worth blanking. A seatbelt, not
# a guarantee: values that are sensitive by content rather than key name (SQL
# strings, email bodies) are NOT caught.
_SENSITIVE_ARG_KEY_RE = re.compile(
    r"password|passwd|secret|token|api[-_]?key|credential|authorization",
    re.IGNORECASE,
)

# Same seatbelt for ``attributes``, but anchored to the whole key. The bag holds
# policy facts, not payloads: ``authorization_tier`` and ``access_token_scope``
# are legitimate ``ctx.*`` keys, and blanking them would leave a ctx-driven deny
# unexplainable — the very thing persisting the bag exists to prevent. A key
# named exactly ``token`` still reads as a secret someone stuffed into the bag,
# so those keep being blanked.
_SENSITIVE_ATTR_KEY_RE = re.compile(
    r"^(?:password|passwd|secret|token|api[-_]?key|credential|authorization)$",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"


def _redact(value: Any, *, pattern: re.Pattern[str]) -> Any:
    """Return a copy of ``value`` with values under ``pattern``-matching keys replaced.

    Pure — never mutates the input, so the ``Decision`` the caller holds
    keeps its full arguments; only the wire payload is redacted."""
    if isinstance(value, dict):
        return {
            k: _REDACTED
            if isinstance(k, str) and pattern.search(k)
            else _redact(v, pattern=pattern)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v, pattern=pattern) for v in value]
    return value


def _bounded_violations(violations: Sequence[str]) -> list[str]:
    """Trim ``violations`` to the platform's list + per-item caps.

    Drops whole entries and says how many, so a truncated list can't read as a
    complete one. Only the audit copy is trimmed; ``Decision.violations`` keeps
    every entry for the host's error payload.
    """
    trimmed = [
        v if len(v) <= MAX_VIOLATION_CHARS else v[: MAX_VIOLATION_CHARS - 3] + "..."
        for v in violations
    ]
    if len(trimmed) <= MAX_VIOLATIONS:
        return trimmed
    kept = trimmed[: MAX_VIOLATIONS - 1]
    return [*kept, f"(+{len(trimmed) - len(kept)} more)"]


# Room for the {_truncated, original_bytes, preview} wrapper around the preview.
_TRUNCATION_WRAPPER_HEADROOM_BYTES = 512


def _truncate_json(payload: dict[str, Any], *, cap: int) -> dict[str, Any]:
    """Trim ``payload`` to fit a platform byte cap.

    Serialization mirrors the platform's measurement (``default=str``). Over
    the cap, the dict is replaced by a marker wrapping a JSON-text preview,
    shrunk until the wrapper itself fits — lossy, but stored; the platform
    would 413-reject the raw payload and lose the event entirely.

    Under the cap the payload is copied rather than returned as-is, so no wire
    payload aliases a live ``Decision`` field. ``arguments``/``attributes`` get
    that boundary from ``_redact``; ``hint`` has none of its own, and it is the
    same object ``as_error_payload`` hands the host. The copy is shallow —
    enough to stop a rebind, not a nested in-place mutation."""
    payload_json = json.dumps(payload, default=str)
    if len(payload_json.encode("utf-8")) <= cap:
        return dict(payload)
    preview_bytes = cap - _TRUNCATION_WRAPPER_HEADROOM_BYTES
    while True:
        wrapper = {
            "_truncated": True,
            "original_bytes": len(payload_json.encode("utf-8")),
            "preview": payload_json.encode("utf-8")[:preview_bytes].decode(
                "utf-8", errors="ignore"
            ),
        }
        if len(json.dumps(wrapper).encode("utf-8")) <= cap:
            return wrapper
        preview_bytes //= 2


# Public aliases so server-side ingestion can import this pipeline instead of
# keeping its own copy.
redact = _redact
truncate_json = _truncate_json
bounded_violations = _bounded_violations
SENSITIVE_ARG_KEY_RE = _SENSITIVE_ARG_KEY_RE
SENSITIVE_ATTR_KEY_RE = _SENSITIVE_ATTR_KEY_RE


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Decision plus caller identity from the active HexgateContext scope.

    ``event_id`` / ``occurred_at`` are stamped here, not on ``Decision`` —
    they exist only for audit emission, and the no-audit path never
    constructs an event. ``occurred_at`` becomes the span's start time;
    ``event_id`` is the platform's idempotency key (see ``semconv``)."""

    SCOPE: ClassVar[str] = semconv.SCOPE_AUDIT

    decision: Decision
    user_id: str = ""
    session_id: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def span_attributes(self) -> dict[str, Any]:
        """Flat span attributes keyed by ``semconv`` names.

        ``arguments`` and ``attributes`` are redacted (sensitive key names, on
        their own patterns — see ``_SENSITIVE_ATTR_KEY_RE``); those plus
        ``hint`` and ``violations`` are truncated to their platform caps here —
        the single choke point onto the wire. The three dict fields travel as
        JSON strings (the caps are defined in serialized-JSON bytes, so the
        capped quantity stays the measured one); the two list fields as native
        string arrays. Absent optional fields are left out rather than sent as
        ``None`` — OTel attributes can't carry null. The role fields and the
        ``run.*`` fields deliberately pass through untouched — see the comments
        on them below."""
        d = self.decision
        attrs: dict[str, Any] = {
            semconv.EVENT_ID: str(self.event_id),
            semconv.AGENT_NAME: d.agent_name,
            semconv.TOOL_NAME: d.tool_name,
            semconv.OUTCOME: d.outcome.value,
            # Roles evaluated, in caller order, and the one that granted or
            # gated the call ("" on a deny). No legacy scalar ``role``: it was
            # only ever ``user_roles[0]``, and the platform derives what it
            # needs from the list. Uncapped on purpose: these are policy
            # identifiers, not caller payloads, and the platform bounds them
            # (32 x 256) on ``DecisionEvent``.
            semconv.USER_ROLES: list(d.user_roles),
            semconv.DECIDING_ROLE: d.deciding_role or "",
            semconv.ERROR_TYPE: d.error_type or "",
            semconv.REASON: d.reason,
            semconv.VIOLATIONS: _bounded_violations(d.violations),
            semconv.USER_ID: self.user_id,
            semconv.SESSION_ID: self.session_id,
            # Neither redacted nor capped — SDK counters, not caller data.
            # Spread so the attribute names live in one place.
            **d.run.as_span_attributes(),
        }
        if d.arguments is not None:
            attrs[semconv.ARGUMENTS] = json.dumps(
                _truncate_json(
                    _redact(d.arguments, pattern=_SENSITIVE_ARG_KEY_RE),
                    cap=MAX_ARGS_BYTES,
                ),
                default=str,
            )
        if d.hint is not None:
            attrs[semconv.HINT] = json.dumps(
                _truncate_json(d.hint, cap=MAX_HINT_BYTES), default=str
            )
        if d.attributes:
            attrs[semconv.ATTRIBUTES] = json.dumps(
                _truncate_json(
                    _redact(d.attributes, pattern=_SENSITIVE_ATTR_KEY_RE),
                    cap=MAX_ATTRIBUTES_BYTES,
                ),
                default=str,
            )
        return attrs


def configure(
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the audit sender for ``api_key``. Idempotent per key.

    Both args fall back to ``HEXGATE_API_KEY`` / ``HEXGATE_API_URL`` env vars
    (``HEXGATE_OTLP_ENDPOINT`` overrides where spans are exported). Reuses the
    existing sender when the same key was already configured — one sender per
    key carries decisions, LLM usage and ban enforcements alike; distinct keys
    get distinct senders. Returns ``None`` when no api_key is resolvable —
    audit stays inert.

    Also returns ``None`` when ``HEXGATE_LOCAL_MODE`` is set in env, even
    if a key was resolvable — that's the "I have a key in .env but I'm
    iterating locally and don't want cloud writes" path
    (``hexgate chat`` opts in via ``bootstrap(local_only=True)``).
    """
    return get_or_create_sender(api_key, base_url)


def get_sender(api_key: str | None = None) -> AuditSender | None:
    """Return the audit sender for ``api_key`` (or ``HEXGATE_API_KEY``), if configured.

    Production code should use the sender injected into
    :class:`~hexgate.security.enforcer.PolicyEnforcer`; this lookup exists for
    diagnostics and is unambiguous only when scoped to a key.
    """
    return _get_sender(api_key)


async def shutdown() -> None:
    """Flush queued events and stop every sender in the shared registry —
    decisions, LLM usage and ban enforcements alike. Safe to call multiple
    times."""
    await _shutdown_all()
