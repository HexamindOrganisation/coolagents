"""Per-decision audit emission to the platform's /v1/audit/decisions endpoint.

Fire-and-forget POST per decision; bounded concurrency; drops on saturation.
Lifecycle: configure() per api_key, await shutdown() at process exit.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

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

# Keys whose values are stripped from the audit copy of ``arguments`` and
# ``attributes`` before transmission. A seatbelt, not a guarantee: values that
# are sensitive by content rather than key name (SQL strings, email bodies) are
# NOT caught.
_SENSITIVE_KEY_RE = re.compile(
    r"password|passwd|secret|token|api[-_]?key|credential|authorization",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"


def _redact(value: Any) -> Any:
    """Return a copy of ``value`` with sensitive-keyed values replaced.

    Pure — never mutates the input, so the ``Decision`` the caller holds
    keeps its full arguments; only the wire payload is redacted."""
    if isinstance(value, dict):
        return {
            k: _REDACTED
            if isinstance(k, str) and _SENSITIVE_KEY_RE.search(k)
            else _redact(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value


# Room for the {_truncated, original_bytes, preview} wrapper around the preview.
_TRUNCATION_WRAPPER_HEADROOM_BYTES = 512


def _truncate_json(payload: dict[str, Any], *, cap: int) -> dict[str, Any]:
    """Trim ``payload`` to fit a platform byte cap.

    Serialization mirrors the platform's measurement (``default=str``). Over
    the cap, the dict is replaced by a marker wrapping a JSON-text preview,
    shrunk until the wrapper itself fits — lossy, but stored; the platform
    would 413-reject the raw payload and lose the event entirely."""
    payload_json = json.dumps(payload, default=str)
    if len(payload_json.encode("utf-8")) <= cap:
        return payload
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


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Decision plus caller identity from the active HexgateContext scope.

    ``event_id`` / ``occurred_at`` are stamped here, not on ``Decision`` —
    they exist only for audit emission, and the no-audit path never
    constructs an event. Names mirror the platform's AuditEnvelope."""

    decision: Decision
    user_id: str = ""
    session_id: str = ""
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_payload(self) -> dict[str, Any]:
        """Flat JSON payload matching the platform's DecisionEvent body.

        ``arguments`` and ``attributes`` are redacted (sensitive key names) and
        truncated to their platform byte caps here — the single choke point
        onto the wire."""
        d = self.decision
        arguments = (
            _truncate_json(_redact(d.arguments), cap=MAX_ARGS_BYTES)
            if d.arguments is not None
            else None
        )
        # Falsy, not ``is not None``: an active context with no attributes
        # yields ``{}`` (HexgateContext.attributes defaults to an empty dict),
        # and an empty bag is indistinguishable from no bag downstream — both
        # store '' and read back as None.
        attributes = (
            _truncate_json(_redact(d.attributes), cap=MAX_ATTRIBUTES_BYTES)
            if d.attributes
            else None
        )
        return {
            "event_id": str(self.event_id),
            "occurred_at": self.occurred_at.isoformat(),
            "agent_name": d.agent_name,
            "tool_name": d.tool_name,
            "outcome": d.outcome.value,
            "role": d.role or "",
            "error_type": d.error_type or "",
            "reason": d.reason,
            "violations": list(d.violations),
            "hint": d.hint,
            "arguments": arguments,
            "attributes": attributes,
            "user_id": self.user_id,
            "session_id": self.session_id,
        }


# --- Per-key sender registry --------------------------------------------------
#
# The registry mechanics (dict + get-or-create + shutdown), the
# HEXGATE_LOCAL_MODE gate, and AuditSender itself now live in the neutral
# hexgate.tracing._senders module, shared with hexgate.tracing.usage. The
# functions below are thin, decisions-specific wrappers around it.


_AUDIT_PATH = "/v1/audit/decisions"


def configure(
    api_key: str | None = None,
    base_url: str | None = None,
) -> AuditSender | None:
    """Get-or-create the audit sender for ``api_key``. Idempotent per key.

    Both args fall back to ``HEXGATE_API_KEY`` / ``HEXGATE_API_URL`` env vars.
    Reuses the existing sender when the same key was already configured;
    distinct keys get distinct senders. Returns ``None`` when no api_key is
    resolvable — audit stays inert.

    Also returns ``None`` when ``HEXGATE_LOCAL_MODE`` is set in env, even
    if a key was resolvable — that's the "I have a key in .env but I'm
    iterating locally and don't want cloud writes" path
    (``hexgate chat`` opts in via ``bootstrap(local_only=True)``).
    """
    return get_or_create_sender(_AUDIT_PATH, api_key, base_url)


def get_sender(api_key: str | None = None) -> AuditSender | None:
    """Return the audit sender for ``api_key`` (or ``HEXGATE_API_KEY``), if configured.

    Production code should use the sender injected into
    :class:`~hexgate.security.enforcer.PolicyEnforcer`; this lookup exists for
    diagnostics and is unambiguous only when scoped to a key.
    """
    return _get_sender(_AUDIT_PATH, api_key)


async def shutdown() -> None:
    """Drain in-flight emits and close every sender in the shared registry
    (decisions and LLM usage alike). Safe to call multiple times."""
    await _shutdown_all()
