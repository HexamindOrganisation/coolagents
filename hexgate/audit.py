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

# Keys whose values are stripped from the audit copy of ``arguments`` before
# transmission. A seatbelt, not a guarantee: values that are sensitive by
# content rather than key name (SQL strings, email bodies) are NOT caught.
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


def _truncate_args(arguments: dict[str, Any]) -> dict[str, Any]:
    """Trim ``arguments`` to fit the platform's byte cap.

    Serialization mirrors the platform's measurement (``default=str``). Over
    the cap, the dict is replaced by a marker wrapping a JSON-text preview,
    shrunk until the wrapper itself fits — lossy, but stored; the platform
    would 413-reject the raw payload and lose the event entirely."""
    args_json = json.dumps(arguments, default=str)
    if len(args_json.encode("utf-8")) <= MAX_ARGS_BYTES:
        return arguments
    preview_bytes = MAX_ARGS_BYTES - 512
    while True:
        wrapper = {
            "_truncated": True,
            "original_bytes": len(args_json.encode("utf-8")),
            "preview": args_json.encode("utf-8")[:preview_bytes].decode(
                "utf-8", errors="ignore"
            ),
        }
        if len(json.dumps(wrapper).encode("utf-8")) <= MAX_ARGS_BYTES:
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
    # Trusted ``ctx.*`` keys, and whether the verified values were self-minted
    # in-process (vs verified from an external token) — set each attribute's
    # provenance in the snapshot.
    trusted_attributes: frozenset[str] = field(default_factory=frozenset)
    attributes_self_asserted: bool = False
    event_id: UUID = field(default_factory=uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_payload(self) -> dict[str, Any]:
        """Flat JSON payload matching the platform's DecisionEvent body.

        ``arguments`` are redacted (sensitive key names) and truncated to the
        platform byte cap here — the single choke point onto the wire."""
        d = self.decision
        arguments = (
            _truncate_args(_redact(d.arguments)) if d.arguments is not None else None
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
            "attributes": self._attribute_snapshot(),
            "user_id": self.user_id,
            "session_id": self.session_id,
        }

    def _attribute_snapshot(self) -> dict[str, Any] | None:
        """The decision's ABAC bag as ``{key: {value, provenance}}``, redacted
        like ``arguments``; ``None`` when empty.

        ``provenance`` is honest about trust: ``advisory`` (contextvar, not a
        trusted key), ``verified`` (trusted key resolved from an externally
        verified token), or ``self_asserted`` (trusted key whose value the SDK
        signed in-process from the spoofable contextvar — pinned, not
        independently verified).

        Forward-compatible: the current platform schema has no ``attributes``
        field and drops this on ingest — emitted so persistence lights up once
        the platform grows the column."""
        attrs = self.decision.attributes
        if not attrs:
            return None
        redacted = _redact(attrs)
        return {
            key: {"value": redacted[key], "provenance": self._provenance(key)}
            for key in attrs
        }

    def _provenance(self, key: str) -> str:
        """Trust provenance of one attribute in the snapshot (see
        :meth:`_attribute_snapshot`). A trusted key present here was resolved
        from a token, so it's ``verified`` unless that token was self-minted."""
        if key not in self.trusted_attributes:
            return "advisory"
        return "self_asserted" if self.attributes_self_asserted else "verified"


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
