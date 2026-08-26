"""Semantic conventions for Hexgate audit events carried as OTel spans.

Single source of truth for the OTLP wire contract between the SDK's span
emitter (future) and the platform's span-enricher job. Both sides import
these names; neither hardcodes a string. String constants only — this
module must stay importable with zero dependencies.

Wire contract (normative — the enricher decodes by these rules, the emitter
must produce by them):

- One event = one span. The instrumentation scope name selects the event
  type: ``SCOPE_AUDIT`` → DecisionEvent, ``SCOPE_USAGE`` → LlmInvocationEvent,
  ``SCOPE_BANS`` → BanEnforcementEvent (platform schemas).
- ``occurred_at`` travels as the span's ``start_time_unix_nano`` — the one
  field OTLP already types as a timestamp. No separate attribute: a duplicate
  would invite the two values disagreeing with no rule for which wins. These
  are point-in-time events; the emitter sets start == end (or start ≈ end).
  A zero start time is a rejected span.
- ``event_id`` travels as the ``EVENT_ID`` string-UUID attribute, never as
  span identity: ``span_id`` is 8 bytes and regenerates on a client retry,
  so keying dedup on it would fail to collapse retries. ``EVENT_ID`` is the
  ReplacingMergeTree idempotency key end-to-end.
- ``project_id`` is NOT a span attribute. It is auth-derived by the
  Collector's Biscuit extension and travels as the Kafka record key —
  a self-declared project on the span body is never trusted.
- List fields (``USER_ROLES``, ``VIOLATIONS``) are native OTLP string
  arrays (AnyValue.array_value).
- Dict fields (``HINT``, ``ARGUMENTS``, ``ATTRIBUTES``) are JSON-string
  attributes, not kvlists and not flattened keys: their platform byte caps
  are defined in serialized-JSON bytes, so a JSON string keeps the capped
  quantity the measured quantity, and kvlist round-tripping is the least
  supported AnyValue shape across third-party pipelines.
- LLM usage reuses the official ``gen_ai.*`` names where they exist (model,
  token counts) and never invents new ``gen_ai.*`` names; everything
  Hexgate-specific lives under ``sec_ai.*``.
"""

from __future__ import annotations

# --- Instrumentation scope names (one per event stream) -----------------------
SCOPE_AUDIT = "hexgate.audit"
SCOPE_USAGE = "hexgate.usage"
SCOPE_BANS = "hexgate.bans"

# --- Envelope attributes (all three scopes) -----------------------------------
EVENT_ID = "sec_ai.event_id"
AGENT_NAME = "sec_ai.agent_name"
SESSION_ID = "sec_ai.session_id"
USER_ID = "sec_ai.user_id"

# --- Decision spans (SCOPE_AUDIT) ----------------------------------------------
TOOL_NAME = "sec_ai.tool_name"
OUTCOME = "sec_ai.outcome"
USER_ROLES = "sec_ai.user_roles"
DECIDING_ROLE = "sec_ai.deciding_role"
ERROR_TYPE = "sec_ai.error_type"
REASON = "sec_ai.reason"
VIOLATIONS = "sec_ai.violations"
HINT = "sec_ai.hint"
ARGUMENTS = "sec_ai.arguments"
ATTRIBUTES = "sec_ai.attributes"

# --- LLM usage spans (SCOPE_USAGE) ----------------------------------------------
# Official OTel GenAI semconv names — never coin new gen_ai.* names ourselves.
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
# Hexgate-specific usage fields.
LATENCY_MS = "sec_ai.latency_ms"
STATUS = "sec_ai.status"
ERROR_CODE = "sec_ai.error_code"

# --- Ban enforcement spans (SCOPE_BANS) ------------------------------------------
BAN_TYPE = "sec_ai.ban_type"
BAN_ID = "sec_ai.ban_id"
