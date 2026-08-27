from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

# Ceiling for counters stored in ClickHouse UInt32 columns (schema.sql).
UINT32_MAX = 2**32 - 1


# ---------------------------------------------------------------------------
# M3 Phase 4 — Organization wire shapes
# ---------------------------------------------------------------------------


class OrgRead(BaseModel):
    """Shared base — what an org looks like over the wire."""

    id: str
    slug: str
    name: str
    created_at: datetime


class OrgWithRole(OrgRead):
    """Org enriched with the caller's role. Returned by ``GET /v1/orgs``
    so the dashboard knows which actions the active user can take in
    each listed org without a second round-trip."""

    role: str  # "owner" | "admin" | "member"


class OrgCreate(BaseModel):
    """``POST /v1/orgs`` body.

    ``slug`` is optional — when omitted, the server derives one from
    ``name`` (sanitised + collision-fallback). Constraints match
    DNS-label rules + a 32-char ceiling so the slug fits comfortably
    in any URL we'd ever render.
    """

    name: str = Field(min_length=1, max_length=64)
    slug: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=32,
        # Lowercase letters, digits, hyphens. Must start with a letter
        # and not end with a hyphen — matches DNS-label conventions so
        # the slug can later double as a hostname/subdomain.
        pattern=r"^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$",
    )


class OrgUpdate(BaseModel):
    """``PATCH /v1/orgs/{id}`` body. Both fields optional; omitted
    fields are left unchanged on the row."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    slug: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=32,
        pattern=r"^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$",
    )


class MemberRead(BaseModel):
    """Row in ``GET /v1/orgs/{org_id}/members``.

    Keeps ``email`` on the row even though the relationship is on
    ``user_id`` — the dashboard's member list renders ``<email> · <role>``
    per row, so denormalizing the email here saves a JOIN-per-row
    on the frontend.
    """

    user_id: str
    email: str
    role: str  # "owner" | "admin" | "member"
    joined_at: datetime


class MemberUpdate(BaseModel):
    """``PATCH /v1/orgs/{id}/members/{user_id}`` body.

    Only ``role`` is mutable — promoting / demoting an existing
    member. Adding a member happens via the invitation flow (Phase 4
    step 4); removing is ``DELETE`` (step 3); changing the user's
    email is a self-service action on the user itself, not here.
    """

    role: str = Field(pattern="^(owner|admin|member)$")


# ---------------------------------------------------------------------------
# M3 Phase 4 step 4 — Invitations
# ---------------------------------------------------------------------------


class InvitationCreate(BaseModel):
    """``POST /v1/orgs/{org_id}/invites`` body."""

    email: EmailStr
    role: str = Field(pattern="^(owner|admin|member)$")


class InvitationRead(BaseModel):
    """Row in ``GET /v1/orgs/{org_id}/invites`` — pending invitations
    visible to org admins/owners.

    The invitation ``id`` IS exposed here despite doubling as the
    magic-link token. Reasoning: the strict email-match guard on
    ``POST /invites/{id}/accept`` is the load-bearing protection —
    even with the URL, only the invited email's signed-in user can
    accept. Hiding the id from this admin-only list was earlier
    defense-in-depth, but the dashboard needs to address invitations
    to cancel them, and adding a parallel "DELETE by email" endpoint
    just to avoid surfacing the id would cost more code than it buys.
    """

    id: str
    email: str
    role: str
    invited_by_email: str
    expires_at: datetime
    created_at: datetime


class ProjectCreate(BaseModel):
    """``POST /v1/orgs/{org_id}/projects`` body. Name only — projects
    don't have user-visible slugs today; dashboards address by name,
    the API by UUID. Slugs can land later when a URL like
    ``/orgs/acme/projects/customer-bot`` becomes a need."""

    name: str = Field(min_length=1, max_length=64)


class ProjectRead(BaseModel):
    """Wire shape for project read endpoints. Mirrors the columns the
    dashboard cares about on the row — the WASM bundle and version
    fields live on the existing ``AgentRead`` shape for individual
    agents, not here."""

    id: str
    org_id: str
    name: str
    created_at: datetime


class ProjectUpdate(BaseModel):
    """``PATCH /v1/projects/{project_id}`` body. Rename only for now;
    moving a project to a different org is its own larger feature
    (transfer + ownership change + member-access reconciliation) that
    doesn't land in Phase 4."""

    name: str = Field(min_length=1, max_length=64)


# ---------------------------------------------------------------------------
# Ban wire shapes
# ---------------------------------------------------------------------------

# The two ban kinds. Kept as a closed set on the wire so a stray DB value can't
# slip past OpenAPI/Pydantic into the dashboard (writes are already gated by
# BanCreate + the ClickHouse Enum8).
BanType = Literal["agent", "user"]


class BanCreate(BaseModel):
    """``POST /v1/projects/{project_id}/bans`` body — exactly one target,
    matching ``ban_type`` (enforced below, so a bad shape is a 422)."""

    ban_type: str = Field(pattern="^(agent|user)$")
    target_agent_name: Optional[str] = Field(default=None, min_length=1, max_length=256)
    target_user_id: Optional[str] = Field(default=None, min_length=1, max_length=256)
    reason: Optional[str] = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _check_target(self) -> "BanCreate":
        if self.ban_type == "agent":
            if not self.target_agent_name:
                raise ValueError("agent ban requires target_agent_name")
            if self.target_user_id is not None:
                raise ValueError("agent ban must not set target_user_id")
        else:  # "user"
            if not self.target_user_id:
                raise ValueError("user ban requires target_user_id")
            if self.target_agent_name is not None:
                raise ValueError("user ban must not set target_agent_name")
        return self


class BanRead(BaseModel):
    """A ban row for the dashboard, with its created/revoked audit trail."""

    id: str
    project_id: str
    ban_type: BanType
    target_agent_name: Optional[str]
    target_user_id: Optional[str]
    reason: Optional[str]
    created_by_user_id: str
    # Resolved from the User table for display; null if the account no longer
    # exists. The id above stays the stable key.
    created_by_email: Optional[str] = None
    created_at: datetime
    revoked_at: Optional[datetime]
    active: bool


class BanFeedEntry(BaseModel):
    """``GET /v1/bans`` shape — carries ``ban_id`` so the SDK gate can echo it
    into a ``BanEnforcementEvent``; no created_by/timestamps leak."""

    ban_id: str
    ban_type: str
    target_agent_name: Optional[str]
    target_user_id: Optional[str]
    reason: Optional[str]


class InvitationPreview(BaseModel):
    """``GET /v1/invites/{id}`` response — what the invitee sees on
    the accept landing page before clicking through.

    Public-readable: the invite id is unguessable (UUID v4) so anyone
    with the link can preview it. Includes the org's name/slug so the
    invitee knows what they're joining without needing an account
    yet. The accept POST is what requires authentication + a matching
    email.
    """

    email: str
    role: str
    invited_by_email: str
    org_id: str
    org_name: str
    org_slug: str
    expires_at: datetime


class TokenMintRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(default_factory=lambda: ["mint_user_token", "read_audit"])
    env: str = Field(default="test", pattern="^(test|live)$")


class TokenListItem(BaseModel):
    id: str
    name: str
    masked: str  # e.g., "fty_live_8F3d…k29P"
    scopes: list[str]
    created_at: datetime
    last_used_at: Optional[datetime]


class TokenMintResponse(BaseModel):
    id: str
    name: str
    full: str  # only returned on mint
    masked: str
    scopes: list[str]
    created_at: datetime


class KeyIntrospection(BaseModel):
    """``GET /v1/me/key`` response — what a hexgate key resolves to.

    Used by the CLI to look up its own context at startup (project, env,
    scopes) without parsing the envelope. The token never round-trips —
    only its descriptive metadata. Authentication is the bearer itself,
    so possessing the key proves the right to read its description.
    """

    token_id: str
    name: str
    project_id: str
    env: str  # "test" | "live"
    scopes: list[str]


class AgentRead(BaseModel):
    id: str
    name: str
    agent_yaml: str
    policy_yaml: str
    system_md: str
    updated_at: datetime
    # Signed WASM bundle compiled from policy_yaml at save time. Null when
    # the platform couldn't compile (opa missing or bad policy) — the SDK
    # then falls back to the pydantic engine. wasm + signature are base64;
    # manifest is the exact signed JSON text (verified over its bytes).
    bundle_wasm_b64: Optional[str] = None
    bundle_manifest: Optional[str] = None
    bundle_signature_b64: Optional[str] = None


class AgentUpdate(BaseModel):
    agent_yaml: str | None = None
    policy_yaml: str | None = None
    system_md: str | None = None


class PolicyValidationError(BaseModel):
    """One diagnostic from the policy-document linter.

    ``role`` is set when the failure was inside a specific entry of a
    role-aware ``policy.yaml``'s ``roles:`` section; ``None`` for errors
    at the top level (e.g. invalid YAML, schema violation).

    ``tool`` is the separate locus a lint can carry (``permissive-default``
    names the over-granted tool). It has its own field because the two read
    identically once rendered — a tool in the ``role`` slot looks like a role.
    """

    role: str | None = None
    tool: str | None = None
    line: int | None = None
    message: str


class ValidatePolicyRequest(BaseModel):
    """Body for the policy-document validation endpoint.

    Validates a single ``policy.yaml`` text — either a flat single-policy
    shape or an inline-roles shape with a top-level ``roles:`` map. The
    endpoint runs the same parsing the SDK uses at enforcement time.
    """

    policy_yaml: str


class ValidatePolicyResponse(BaseModel):
    """Result of validating a policy document.

    ``ok`` is True when the document and every nested role parsed cleanly.
    ``errors`` carries per-issue diagnostics.

    ``warnings`` carries authoring lints and never affects ``ok``: a
    single-role agent's flat policy.yaml *is* the ``default`` role, so failing
    it would be wrong. CI opts in with ``--max-severity warning``.
    """

    ok: bool
    errors: list[PolicyValidationError] = Field(default_factory=list)
    warnings: list[PolicyValidationError] = Field(default_factory=list)


# --- Multi-module policy store (see docs/adr/R-POL-001) ----------------------


class PolicyModuleRead(BaseModel):
    tier: str  # "boundary" | "capability"
    path: str
    content: str
    content_hash: str
    updated_at: datetime


class PolicyModuleWrite(BaseModel):
    """Body for upserting a module. The tier + path come from the URL."""

    content: str


class PolicyFolderRead(BaseModel):
    """A persisted empty folder — tier + path prefix (see models.PolicyFolder)."""

    tier: str
    path: str


class RoleBindingsRead(BaseModel):
    """A project's role bindings as the ``(role, agent)`` matrix:
    ``role -> agent-or-"*" -> capability names``. The ``"*"`` agent is the
    generic default; a project written before the agent axis reads back with all
    capabilities under ``"*"``."""

    roles: dict[str, dict[str, list[str]]] = Field(default_factory=dict)


class RoleBindingsWrite(BaseModel):
    """Write role bindings. Accepts either the ``(role, agent)`` matrix
    (``role -> {agent: [caps]}``) or the flat form (``role -> [caps]``, applied to
    the generic ``"*"`` agent) — the service normalizes both, so a flat client
    stays valid."""

    roles: dict[str, dict[str, list[str]] | list[str]] = Field(default_factory=dict)


class ResolvedPolicyResponse(BaseModel):
    """The composed effective policy per role. Each value is an AgentPolicy dump."""

    roles: dict[str, dict] = Field(default_factory=dict)


class PolicyLintOut(BaseModel):
    """One analyzer lint, tagged with the role it fired in (None if project-wide)."""

    code: str
    severity: str
    message: str
    source: str | None = None
    tier: str | None = None
    tool: str | None = None
    role: str | None = None


class PolicyCheckResponse(BaseModel):
    """Lints over the resolved project, diagnostics-as-data (always 200)."""

    ok: bool
    lints: list[PolicyLintOut] = Field(default_factory=list)


# --- Editor: preview, test, move (see policy-editor-plan.md) -----------------


class PolicyModuleDraft(BaseModel):
    """An unsaved edit of one module, overlaid before resolve/test."""

    tier: str  # "boundary" | "capability"
    path: str
    content: str


class PolicyDraft(BaseModel):
    """The editor's unsaved state: one module OR the roles map (never both)."""

    module: Optional[PolicyModuleDraft] = None
    roles: Optional[dict[str, list[str]]] = None


class PolicyPreviewRequest(BaseModel):
    draft: Optional[PolicyDraft] = None


class PolicyPreviewResponse(BaseModel):
    """Resolved policy per role + lints for the (optionally draft-overlaid) project.

    Always 200: an unresolvable or unparseable draft comes back with an empty
    ``resolved`` and an error lint, so the editor renders it in place.
    """

    resolved: dict[str, dict] = Field(default_factory=dict)
    lints: list[PolicyLintOut] = Field(default_factory=list)


class PolicyTestRequest(BaseModel):
    """A tool call to evaluate against the whole resolved policy for ``role``."""

    role: str
    tool: str
    args: dict = Field(default_factory=dict)
    attributes: Optional[dict] = None
    draft: Optional[PolicyDraft] = None  # reflect an unsaved edit, like preview


class PolicyTestResponse(BaseModel):
    outcome: str  # "allow" | "deny" | "approval_required"
    reason: Optional[str] = None
    violations: list[str] = Field(default_factory=list)
    hint: Optional[str] = None


class MoveModuleRequest(BaseModel):
    new_path: str


# --- Agent manifest registration ---------------------------------------------
# These mirror hexgate/manifest/models.py so SDK and platform stay in sync.


class AgentFramework(StrEnum):
    HEXGATE = "hexgate"
    PYDANTIC_AI = "pydantic-ai"
    LANGCHAIN = "langchain"
    GOOGLE = "google"
    OPENAI = "openai"


class InputProperty(BaseModel):
    title: str
    type: str


class InputSchema(BaseModel):
    properties: dict[str, InputProperty]
    required: list[str]


class ToolDefinition(BaseModel):
    name: str
    description: Optional[str] = None
    input_schema: InputSchema


class AgentManifest(BaseModel):
    """Schema for the manifest of an agent."""

    name: str
    description: Optional[str] = None
    framework: AgentFramework
    model: Optional[str] = None
    system_prompt: Optional[str] = None
    tools: list[ToolDefinition]


class RegisterAgentRequest(BaseModel):
    manifest: AgentManifest


class RegisterAgentResponse(BaseModel):
    agent_id: str
    agent_version_id: str
    name: str
    version: int
    content_hash: str
    created: bool  # False if the same content_hash already existed (no-op)


class AgentManifestView(BaseModel):
    """Resolved latest manifest of an agent, for the dashboard read path.

    ``manifest`` is None when the Agent row exists but no AgentVersion has
    been registered yet.
    ``name`` lives on the envelope so the picker can display it directly.
    """

    name: str
    manifest: Optional[AgentManifest] = None
    version: Optional[int] = None
    content_hash: Optional[str] = None
    updated_at: datetime


# --- Audit event ingest ------------------------------------------------------


class AuditEnvelope(BaseModel):
    """Wire envelope shared by every audit event type.

    Narrower than the ClickHouse storage envelope: project_id (bearer),
    received_at (column default), and agent_version_id (platform lookup)
    are server-resolved and never trusted from the body.
    """

    event_id: UUID
    occurred_at: datetime
    agent_name: str = Field(min_length=1, max_length=256)
    session_id: str = Field(default="", max_length=128)
    user_id: str = Field(default="", max_length=256)

    @field_validator("occurred_at")
    @classmethod
    def _assume_utc(cls, v: datetime) -> datetime:
        # Assume UTC for naive input so downstream tz-aware comparisons can't
        # raise TypeError; matches the DateTime64(3, 'UTC') storage column.
        return v if v.tzinfo is not None else v.replace(tzinfo=timezone.utc)


class AuditOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


class DecisionEvent(AuditEnvelope):
    """One policy decision; mirrors the policy_decision table."""

    tool_name: str = Field(min_length=1, max_length=256)
    outcome: AuditOutcome
    # Ingest-only compatibility shim for SDKs released before multi-role
    # (<= 0.2.11), which send this instead of ``user_roles``. Folded into
    # ``user_roles`` by insert_decision and never stored on its own — there
    # is no ``role`` column. Accepted, never emitted: current SDKs omit it.
    role: str = Field(default="", max_length=256)
    # Distinct roles the SDK evaluated, in caller order. Advisory +
    # client-assertable like ``role`` / ``user_id``. Caps mirror ``violations``;
    # the list cap matches the SDK's MAX_EVALUATED_ROLES.
    user_roles: list[Annotated[str, StringConstraints(max_length=256)]] = Field(
        default_factory=list, max_length=32
    )
    # Role whose policy granted (or gated) the call; "" on a full deny, or from
    # an older SDK.
    deciding_role: str = Field(default="", max_length=256)
    error_type: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=4096)
    # Per-item cap so 64 unbounded strings can't smuggle a multi-MB body.
    violations: list[Annotated[str, StringConstraints(max_length=1024)]] = Field(
        default_factory=list, max_length=64
    )
    # Byte caps enforced after serialization in audit.insert_decision.
    hint: Optional[dict] = None
    arguments: Optional[dict] = None
    # Caller ABAC bag (the ``ctx.*`` namespace) the decision was evaluated
    # against. Advisory: contextvar-sourced and client-assertable, exactly like
    # ``role`` and ``user_id``.
    attributes: Optional[dict] = None


class LlmInvocationEvent(AuditEnvelope):
    """One LLM invocation; mirrors the llm_invocation table."""

    model: str = Field(min_length=1, max_length=256)
    # The upper bound mirrors the UInt32 columns in schema.sql. Without it an
    # over-range value (e.g. latency sent in ns) passes validation and only
    # fails at insert time — a permanent ClickHouse error the enricher would
    # retry forever instead of rejecting the span to the DLQ.
    input_tokens: int = Field(ge=0, le=UINT32_MAX)
    output_tokens: int = Field(ge=0, le=UINT32_MAX)
    latency_ms: int = Field(ge=0, le=UINT32_MAX)
    status: str = Field(default="success", max_length=64)
    error_code: str = Field(default="", max_length=64)


class DecisionAccepted(BaseModel):
    """Response shape for POST /v1/audit/decisions."""

    event_id: UUID


class BanEnforcementEvent(AuditEnvelope):
    """One kill-switch ban enforcement; mirrors the ban_enforcement table."""

    ban_type: str = Field(pattern="^(agent|user)$")
    ban_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="", max_length=1024)


class BanEnforcementAccepted(BaseModel):
    """Response shape for POST /v1/audit/ban-enforcements."""

    event_id: UUID


class LlmInvocationAccepted(BaseModel):
    """Response shape for POST /v1/audit/llm-invocations."""

    event_id: UUID


# --- Audit dashboard read models (mirror audit.py return shapes) -------------

AuditWindow = Literal["24h", "7d", "30d", "90d"]


class OutcomeCounts(BaseModel):
    """Decision counts by outcome plus the grand total for a slice."""

    all: int = 0
    allow: int = 0
    deny: int = 0
    needs_approval: int = 0


class AuditBreakdownRow(OutcomeCounts):
    """One agent/role/tool bucket; an empty role keeps its raw ``""`` key
    (the dashboard renders the "(none)" label — nothing is reserved on
    the wire).

    ``by_role`` counts membership — a caller carrying ``["billing", "support"]``
    lands in both — so its sums can exceed ``totals``. Every other breakdown
    stays one row per decision."""

    key: str


class AuditSummary(BaseModel):
    """Totals + breakdowns powering the KPI cards and breakdown panels."""

    totals: OutcomeCounts
    by_agent: list[AuditBreakdownRow]
    by_role: list[AuditBreakdownRow]
    by_tool: list[AuditBreakdownRow]
    by_user: list[AuditBreakdownRow]


class LlmInvocationTotals(BaseModel):
    """Call volume + token counts for a slice."""

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class LlmInvocationBreakdownRow(LlmInvocationTotals):
    """One model/agent/user bucket."""

    key: str


class LlmInvocationSummary(BaseModel):
    """Totals + breakdowns powering the token-usage dashboard panel."""

    totals: LlmInvocationTotals
    by_model: list[LlmInvocationBreakdownRow]
    by_agent: list[LlmInvocationBreakdownRow]
    by_user: list[LlmInvocationBreakdownRow]


class AuditTimeseriesPoint(BaseModel):
    """One time bucket of the outcome-over-time chart."""

    bucket: datetime
    allow: int = 0
    deny: int = 0
    needs_approval: int = 0


class AuditDecisionRow(BaseModel):
    """One events-table row; hint/arguments/attributes are decoded JSON."""

    event_id: UUID
    occurred_at: datetime
    received_at: datetime
    agent_name: str
    agent_version_id: str = ""
    session_id: str = ""
    user_id: str = ""
    tool_name: str
    # No legacy ``role``: an SDK that sends one has it folded into ``user_roles``
    # at ingest, so every stored row speaks the same shape.
    user_roles: list[str] = Field(default_factory=list)
    deciding_role: str = ""
    outcome: AuditOutcome
    error_type: str = ""
    reason: str = ""
    violations: list[str] = Field(default_factory=list)
    hint: Any = None
    arguments: Any = None
    attributes: Any = None


class AuditDecisionPage(BaseModel):
    """A page of rows; ``total`` is the unpaginated match count."""

    rows: list[AuditDecisionRow]
    total: int
    limit: int
    offset: int


class BanEnforcementRow(BaseModel):
    """One blocked-attempt row for the Bans page. No tool/role/outcome
    or arguments/hint — a ban is refused before any tool call runs."""

    event_id: UUID
    occurred_at: datetime
    received_at: datetime
    agent_name: str
    session_id: str = ""
    user_id: str = ""
    ban_type: BanType
    ban_id: str
    reason: str = ""


class BanEnforcementPage(BaseModel):
    """A page of ban-enforcement rows; ``total`` is the unpaginated match count."""

    rows: list[BanEnforcementRow]
    total: int
    limit: int
    offset: int


class AnomalySeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"


class AuditAnomaly(BaseModel):
    user_id: str
    severity: AnomalySeverity
    deny: int
    all: int
    deny_rate: float
    first_seen: datetime
    last_seen: datetime
