from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, StringConstraints, field_validator


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
    """

    role: str | None = None
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
    """

    ok: bool
    errors: list[PolicyValidationError] = Field(default_factory=list)


# --- Agent manifest registration ---------------------------------------------
# These mirror hexgate/cli/register/models.py so SDK and platform stay in sync.


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
    role: str = Field(default="", max_length=256)
    error_type: str = Field(default="", max_length=64)
    reason: str = Field(default="", max_length=4096)
    # Per-item cap so 64 unbounded strings can't smuggle a multi-MB body.
    violations: list[Annotated[str, StringConstraints(max_length=1024)]] = Field(
        default_factory=list, max_length=64
    )
    # Byte caps enforced after serialization in audit.insert_decision.
    hint: Optional[dict] = None
    arguments: Optional[dict] = None


class DecisionAccepted(BaseModel):
    """Response shape for POST /v1/audit/decisions."""

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
    the wire)."""

    key: str


class AuditSummary(BaseModel):
    """Totals + breakdowns powering the KPI cards and breakdown panels."""

    totals: OutcomeCounts
    by_agent: list[AuditBreakdownRow]
    by_role: list[AuditBreakdownRow]
    by_tool: list[AuditBreakdownRow]
    by_user: list[AuditBreakdownRow]


class AuditTimeseriesPoint(BaseModel):
    """One time bucket of the outcome-over-time chart."""

    bucket: datetime
    allow: int = 0
    deny: int = 0
    needs_approval: int = 0


class AuditDecisionRow(BaseModel):
    """One events-table row; hint/arguments are decoded JSON."""

    event_id: UUID
    occurred_at: datetime
    received_at: datetime
    agent_name: str
    agent_version_id: str = ""
    session_id: str = ""
    user_id: str = ""
    tool_name: str
    role: str = ""
    outcome: AuditOutcome
    error_type: str = ""
    reason: str = ""
    violations: list[str] = Field(default_factory=list)
    hint: Any = None
    arguments: Any = None


class AuditDecisionPage(BaseModel):
    """A page of rows; ``total`` is the unpaginated match count."""

    rows: list[AuditDecisionRow]
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
