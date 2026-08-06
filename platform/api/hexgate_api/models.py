import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Column, DateTime, LargeBinary
from sqlmodel import Field, Relationship, SQLModel, UniqueConstraint


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_uuid_str() -> str:
    """Default factory for str-typed UUID primary keys.

    UUID-format string so the value is content-addressable and
    immutable across renames (the property we wanted for project IDs);
    str-typed so the column maps to TEXT on SQLite and VARCHAR on
    Postgres without a UUID column-type cascade. FastAPI Users'
    SQLAlchemyUserDatabase is generic over the ID type, so this works
    end-to-end without subclassing the library's UUID base class.
    """
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Identity + tenancy (M3 — multi-tenant platform)
#
# Three tables make Hexgate multi-tenant: ``User`` (a person), ``Organization``
# (a tenant — what customers see as their "workspace" or "team"), and
# ``OrganizationMember`` (the many-to-many that grants a user access to an
# org, with a role on the edge).
#
# Auth-specific columns on User (hashed_password, is_verified, OAuth accounts)
# land later when we wire FastAPI Users. For v1 schema, identity = an email
# we can correlate later; tenancy is the load-bearing structure that gates
# access to every other table.
# ---------------------------------------------------------------------------


class Organization(SQLModel, table=True):
    """A tenant. Customers see this as their workspace / team.

    All other tenant-scoped data (Projects, Agents via projects, etc.) hangs
    off ``Organization`` by FK. Tenant isolation is enforced at the API layer
    by checking ``OrganizationMember`` for the active user before every
    access to anything inside this org.
    """

    id: str = Field(default_factory=new_uuid_str, primary_key=True)
    # URL-safe stable identifier — used in human-facing URLs like
    # /orgs/{slug}/dashboard. Globally unique across the platform; mutable
    # (rarely — renaming the slug breaks bookmarks but that's the user's
    # call), but the immutable ``id`` is what every FK points at.
    slug: str = Field(index=True, unique=True)
    name: str
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )


class User(SQLModel, table=True):
    """A person. One email, one account, many org memberships.

    Columns mirror what FastAPI Users' ``SQLAlchemyBaseUserTable``
    exposes — ``hashed_password`` / ``is_active`` / ``is_verified`` /
    ``is_superuser`` are the protocol attributes its UserManager +
    SQLAlchemyUserDatabase look up by name. We declare them directly
    instead of inheriting the mixin so the column types stay aligned
    with the rest of our SQLModel-based tables (str ID, no UUID mixin).
    """

    id: str = Field(default_factory=new_uuid_str, primary_key=True)
    email: str = Field(index=True, unique=True)
    # Bcrypt/argon2 digest of the password; empty for OAuth-only users
    # who never set one (Phase 3c, Google sign-in). ``""`` not ``None``
    # because FastAPI Users' protocol types this as ``str``.
    hashed_password: str = Field(default="")
    # Soft-disable a user without deleting the row. Inactive users can't log in
    # but their projects + tokens stay intact for an admin to restore.
    is_active: bool = Field(default=True)
    # Platform-staff flag. No M3 routes check it yet; reserved for the
    # eventual /admin/* surface (impersonation, cross-org diagnostics, etc.).
    is_superuser: bool = Field(default=False)
    # Email verified via the magic-link flow (Phase 3b). Created users start
    # unverified; production gates destructive actions until verified.
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )

    # Link to the provider rows (Google, GitHub, …) FastAPI Users uses to
    # find a returning OAuth user. ``lazy="selectin"`` so every User
    # fetch eagerly loads OAuth links via a second IN-clause query;
    # ``"joined"`` would do it in one SQL but produce duplicate rows
    # (one per OAuthAccount), which trips SQLAlchemy 2.0's "call
    # .unique()" guard inside fastapi-users-db-sqlalchemy's select().
    # selectin is the idiomatic load strategy for one-to-many.
    oauth_accounts: list["OAuthAccount"] = Relationship(
        sa_relationship_kwargs={"lazy": "selectin", "cascade": "all, delete-orphan"},
    )


class OAuthAccount(SQLModel, table=True):
    """Links a User to a (provider, account_id) tuple from an OAuth login.

    Created by FastAPI Users when an unknown Google account logs in
    (Phase 3c). The same User can have multiple OAuthAccount rows
    (Google + GitHub later); the unique constraint on
    ``(oauth_name, account_id)`` stops the same Google account from
    binding to two different Users.

    Columns mirror FastAPI Users' ``SQLAlchemyBaseOAuthAccountTable``
    protocol so :class:`SQLAlchemyUserDatabase` can read+write the
    table directly when wired with ``oauth_account_table=OAuthAccount``.
    """

    __tablename__ = "oauth_account"
    __table_args__ = (
        UniqueConstraint("oauth_name", "account_id", name="uq_oauth_provider_account"),
    )

    id: str = Field(default_factory=new_uuid_str, primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    oauth_name: str  # "google" | "github" | ...
    access_token: str
    # Unix epoch seconds; can be None for providers that don't expire tokens.
    expires_at: Optional[int] = None
    refresh_token: Optional[str] = None
    # Provider's stable user identifier (Google's ``sub`` claim, GitHub's
    # numeric user id, etc.). Together with ``oauth_name`` it's the lookup
    # key when a returning user lands on /callback.
    account_id: str = Field(index=True)
    account_email: str


class OrganizationMember(SQLModel, table=True):
    """User <-> Organization edge, with a role.

    A user can belong to many orgs; an org can have many members. The
    unique constraint on (user_id, org_id) enforces "at most one
    membership per pair" — role changes update the existing row.

    Role is a string (not an Enum) so we can add ``billing_admin`` /
    ``read_only`` / etc. without an Alembic migration; validation happens
    at the API layer.
    """

    __tablename__ = "organization_member"
    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_org_member"),)

    id: str = Field(default_factory=new_uuid_str, primary_key=True)
    user_id: str = Field(foreign_key="user.id", index=True)
    org_id: str = Field(foreign_key="organization.id", index=True)
    role: str  # "owner" | "admin" | "member"
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )


class Invitation(SQLModel, table=True):
    """Pending invite to join an Organization. M3 Phase 4.

    The row's ``id`` doubles as the link token — emails embed
    ``${dashboard_url}/invites/{id}/accept``, and the accept handler
    looks the row up by id. Unguessable enough on its own (UUID v4);
    rate-limit the accept endpoint anyway. ``revoked_at`` /
    ``accepted_at`` are mutually exclusive terminal states; both null
    means the invite is still pending.

    The (email, org_id) pair is unique among NON-terminal rows — we
    enforce that at the service layer rather than via a partial unique
    index (which SQLite doesn't reliably support). A second invite to
    the same email replaces the first.
    """

    id: str = Field(default_factory=new_uuid_str, primary_key=True)
    org_id: str = Field(foreign_key="organization.id", index=True)
    # Lowercase email at insertion time so accept-by-email matching is
    # case-insensitive even on SQLite (no native CI collations).
    email: str = Field(index=True)
    # Role granted on accept. Validated against the role-permissions
    # matrix in hexgate_api.features.members.service (_can_invite_role) — caller can't escalate above
    # their own role.
    role: str
    invited_by_user_id: str = Field(foreign_key="user.id")
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))
    accepted_at: Optional[datetime] = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
    revoked_at: Optional[datetime] = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )


# ---------------------------------------------------------------------------
# Existing tables — Project gains an org_id FK so it inherits tenancy.
# ---------------------------------------------------------------------------


class Project(SQLModel, table=True):
    # Unique-per-org name. A duplicate Create lands the user back on
    # 409 so the UI prompts for a different name (most likely they
    # meant to switch into the existing one instead of creating
    # another). Doesn't constrain rename — the user can pick whatever
    # name they want, just not one already taken in this org.
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_project_org_name"),)

    # UUID, immutable. Existing seed (``support-bot``) is reseeded with the
    # fixed ``DEFAULT_PROJECT_ID`` UUID in seeds.py so dev environments stay
    # reproducible across rebuilds.
    id: str = Field(primary_key=True)
    # Project belongs to exactly one org. Tenant isolation is enforced by
    # checking the active user's OrganizationMember row for this org_id
    # before any access to project-scoped data.
    org_id: str = Field(foreign_key="organization.id", index=True)
    name: str
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )


class ApiKey(SQLModel, table=True):
    id: str = Field(primary_key=True)
    project_id: str = Field(foreign_key="project.id", index=True)
    name: str
    prefix: str  # "fty_test" or "fty_live"
    secret: str  # full token value; opaque random string for Phase A
    scopes_csv: str = ""  # comma-separated for now
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )
    last_used_at: Optional[datetime] = Field(
        default=None, sa_type=DateTime(timezone=True)
    )


class Agent(SQLModel, table=True):
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_agent_project_name"),
    )

    id: str = Field(primary_key=True)
    project_id: str = Field(foreign_key="project.id", index=True)
    name: str = Field(index=True)
    agent_yaml: str  # manifest: name, model, tool list
    # Canonical policy document. May be a flat single-policy YAML (legacy
    # one-role-per-agent shape) or an inline-roles YAML with a top-level
    # ``roles:`` section. The SDK's load_policy_set_from_dict dispatches on
    # which shape is present.
    policy_yaml: str
    system_md: str = ""
    updated_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )

    # Compiled + signed WASM bundle, produced from policy_yaml at save time
    # (see hexgate_api.features.agents.compiler.compile_bundle). Null when opa is unavailable or the
    # policy fails to compile — the SDK then falls back to the pydantic
    # engine on policy_yaml. The signature is over bundle_manifest's exact
    # bytes, signed by the platform's root key (the same key that signs
    # biscuits), so the SDK verifies it against the published JWKS pubkey.
    compiled_wasm: Optional[bytes] = Field(
        default=None, sa_column=Column(LargeBinary, nullable=True)
    )
    bundle_manifest: Optional[str] = None  # exact signed JSON bytes, as text
    bundle_signature: Optional[bytes] = Field(
        default=None, sa_column=Column(LargeBinary, nullable=True)
    )


class AgentVersion(SQLModel, table=True):
    __tablename__ = "agent_version"
    __table_args__ = (
        UniqueConstraint("agent_id", "version", name="uq_agent_version"),
        UniqueConstraint("agent_id", "content_hash", name="uq_agent_content_hash"),
    )

    id: str = Field(primary_key=True)
    agent_id: str = Field(foreign_key="agent.id", index=True)
    version: int
    description: Optional[str] = None
    content_hash: str
    manifest: Optional[dict] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )


class Tool(SQLModel, table=True):
    __tablename__ = "tool"
    __table_args__ = (
        UniqueConstraint("agent_version_id", "name", name="uq_tool_agent_version_name"),
    )

    id: str = Field(primary_key=True)
    agent_version_id: str = Field(foreign_key="agent_version.id", index=True)
    name: str
    description: Optional[str] = None
    input_schema: dict = Field(sa_column=Column(JSON, nullable=False))


# ---------------------------------------------------------------------------
# Kill switch — operator hard blocks that override policy at the SDK's
# invoke-time gate. v1 targets: a whole agent or a whole user_id.
# ---------------------------------------------------------------------------


class Ban(SQLModel, table=True):
    """A hard block overriding policy for one agent or user_id, project-scoped.

    Active while ``revoked_at`` is null; revoke is a soft delete keeping the
    who/when trail (the row is the audit record). One active ban per target,
    enforced in the service like :class:`Invitation` (no SQLite partial index).
    """

    id: str = Field(primary_key=True)  # new_id(Ban) -> "ban_…"
    project_id: str = Field(foreign_key="project.id", index=True)
    ban_type: str = Field(index=True)  # "agent" | "user"
    # Exactly one set, matching ban_type; a user ban leaves this null.
    target_agent_name: Optional[str] = Field(default=None, index=True)
    target_user_id: Optional[str] = Field(default=None, index=True)
    reason: Optional[str] = None
    created_by_user_id: str = Field(foreign_key="user.id", index=True)
    created_at: datetime = Field(
        default_factory=utcnow, sa_type=DateTime(timezone=True)
    )
    revoked_at: Optional[datetime] = Field(
        default=None, sa_type=DateTime(timezone=True)
    )
    revoked_by_user_id: Optional[str] = Field(default=None, foreign_key="user.id")
