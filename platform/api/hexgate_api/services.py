import hashlib
import json
import logging
import os
import secrets
from typing import Callable

from sqlalchemy import func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.models import (
    Agent,
    AgentVersion,
    Invitation,
    Organization,
    OrganizationMember,
    Project,
    Tool,
    User,
    utcnow,
)
from hexgate_api.constants import (
    ALL_ROLES,
    DEFAULT_MEMBERSHIP_ID,
    DEFAULT_ORG_ID,
    DEFAULT_ORG_NAME,
    DEFAULT_ORG_SLUG,
    DEFAULT_PROJECT_ID,
    DEFAULT_PROJECT_NAME,
    DEFAULT_USER_EMAIL,
    DEFAULT_USER_ID,
    ROLE_OWNER,
)
from hexgate_api.core.ids import new_id
from hexgate_api.domains.members.service import (
    _ROLE_RANK,
    _can_invite_role,
    find_member,
)
from hexgate_api.schemas import AgentManifest, ToolDefinition
from hexgate_api.seeds import SEED_AGENTS

logger = logging.getLogger("hexgate.platform.services")


def _seed_disabled() -> bool:
    """``HEXGATE_SEED=skip`` opts a deployment out of the triple-default."""
    return os.environ.get("HEXGATE_SEED", "").strip().lower() == "skip"


async def _generate_unique_org_slug(session: AsyncSession, base: str) -> str:
    """Return a globally-unique slug derived from ``base``.

    Tries the bare ``base`` first; on collision tries ``base-2``,
    ``base-3``, … up to ``-9``; falls back to ``base-<6-hex>`` after
    that. The progression keeps human-readable slugs for the common
    case (no collision) while guaranteeing uniqueness even when the
    same email-prefix is shared across providers (alice@gmail.com vs
    alice@company.com both bidding for slug ``alice``).
    """
    candidate = base
    for n in range(2, 10):
        existing = (
            await session.exec(
                select(Organization).where(Organization.slug == candidate)
            )
        ).first()
        if existing is None:
            return candidate
        candidate = f"{base}-{n}"
    # Truly contested base — fall back to a uuid suffix.
    return f"{base}-{secrets.token_hex(3)}"


def _email_to_slug_base(email: str) -> str:
    """Derive a slug-friendly base from an email's local part.

    ``alice.smith+work@company.com`` → ``alice-smith-work``. Falls back
    to ``user`` when the local part has no kept characters (an email
    like ``"++@x.com"`` is technically valid).
    """
    local = email.split("@", 1)[0].lower()
    # Keep letters/digits/dashes; collapse anything else to a dash.
    cleaned = "".join(c if c.isalnum() or c == "-" else "-" for c in local)
    # Collapse runs of dashes + trim ends.
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned or "user"


async def create_org(
    session: AsyncSession,
    *,
    name: str,
    slug: str,
    owner_user_id: str,
) -> Organization:
    """Atomically create an Organization + owner membership.

    Both rows go into the same commit — no transient state where an
    org exists with zero members. Caller is responsible for ensuring
    ``slug`` is globally unique (use :func:`_generate_unique_org_slug`).
    """
    org = Organization(name=name, slug=slug)
    session.add(org)
    await session.flush()  # populate org.id before referencing it

    member = OrganizationMember(
        user_id=owner_user_id,
        org_id=org.id,
        role=ROLE_OWNER,
    )
    session.add(member)
    await session.commit()
    await session.refresh(org)
    return org


async def ensure_personal_default_org(
    session: AsyncSession, user: User
) -> Organization:
    """Create a 'default' org for a freshly-registered user.

    Called from ``auth.UserManager.on_after_register`` so every new
    user lands on a working org from their first dashboard render —
    no "no orgs yet" empty state, no manual setup. The slug is
    derived from the email prefix with collision fallback so the URL
    reads cleanly (``/orgs/alice/...``) when Phase 5 builds the
    slug-routed UI.

    Idempotent on the caller-must-not-already-have-a-default invariant:
    if the user already owns an org, this returns it instead of
    creating a duplicate. Useful for OAuth-then-email-link merges
    (Phase 4 invite-accept).
    """
    existing = (
        await session.exec(
            select(Organization)
            .join(OrganizationMember)
            .where(OrganizationMember.user_id == user.id)
            .where(OrganizationMember.role == ROLE_OWNER)
        )
    ).first()
    if existing is not None:
        return existing

    slug = await _generate_unique_org_slug(session, _email_to_slug_base(user.email))
    return await create_org(session, name="default", slug=slug, owner_user_id=user.id)


async def list_orgs_for_user(
    session: AsyncSession, user_id: str
) -> list[tuple[Organization, str]]:
    """Return (org, role) tuples for every org the user belongs to.

    Single JOIN — no N+1 over membership rows. Result is sorted by
    org creation time so a user's personal default org (created on
    signup) lands first and additional orgs appear in join order.
    """
    stmt = (
        select(Organization, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.org_id == Organization.id)
        .where(OrganizationMember.user_id == user_id)
        .order_by(Organization.created_at)  # type: ignore[attr-defined]
    )
    return [(o, r) for o, r in (await session.exec(stmt)).all()]


# ---------------------------------------------------------------------------
# M3 Phase 4 step 4 — Invitations
#
# Admins/owners mint an Invitation row; the row's id doubles as the
# unguessable magic-link token. The invitee clicks an emailed
# ``${dashboard}/invites/{id}/accept`` link, the dashboard logs them in
# (registering first if needed) and POSTs /accept which atomically
# creates the OrganizationMember row + marks the invite consumed.
# ---------------------------------------------------------------------------


# Default lifetime — a week is enough for "I'll get to it on Monday" but
# short enough that an exfiltrated email link 6 months later is dead.
_DEFAULT_INVITE_TTL_HOURS = 168


class InvitationError(Exception):
    """Base class for invitation-validation failures.

    Routes translate the subclasses to specific HTTP codes:
      * :class:`InvitationExpired`         → 410 Gone
      * :class:`InvitationAlreadyConsumed` → 409 Conflict
      * :class:`InvitationEmailMismatch`   → 403 Forbidden
      * any other InvitationError          → 400 Bad Request
    """


class InvitationExpired(InvitationError):
    """The ``expires_at`` deadline has passed."""


class InvitationAlreadyConsumed(InvitationError):
    """The invitation was already accepted or revoked — terminal."""


class InvitationEmailMismatch(InvitationError):
    """The signed-in user's email doesn't match the invited address.

    The invite is for a specific person, not a bearer-token-for-anyone.
    Refuse strictly rather than allow anyone-with-the-link to join."""


async def create_invitation(
    session: AsyncSession,
    *,
    org_id: str,
    email: str,
    role: str,
    invited_by: OrganizationMember,
    ttl_hours: int = _DEFAULT_INVITE_TTL_HOURS,
) -> Invitation:
    """Mint a pending invitation. Cancels any existing pending invite
    for the same (org, email) pair so a re-invite produces one
    valid link rather than two.

    Refuses with ``InvitationError`` if the role is unknown or if the
    inviter doesn't outrank the target role (see :func:`_can_invite_role`).
    Email is lowercased so the case-insensitive accept-match works
    even on SQLite (no native CI collations).
    """
    from datetime import timedelta

    if role not in ALL_ROLES:
        raise InvitationError(f"unknown role: {role!r}")
    if not _can_invite_role(invited_by.role, role):
        raise InvitationError(f"a {invited_by.role} cannot invite at the {role} level")

    normalized_email = email.strip().lower()

    # Cancel any existing pending invite for this (org, email). Two
    # parallel invites would let either link redeem the seat — we want
    # exactly one canonical pending link per address per org.
    existing = (
        await session.exec(
            select(Invitation).where(
                Invitation.org_id == org_id,
                Invitation.email == normalized_email,
                Invitation.accepted_at.is_(None),  # type: ignore[union-attr]
                Invitation.revoked_at.is_(None),  # type: ignore[union-attr]
            )
        )
    ).all()
    for stale in existing:
        stale.revoked_at = utcnow()
        session.add(stale)

    invitation = Invitation(
        org_id=org_id,
        email=normalized_email,
        role=role,
        invited_by_user_id=invited_by.user_id,
        expires_at=utcnow() + timedelta(hours=ttl_hours),
    )
    session.add(invitation)
    await session.commit()
    await session.refresh(invitation)
    return invitation


async def find_invitation(
    session: AsyncSession, invitation_id: str
) -> Invitation | None:
    """Return the Invitation by id, or None. Doesn't validate
    expiry / consumed state — the caller does that (the preview
    endpoint shows expired invites with an error message rather
    than 404)."""
    return await session.get(Invitation, invitation_id)


async def list_pending_invitations(
    session: AsyncSession, org_id: str
) -> list[tuple[Invitation, User]]:
    """List non-terminal invites for an org, paired with the inviter.

    Returned tuple shape mirrors :func:`list_org_members` for symmetry —
    the dashboard's Members tab renders both as adjacent lists.
    """
    stmt = (
        select(Invitation, User)
        .join(User, User.id == Invitation.invited_by_user_id)
        .where(
            Invitation.org_id == org_id,
            Invitation.accepted_at.is_(None),  # type: ignore[union-attr]
            Invitation.revoked_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(Invitation.created_at)  # type: ignore[attr-defined]
    )
    return [(i, u) for i, u in (await session.exec(stmt)).all()]


def _ensure_utc_aware(dt):
    """Re-attach UTC tz to a datetime that lost it during a DB round-trip.

    SQLite stores TIMESTAMP as a string with no timezone info, so a
    value written as ``utcnow()`` (tz-aware UTC) comes back naive.
    Comparing a naive value against a tz-aware ``utcnow()`` raises
    ``TypeError``. The fix: treat naive DB-loaded values as already-
    UTC and attach the tz before any comparison.
    """
    from datetime import timezone

    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _is_invitation_terminal(invitation: Invitation) -> bool:
    """True if the invitation is already accepted, revoked, or expired."""
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        return True
    return _ensure_utc_aware(invitation.expires_at) < utcnow()


async def accept_invitation(
    session: AsyncSession,
    *,
    invitation: Invitation,
    accepting_user: User,
) -> OrganizationMember:
    """Atomically: validate + insert OrganizationMember + mark consumed.

    Raises:
      * :class:`InvitationExpired`         — past ``expires_at``
      * :class:`InvitationAlreadyConsumed` — already accepted or revoked
      * :class:`InvitationEmailMismatch`   — caller's email ≠ invited email

    Idempotent on retry only in the same session — once ``accepted_at``
    is set, a second call raises ``InvitationAlreadyConsumed``. That's
    intentional: a double-click on the accept button shouldn't silently
    succeed; the UI should refresh and notice the user is already a
    member.

    If the user is already a member of the org (e.g., manual add or
    re-invite), the existing membership row is returned and the
    invitation is still marked consumed. The role is *upgraded* (never
    downgraded) when the invitation's role outranks the current one —
    so an owner can promote a teammate from member → admin by sending
    a new invite, but a member-tier re-invite of an existing admin or
    owner is a no-op rather than a silent demotion.
    """
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        raise InvitationAlreadyConsumed("invitation already accepted or revoked")
    if _ensure_utc_aware(invitation.expires_at) < utcnow():
        raise InvitationExpired("invitation expired")
    if invitation.email.lower() != accepting_user.email.lower():
        # Don't echo ``invitation.email`` back: the route forwards
        # ``str(exc)`` as the HTTP detail, and a logged-in attacker who
        # got hold of an invite id would otherwise be able to harvest
        # the invitee's address. Stay generic.
        raise InvitationEmailMismatch("invitation is for a different account")

    # If already a member (re-invite of an existing teammate), reuse
    # the existing row. Otherwise create a fresh membership.
    member = await find_member(
        session, org_id=invitation.org_id, user_id=accepting_user.id
    )
    if member is None:
        member = OrganizationMember(
            user_id=accepting_user.id,
            org_id=invitation.org_id,
            role=invitation.role,
        )
        session.add(member)
    elif _ROLE_RANK.get(invitation.role, -1) > _ROLE_RANK.get(member.role, -1):
        # Re-invite is a promotion: an admin invited as owner, or a
        # member invited as admin. Upgrade in place. We never downgrade
        # on the reverse — a stray member-level re-invite of an
        # existing owner mustn't silently strip privileges.
        member.role = invitation.role
        session.add(member)
    invitation.accepted_at = utcnow()
    session.add(invitation)
    await session.commit()
    await session.refresh(member)
    return member


async def revoke_invitation(session: AsyncSession, invitation: Invitation) -> None:
    """Mark an invitation revoked. Idempotent — already-terminal
    invites silently no-op (the caller has already gotten the desired
    outcome)."""
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        return
    invitation.revoked_at = utcnow()
    session.add(invitation)
    await session.commit()


async def send_invitation_email(
    *,
    invitation: Invitation,
    org_name: str,
    inviter_email: str,
) -> None:
    """Mail the invitee a clickable accept link.

    Same HEXGATE_DASHBOARD_URL the verify/reset flows use, same
    StderrEmailSender dev mode, same swap-for-real-provider story for
    production via :func:`mailer.set_email_sender`.
    """
    import os

    from hexgate_api.core.mailer import get_email_sender

    dashboard_url = os.environ.get(
        "HEXGATE_DASHBOARD_URL", "http://localhost:5173"
    ).rstrip("/")
    link = f"{dashboard_url}/invites/{invitation.id}/accept"
    ttl_hours = max(
        1,
        int(
            (_ensure_utc_aware(invitation.expires_at) - utcnow()).total_seconds() / 3600
        ),
    )

    body = (
        f"Hi,\n\n"
        f'{inviter_email} invited you to join the "{org_name}" '
        f"organisation on Hexgate as a {invitation.role}.\n\n"
        f"Open this link to accept (you'll be prompted to sign in or sign\n"
        f"up first if you don't have an account):\n\n"
        f"    {link}\n\n"
        f"The link expires in about {ttl_hours} hours. If you don't\n"
        f"recognise the sender, just delete this email — nothing happens\n"
        f"until you click.\n"
    )
    await get_email_sender().send(
        to=invitation.email,
        subject=f"{inviter_email} invited you to {org_name} on Hexgate",
        body=body,
    )


# ---------------------------------------------------------------------------
# First-boot seeding — the triple-default Org + User + Membership + Project
# + agents. Cross-domain by nature; lives here until a dedicated bootstrap
# module owns it.
# ---------------------------------------------------------------------------


def _announce_default_admin_credentials(email: str, password: str) -> None:
    """Loud one-shot stderr print of the freshly-generated admin password.

    Same posture as ``FileKeyStore._announce_first_run`` — operators
    only see this once, ever; subsequent boots are silent. The password
    is never logged again from anywhere in the codebase.
    """
    import sys

    bar = "=" * 72
    print(
        f"\n{bar}\n"
        f"FIRST-BOOT DEFAULT ADMIN CREDENTIALS\n"
        f"   email:    {email}\n"
        f"   password: {password}\n\n"
        f"This is printed ONCE on first boot. Save it now — there is no\n"
        f"second display. Sign in at the dashboard and rotate the password\n"
        f"via your account settings as soon as you're in.\n"
        f"\n"
        f"Self-hosted deployments that don't want a default account at\n"
        f"all should set HEXGATE_SEED=skip and POST /v1/auth/register\n"
        f"to bootstrap their first user from scratch.\n"
        f"{bar}\n",
        file=sys.stderr,
        flush=True,
    )


async def ensure_default_seed(session: AsyncSession) -> Project | None:
    """Idempotently create the triple-default: Org + User + Membership + Project + agents.

    First-boot UX for self-hosters and `make platform-api`. Every step is
    individually idempotent so calling this on an already-seeded DB is a
    no-op — same shape `ensure_default_project` used to have, just broader.

    Returns the default Project, or ``None`` when ``HEXGATE_SEED=skip``
    is set (production hosted deployments). When skipped, callers must
    handle the empty-DB case explicitly — there is no implicit project.
    """
    if _seed_disabled():
        return None

    # Org first — Project FKs to it, so it has to exist before the project.
    org = await session.get(Organization, DEFAULT_ORG_ID)
    if org is None:
        org = Organization(
            id=DEFAULT_ORG_ID,
            slug=DEFAULT_ORG_SLUG,
            name=DEFAULT_ORG_NAME,
        )
        session.add(org)

    # Default admin user. M3 Phase 3a: first boot generates a fresh
    # random password, hashes it via FastAPI Users' PasswordHelper, and
    # prints the plaintext to stderr ONCE for the operator to copy. On
    # every subsequent boot the row already exists → no print, no
    # re-hash, no behaviour change. Production deployments that don't
    # want a default account set HEXGATE_SEED=skip and create their
    # first user via POST /v1/auth/register instead.
    user = await session.get(User, DEFAULT_USER_ID)
    if user is None:
        from fastapi_users.password import PasswordHelper

        password_plain = secrets.token_urlsafe(16)
        hashed = PasswordHelper().hash(password_plain)
        user = User(
            id=DEFAULT_USER_ID,
            email=DEFAULT_USER_EMAIL,
            hashed_password=hashed,
            is_active=True,
            # Default seed user is auto-verified — no email flow runs at
            # `make platform-api`. Real registered users start unverified.
            is_verified=True,
            is_superuser=True,
        )
        session.add(user)
        _announce_default_admin_credentials(DEFAULT_USER_EMAIL, password_plain)

    # Owner membership wiring user → org. The unique constraint on
    # (user_id, org_id) makes this safe to re-add on subsequent boots.
    member = await session.get(OrganizationMember, DEFAULT_MEMBERSHIP_ID)
    if member is None:
        member = OrganizationMember(
            id=DEFAULT_MEMBERSHIP_ID,
            user_id=DEFAULT_USER_ID,
            org_id=DEFAULT_ORG_ID,
            role="owner",
        )
        session.add(member)

    project = await session.get(Project, DEFAULT_PROJECT_ID)
    if project is None:
        project = Project(
            id=DEFAULT_PROJECT_ID,
            org_id=DEFAULT_ORG_ID,
            name=DEFAULT_PROJECT_NAME,
        )
        session.add(project)

    await session.commit()
    await session.refresh(project)
    # Always ensure seeded agents exist — idempotent, so existing projects
    # pick up the `default` guarantee on any subsequent boot.
    await ensure_seeded_agents(session, project.id)
    return project


# Back-compat alias for callers that still use the old name. New code uses
# ``ensure_default_seed`` directly; this one-liner keeps existing imports
# (main.py, tests) working without a renaming sweep this turn.
ensure_default_project = ensure_default_seed


async def ensure_seeded_agents(session: AsyncSession, project_id: str) -> None:
    """Idempotently add any missing seeded agents to a project."""
    existing = {a.name for a in await list_agents(session, project_id)}
    added = False
    for seed in SEED_AGENTS:
        if seed["name"] in existing:
            continue
        session.add(
            Agent(
                id=new_id(Agent),
                project_id=project_id,
                name=seed["name"],
                agent_yaml=seed["agent_yaml"],
                policy_yaml=seed["policy_yaml"],
                system_md=seed["system_md"],
            )
        )
        added = True
    if added:
        await session.commit()


async def list_agents(session: AsyncSession, project_id: str) -> list[Agent]:
    stmt = select(Agent).where(Agent.project_id == project_id).order_by(Agent.name)  # type: ignore[attr-defined]
    return list((await session.exec(stmt)).all())


async def get_agent(session: AsyncSession, project_id: str, name: str) -> Agent | None:
    stmt = select(Agent).where(Agent.project_id == project_id, Agent.name == name)
    return (await session.exec(stmt)).first()


async def get_latest_agent_version_id(
    session: AsyncSession, project_id: str, agent_name: str
) -> str:
    """Return the latest AgentVersion.id for (project, agent), or "" if unresolved."""
    agent = await get_agent(session, project_id, agent_name)
    if agent is None:
        return ""
    stmt = (
        select(AgentVersion.id)
        .where(AgentVersion.agent_id == agent.id)
        .order_by(AgentVersion.version.desc())  # type: ignore[attr-defined]
        .limit(1)
    )
    return (await session.exec(stmt)).first() or ""


async def get_latest_agent_versions_map(
    session: AsyncSession, agent_ids: list[str]
) -> dict[str, AgentVersion]:
    """Return a map of {agent_id: latest AgentVersion}
    for a list of agent ids in a single query.

    Agents with no registered version are omitted from the map.
    """
    if not agent_ids:
        return {}
    max_version_per_agent = (
        select(
            AgentVersion.agent_id,
            func.max(AgentVersion.version).label("max_version"),
        )
        .where(AgentVersion.agent_id.in_(agent_ids))
        .group_by(AgentVersion.agent_id)
        .subquery()
    )
    statement = select(AgentVersion).join(
        max_version_per_agent,
        (AgentVersion.agent_id == max_version_per_agent.c.agent_id)
        & (AgentVersion.version == max_version_per_agent.c.max_version),
    )
    return {
        version.agent_id: version for version in (await session.exec(statement)).all()
    }


def compile_bundle(
    policy_yaml: str, sign: Callable[[bytes], bytes]
) -> tuple[bytes, str, bytes] | None:
    """Compile ``policy_yaml`` to a signed WASM bundle.

    Runs the SDK's YAML → Rego → WASM compiler, builds a manifest with the
    content hashes, and signs the manifest's exact bytes with ``sign`` (the
    platform's root key). Returns ``(wasm_bytes, manifest_text, signature)``,
    or ``None`` when compilation can't happen — ``opa`` not installed, or the
    policy is malformed. A ``None`` return is not an error: the caller stores
    no bundle and the SDK falls back to the pydantic engine.

    Stays sync because it doesn't touch the DB — only shells out to ``opa``
    via the SDK. Callers run it inside an async handler via the default
    threadpool (``asyncio.to_thread``) if they need to keep the event loop
    responsive during a long compile; for our tiny policies a direct call
    is fine.
    """
    # Imported lazily so the platform still boots if the SDK / opa aren't
    # present — only save-time compilation needs them. build_signed_bundle
    # is the SAME helper `hexgate policy build` uses, so the manifest format
    # and its byte-exact serialization can't drift between the two.
    from hexgate.security import build_signed_bundle
    from hexgate.security.rego_wasm import OpaNotFoundError

    try:
        bundle = build_signed_bundle(policy_yaml, sign=sign)
    except OpaNotFoundError:
        logger.warning(
            "compile_bundle: opa not on PATH — storing no bundle "
            "(SDK will fall back to pydantic). Install opa to ship signed bundles."
        )
        return None
    except Exception as exc:
        # Any other compile failure (bad constraint, schema error, opa build
        # error) degrades gracefully — the save still succeeds without a bundle.
        logger.warning("compile_bundle: policy did not compile: %s", exc)
        return None

    return bundle.wasm_bytes, bundle.manifest_bytes.decode("utf-8"), bundle.signature


async def update_agent(
    session: AsyncSession,
    project_id: str,
    name: str,
    *,
    agent_yaml: str | None = None,
    policy_yaml: str | None = None,
    system_md: str | None = None,
    sign: Callable[[bytes], bytes] | None = None,
) -> Agent | None:
    from datetime import datetime, timezone

    agent = await get_agent(session, project_id, name)
    if agent is None:
        return None
    if agent_yaml is not None:
        agent.agent_yaml = agent_yaml
    if policy_yaml is not None:
        agent.policy_yaml = policy_yaml
    if system_md is not None:
        agent.system_md = system_md

    # Recompile + re-sign the bundle from the (possibly updated) policy. We
    # always rebuild rather than diff so a fixed policy re-acquires a bundle
    # and a newly-broken one drops its stale (now-wrong) bundle.
    if sign is not None:
        bundle = compile_bundle(agent.policy_yaml, sign)
        if bundle is not None:
            agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
        else:
            agent.compiled_wasm = None
            agent.bundle_manifest = None
            agent.bundle_signature = None

    agent.updated_at = datetime.now(timezone.utc)
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent


async def backfill_bundles(
    session: AsyncSession, sign: Callable[[bytes], bytes]
) -> int:
    """Compile + sign a bundle for every agent that doesn't already have one.

    Seeded agents are inserted directly (``ensure_default_project`` builds
    ``Agent(...)`` without the save-time compile hook), so on a fresh DB
    they start bundle-less and would be served via the pydantic fallback.
    Running this at startup means even a brand-new platform serves signed
    WASM bundles for the seeds on the very first request.

    Idempotent: agents that already carry a bundle are skipped, and a
    policy that won't compile (or a platform without opa) is simply left
    bundle-less. Returns the number of agents backfilled.
    """
    count = 0
    agents = (await session.exec(select(Agent))).all()
    for agent in agents:
        if agent.compiled_wasm is not None:
            continue
        bundle = compile_bundle(agent.policy_yaml, sign)
        if bundle is None:
            continue
        agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
        session.add(agent)
        count += 1
    if count:
        await session.commit()
    return count


# --- Agent manifest registration --------------------------------------------


# Tool-name heuristics used by ``_classify_tool`` to bucket a tool into one of
# four categories. Matched against the LOWERCASED tool name with a substring
# search — so ``Read_File`` and ``read_file`` both land in "read". The
# patterns are deliberately broad: misclassification on a brand-new agent is
# a one-time editing chore, while missing a write-shape tool would silently
# hand a freshly-registered agent more power than the operator intended.
_SHELL_PATTERNS = (
    "bash",
    "shell",
    "exec",
    "run_command",
    "subprocess",
    "spawn",
)
_WRITE_PATTERNS = (
    "write_",
    "_write",
    "edit_",
    "create_",
    "update_",
    "delete_",
    "remove_",
    "patch_",
    "post_",
    "put_",
)
_READ_PATTERNS = (
    "read_",
    "_read",
    "search",
    "fetch",
    "list_",
    "get_",
    "find_",
    "grep",
    "glob",
    "view_",
    "describe_",
    "inspect_",
)


def _classify_tool(name: str) -> str:
    """Return one of ``"read" | "write" | "shell" | "unknown"`` for a tool name.

    Order matters: shell wins over write (a tool literally named
    ``run_command`` matches both ``run_command`` and ``_command``), and read
    is checked last so write-prefix takes precedence over a misleading
    ``read_`` substring elsewhere in the name.

    ``"unknown"`` is the fail-closed bucket — callers should treat it as
    write-shape so a brand-new agent doesn't silently inherit power the
    operator didn't authorize.
    """
    lower = name.lower()
    if any(p in lower for p in _SHELL_PATTERNS):
        return "shell"
    if any(p in lower for p in _WRITE_PATTERNS):
        return "write"
    if any(p in lower for p in _READ_PATTERNS):
        return "read"
    return "unknown"


def _emit_tool_lines(names: list[str], mode: str, indent: int = 6) -> str:
    """Render ``{name: { mode: ... }}`` lines for a YAML policy block.

    Returns an empty string when ``names`` is empty — the caller can drop
    the surrounding ``tools:`` key entirely if all its buckets are empty,
    keeping the generated YAML clean (no dangling ``tools:`` with no
    children, which the AgentPolicy validator rejects).
    """
    pad = " " * indent
    return "".join(f"{pad}{n}: {{ mode: {mode} }}\n" for n in names)


def _default_policy_for_manifest(manifest: AgentManifest) -> str:
    """Build a starter role-aware ``policy_yaml`` from a manifest's tools.

    Modeled on the ``support_bot`` seed at :mod:`platform.api.seeds`:

      - ``read_only`` (mixin) — every read-shape tool from the manifest.
      - ``default`` — inherits ``read_only``, used when no User scope is set.
      - ``member`` — inherits ``read_only``; writes + shells + unknowns
        require approval.
      - ``admin`` — inherits ``read_only``; writes pass through, shells
        still require approval.

    Unknown tools (those that didn't match any heuristic) land in the
    write bucket — fail-closed, surfaced to the operator via a comment so
    they can reclassify in the dashboard editor.

    Only called for brand-new agents (first POST /v1/agents for a given
    name); re-registers of an existing agent leave the operator's edited
    policy alone.
    """
    reads: list[str] = []
    writes: list[str] = []
    shells: list[str] = []
    unknowns: list[str] = []
    for tool in manifest.tools:
        bucket = _classify_tool(tool.name)
        if bucket == "read":
            reads.append(tool.name)
        elif bucket == "shell":
            shells.append(tool.name)
        elif bucket == "write":
            writes.append(tool.name)
        else:
            unknowns.append(tool.name)

    # Heads-up comment for unknown-bucket tools — the operator sees them
    # in the dashboard editor and can move them to a more appropriate
    # bucket. Empty when every tool classified cleanly.
    unknown_note = (
        "# Heuristic could not classify these tools — treating as writes\n"
        "# (fail-closed). Move them to read_only or shells as appropriate:\n"
        + "".join(f"#   - {n}\n" for n in unknowns)
        + "\n"
        if unknowns
        else ""
    )

    # ``read_only`` body — drop the ``tools:`` key when the manifest has
    # zero read-shape tools to avoid emitting ``tools:`` with no children
    # (rejected by the policy parser).
    read_only_tools = f"    tools:\n{_emit_tool_lines(reads, 'allow')}" if reads else ""

    # member + admin override blocks. ``writes + unknowns`` always get the
    # role-appropriate mode; shells are pinned to approval_required across
    # both roles because shells are the highest-blast-radius primitive
    # and shouldn't differ between operator personas.
    member_overrides = writes + unknowns + shells
    member_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'approval_required')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if member_overrides
        else ""
    )
    admin_overrides = writes + unknowns + shells
    admin_tools = (
        f"    tools:\n"
        f"{_emit_tool_lines(writes + unknowns, 'allow')}"
        f"{_emit_tool_lines(shells, 'approval_required')}"
        if admin_overrides
        else ""
    )

    return f"""version: 1
# Generated by `hexgate register`. Edit freely — re-running register
# never overwrites this; it only updates the manifest snapshot.
#
# Four entries:
#   read_only  (mixin)  factored-out 'safe to read' allowlist
#   default             fallback when no User scope is set
#   member              typical user; writes + shells require approval
#   admin               power user; writes allow, shells still gate
#
# Note: 'admin' here is an AGENT policy role (used by the SDK at request
# time via User(role="admin")), distinct from the ORG admin role on
# /orgs/:id/members.

{unknown_note}roles:
  read_only:
    is_mixin: true
    default_policy:
      mode: deny
{read_only_tools}
  default:
    inherits: [read_only]

  member:
    inherits: [read_only]
{member_tools}
  admin:
    inherits: [read_only]
{admin_tools}"""


def compute_manifest_hash(manifest: AgentManifest) -> str:
    """Reproducible SHA-256 of an agent manifest.

    Canonical JSON encoding (sorted keys, no whitespace) so the same manifest
    always hashes to the same hex digest regardless of Python dict ordering.

    ``exclude_none=True`` keeps hash continuity across schema growth: when a
    new ``Optional`` field lands with a ``None`` default, an old manifest
    re-registered against the new schema still produces the same digest it
    did before — so ``_find_version_by_hash`` matches and we don't create a
    duplicate ``AgentVersion`` row for what is functionally the same content.
    """
    payload = manifest.model_dump(mode="json", exclude_none=True)
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def register_manifest(
    session: AsyncSession,
    project_id: str,
    manifest: AgentManifest,
    *,
    sign: Callable[[bytes], bytes],
) -> tuple[AgentVersion, bool]:
    """Upsert an agent + version from an AgentManifest.

    Returns ``(version, created)`` where ``created`` is False if a version
    with the same content_hash already existed under this agent — in which
    case nothing is written and the existing row is returned.

    On FIRST registration of an agent (the ``Agent`` row is being created
    for the first time), this also:

      1. Generates a starter role-aware ``policy_yaml`` from the manifest's
         tool list (see :func:`_default_policy_for_manifest`). The dev sees
         this in the dashboard's policy editor and edits from there.
      2. Compiles + signs the bundle so ``hexgate serve`` runs against
         signed WASM from the very first request, not the pydantic
         fallback. Signing failures degrade gracefully (no bundle stored,
         SDK falls through to pydantic) — same shape as ``update_agent``.

    On subsequent registers of an existing agent, ``agent.policy_yaml`` is
    left alone — policy belongs to the operator, manifest updates are just
    snapshot churn.
    """
    content_hash = compute_manifest_hash(manifest)
    agent, agent_created = await _get_or_create_agent(
        session, project_id, manifest.name
    )

    if agent_created:
        # Brand-new agent — seed the policy + bundle so the dashboard's
        # Policies editor has something to render and ``hexgate serve``
        # has a signed bundle to ship.
        agent.policy_yaml = _default_policy_for_manifest(manifest)
        bundle = compile_bundle(agent.policy_yaml, sign)
        if bundle is not None:
            agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
        # Already in session via _get_or_create_agent; the mutation flushes
        # at commit time below alongside the AgentVersion + Tool rows.

    if not agent_created:
        existing = await _find_version_by_hash(session, agent.id, content_hash)
        if existing is not None:
            return existing, False

    next_version = 1 if agent_created else await _next_version_number(session, agent.id)
    version = await _create_agent_version(
        session, agent.id, manifest, content_hash, next_version
    )
    await _create_tools(session, version.id, manifest.tools)

    await session.commit()
    await session.refresh(version)
    return version, True


async def _get_or_create_agent(
    session: AsyncSession, project_id: str, name: str
) -> tuple[Agent, bool]:
    """Return the Agent for (project_id, name), creating it if missing.

    The agent_yaml / policy_yaml columns are legacy NOT-NULL fields from the
    YAML-edited dashboard flow; code-defined agents leave them empty since the
    actual content lives on each AgentVersion.
    """
    agent = await get_agent(session, project_id, name)
    if agent is not None:
        return agent, False
    agent = Agent(
        id=new_id(Agent),
        project_id=project_id,
        name=name,
        agent_yaml="",
        policy_yaml="",
        system_md="",
    )
    session.add(agent)
    await session.flush()
    return agent, True


async def _find_version_by_hash(
    session: AsyncSession, agent_id: str, content_hash: str
) -> AgentVersion | None:
    """Return the existing AgentVersion with this content_hash, if any."""
    stmt = select(AgentVersion).where(
        AgentVersion.agent_id == agent_id,
        AgentVersion.content_hash == content_hash,
    )
    return (await session.exec(stmt)).first()


async def _next_version_number(session: AsyncSession, agent_id: str) -> int:
    """Return the next sequential version number for an agent."""
    last = (
        await session.exec(
            select(AgentVersion)
            .where(AgentVersion.agent_id == agent_id)
            .order_by(AgentVersion.version.desc())  # type: ignore[attr-defined]
        )
    ).first()
    return (last.version + 1) if last is not None else 1


async def _create_agent_version(
    session: AsyncSession,
    agent_id: str,
    manifest: AgentManifest,
    content_hash: str,
    version: int,
) -> AgentVersion:
    """Create and persist a new AgentVersion row for `manifest`."""
    row = AgentVersion(
        id=new_id(AgentVersion),
        agent_id=agent_id,
        version=version,
        description=manifest.description,
        content_hash=content_hash,
        manifest=manifest.model_dump(mode="json"),
    )
    session.add(row)
    await session.flush()
    return row


async def _create_tools(
    session: AsyncSession,
    agent_version_id: str,
    tools: list[ToolDefinition],
) -> None:
    """Insert one Tool row per ToolDefinition under an agent version."""
    for tool in tools:
        session.add(
            Tool(
                id=new_id(Tool),
                agent_version_id=agent_version_id,
                name=tool.name,
                description=tool.description,
                input_schema=tool.input_schema.model_dump(mode="json"),
            )
        )
