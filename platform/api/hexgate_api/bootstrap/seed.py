import os
import secrets

from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.models import (
    Organization,
    OrganizationMember,
    Project,
    User,
)
from hexgate_api.constants import (
    DEFAULT_MEMBERSHIP_ID,
    DEFAULT_ORG_ID,
    DEFAULT_ORG_NAME,
    DEFAULT_ORG_SLUG,
    DEFAULT_PROJECT_ID,
    DEFAULT_PROJECT_NAME,
    DEFAULT_USER_EMAIL,
    DEFAULT_USER_ID,
)
from hexgate_api.domains.agents.service import ensure_seeded_agents


def _seed_disabled() -> bool:
    """``HEXGATE_SEED=skip`` opts a deployment out of the triple-default."""
    return os.environ.get("HEXGATE_SEED", "").strip().lower() == "skip"


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
