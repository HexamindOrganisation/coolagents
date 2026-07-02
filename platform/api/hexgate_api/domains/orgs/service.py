"""Organization persistence: create (+ owner membership), personal-default
bootstrap, list-for-user, and slug derivation/uniqueness."""

import secrets

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import ROLE_OWNER
from hexgate_api.models import Organization, OrganizationMember, User


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
