"""Cookie/dashboard-user dependencies — human auth via session cookie.

The active user comes from the FastAPI Users session cookie, with an
``X-Dev-User`` header fallback that is gated behind
``HEXGATE_ALLOW_DEV_USER_HEADER`` (test-only; off in production).
"""

import os

from fastapi import Depends, Header, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.features.auth.service import current_active_user_optional
from hexgate_api.core.db import get_session
from hexgate_api.models import User


def _dev_user_header_allowed() -> bool:
    """Whether the ``X-Dev-User`` test-only auth seam is enabled.

    Defaults to off — production servers MUST NOT accept this header,
    since it bypasses the cookie/session check and trusts whatever
    UUID the caller asserts. Tests opt in via ``conftest.py`` setting
    ``HEXGATE_ALLOW_DEV_USER_HEADER=1`` in the environment.
    """
    return os.environ.get("HEXGATE_ALLOW_DEV_USER_HEADER", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


async def require_user(
    cookie_user: User | None = Depends(current_active_user_optional),
    x_dev_user: str | None = Header(default=None, alias="X-Dev-User"),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Resolve the active dashboard user via session cookie.

    Cookie-first (production path). ``X-Dev-User`` is a TEST-ONLY
    seam gated behind ``HEXGATE_ALLOW_DEV_USER_HEADER`` — the dashboard
    no longer sends this header from Phase 3d onward; only the test
    suite uses it, via the conftest that flips the env on. Production
    deployments must leave the env unset (the default) so the header
    is silently ignored.
    """
    if cookie_user is not None:
        return cookie_user

    if x_dev_user and _dev_user_header_allowed():
        user = await session.get(User, x_dev_user)
        if user is not None and user.is_active:
            return user

    raise HTTPException(status_code=401, detail="missing or invalid authentication")
