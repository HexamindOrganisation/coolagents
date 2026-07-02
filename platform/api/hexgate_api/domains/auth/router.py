"""FastAPI Users router wiring + Google OAuth mounting.

The identity implementation (UserManager, backend, schemas) lives in
:mod:`hexgate_api.auth`; this module only assembles those pieces onto the app.
"""

import sys

from fastapi import APIRouter, FastAPI

from hexgate_api.auth import (
    UserCreate,
    UserRead,
    UserUpdate,
    auth_backend,
    build_google_oauth_router,
    fastapi_users,
)


def include_auth_routers(v1: APIRouter) -> None:
    """Mount the FastAPI Users routers under ``/v1/auth/*`` + ``/v1/users/*``.

    Cookie auth + register + email-verification + password-reset + the
    user self-service router. All ride the shared ``/v1`` prefix.
    """
    v1.include_router(
        fastapi_users.get_auth_router(auth_backend),
        prefix="/auth/cookie",
        tags=["auth"],
    )
    v1.include_router(
        fastapi_users.get_register_router(UserRead, UserCreate),
        prefix="/auth",
        tags=["auth"],
    )
    # Email verification (POST /auth/request-verify-token + /auth/verify) and
    # password reset (POST /auth/forgot-password + /auth/reset-password). Both
    # routers use the UserManager email hooks (on_after_request_verify +
    # on_after_forgot_password) to send the magic-link tokens through the mailer.
    v1.include_router(
        fastapi_users.get_verify_router(UserRead),
        prefix="/auth",
        tags=["auth"],
    )
    v1.include_router(
        fastapi_users.get_reset_password_router(),
        prefix="/auth",
        tags=["auth"],
    )
    v1.include_router(
        fastapi_users.get_users_router(UserRead, UserUpdate),
        prefix="/users",
        tags=["users"],
    )


def mount_oauth_routers(app: FastAPI) -> None:
    """Mount the Google OAuth router iff env-configured.

    Called from the lifespan once the keystore is initialised — its private
    key derives the OAuth state-token secret. With no Google credentials in
    env, this is a no-op and ``make platform-api`` works out of the box;
    flipping the two env vars and restarting turns Google sign-in on. The
    router goes onto ``app`` directly (not ``v1``) so we don't double-include
    the rest of v1 that ``app.include_router(v1)`` already mounted.
    """
    google_router = build_google_oauth_router()
    if google_router is not None:
        app.include_router(
            google_router,
            prefix="/v1/auth/google",
            tags=["auth"],
        )
        print(
            "[hexgate] Google OAuth enabled (HEXGATE_GOOGLE_CLIENT_ID set)",
            file=sys.stderr,
        )
    else:
        print(
            "[hexgate] Google OAuth disabled — set HEXGATE_GOOGLE_CLIENT_ID "
            "+ HEXGATE_GOOGLE_CLIENT_SECRET to enable",
            file=sys.stderr,
        )
