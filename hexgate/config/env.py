"""Resolution for the platform API credential and URL env vars.

``HEXGATE_API_KEY`` names the platform credential (for symmetry with
``HEXGATE_API_URL`` and the ``api_key`` parameter it feeds, and to
disambiguate it from the signing-key family — ``HEXGATE_KEYSTORE_PATH``,
``HEXGATE_PUBLIC_KEY``).
"""

from __future__ import annotations

import os

API_KEY_ENV = "HEXGATE_API_KEY"
API_URL_ENV = "HEXGATE_API_URL"
OTLP_ENDPOINT_ENV = "HEXGATE_OTLP_ENDPOINT"

# Defaults to Hexgate Cloud: the common case is a hosted key, so an unset
# URL should "just work" for it. Self-hosters / local platform runs set
# HEXGATE_API_URL=http://localhost:8000 explicitly. The key and URL are
# coupled — a key only verifies against the platform instance that minted it.
DEFAULT_API_URL = "https://app.hexgate.ai"

# The OTLP/HTTP traces path every OpenTelemetry Collector's ``otlp`` receiver
# serves by default; appended to the API URL when no dedicated OTLP endpoint
# is configured.
OTLP_TRACES_PATH = "/v1/traces"


def resolve_api_key(explicit: str | None = None) -> str | None:
    """Resolve the platform API key: ``explicit`` arg → ``HEXGATE_API_KEY``.

    Returns ``None`` when neither is set.
    """
    if explicit:
        return explicit
    return os.environ.get(API_KEY_ENV)


def resolve_api_url(explicit: str | None = None) -> str:
    """Resolve the platform API URL: ``explicit`` arg → ``HEXGATE_API_URL`` →
    ``DEFAULT_API_URL``. Empty values fall through to the next source, and the
    result has any trailing slash stripped so callers can append paths.
    """
    return (explicit or os.environ.get(API_URL_ENV) or DEFAULT_API_URL).rstrip("/")


def resolve_otlp_endpoint(
    explicit: str | None = None, base_url: str | None = None
) -> str:
    """Resolve the full OTLP/HTTP traces URL the SDK exports spans to:
    ``explicit`` arg → ``HEXGATE_OTLP_ENDPOINT`` → ``resolve_api_url(base_url)``
    + ``OTLP_TRACES_PATH``.

    The env var exists because the OTLP Collector can be deployed on a
    different host/port than the FastAPI control plane (its ``otlp``
    receiver listens on 4318 by default); the API-URL fallback keeps the
    single-host case — local dev, a reverse proxy in front of both —
    zero-config."""
    endpoint = explicit or os.environ.get(OTLP_ENDPOINT_ENV)
    if endpoint:
        return endpoint
    return f"{resolve_api_url(base_url)}{OTLP_TRACES_PATH}"
