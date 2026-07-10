"""HTTP client for the Hexgate control plane.

The client trusts ``HEXGATE_API_KEY`` only after verifying its Biscuit signature
against the platform's public key. The public key is resolved in this order:

1. Explicit ``public_key`` arg passed to ``HexgateConfig``.
2. ``HEXGATE_PUBLIC_KEY`` env var (base64 url-safe, 32 raw bytes).
3. Fetched from ``GET /v1/.well-known/keys`` on first use (TOFU for POC;
   embed a build-time constant for hosted Hexgate Cloud later).

If none of the above produces a verifying key, the client raises with a
clear error rather than blindly forwarding the bearer token.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, cast

from hexgate.cloud.biscuit import (
    TokenError,
    TokenSignatureError,
    extract_facts,
    parse_envelope,
    verify_biscuit,
)
from hexgate.config.env import resolve_api_key, resolve_api_url

DEFAULT_TIMEOUT = 10.0
# Tight timeout for the conditional-GET hot path (refresh_policy runs at
# the top of every chat turn). The default 10s would stall every turn up
# to 10s when the platform is slow, even though policy refresh falls back
# to the cached bundle on failure anyway — a tight timeout makes the
# fallback fire fast.
DEFAULT_REFRESH_TIMEOUT = 2.0
TOKEN_PREFIX = "fty_"


class HexgateError(RuntimeError):
    """Raised for any Hexgate API interaction failure.

    ``status`` is the HTTP status code, or ``None`` for transport errors.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class HexgateConfig:
    """Resolved configuration for a Hexgate client.

    ``project_id`` is best-effort only — used by display surfaces
    (log lines, langchain tags) but never threaded through API URLs.
    The bearer token carries the authoritative project context;
    server-side ``GET /v1/me/key`` is the canonical lookup if
    something needs the resolved id at runtime.
    """

    base_url: str
    api_key: str
    project_id: str | None = field(default=None)
    public_key: bytes | None = field(default=None, repr=False)

    @classmethod
    def from_env(
        cls,
        *,
        project_id: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        public_key: bytes | None = None,
    ) -> HexgateConfig:
        """Resolve configuration from explicit args → env → key prefix.

        ``public_key`` is optional here — when omitted, the client fetches
        it from ``/v1/.well-known/keys`` on first use. Pass it (or set
        ``HEXGATE_PUBLIC_KEY`` env var) when you want signature verification
        without a startup network round-trip, e.g. in CI or on cold boots.

        ``project_id`` is also optional — when the key carries it in the
        envelope prefix (``fty_<env>_<project>_<biscuit>``) we surface it
        for display; when it can't be derived we return ``None`` and let
        callers either ask the platform (``GET /v1/me/key``) or display
        a placeholder. URLs never use it any more.
        """
        key = resolve_api_key(api_key)
        if not key:
            raise HexgateError(
                "HEXGATE_API_KEY not set — export it or pass api_key= explicitly"
            )

        url = resolve_api_url(base_url)

        # Display-only — never raises. A key whose envelope doesn't carry
        # the project prefix is still usable; we just won't be able to
        # show "project=..." until the server tells us.
        resolved_project = (
            project_id
            or os.environ.get("HEXGATE_PROJECT_ID")
            or _parse_project_from_key(key)
        )

        resolved_pub = public_key if public_key is not None else _public_key_from_env()

        return cls(
            base_url=url,
            api_key=key,
            project_id=resolved_project,
            public_key=resolved_pub,
        )


def _public_key_from_env() -> bytes | None:
    """Decode ``HEXGATE_PUBLIC_KEY`` (base64 url-safe) if set, else None."""
    raw = os.environ.get("HEXGATE_PUBLIC_KEY")
    if not raw:
        return None
    try:
        # urlsafe_b64decode requires padding; tolerate keys minted without it.
        padded = raw + "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(padded)
    except (ValueError, TypeError) as exc:
        raise HexgateError(f"HEXGATE_PUBLIC_KEY is not valid base64: {exc}") from exc


def _parse_project_from_key(key: str) -> str | None:
    """Best-effort parse of ``fty_<env>_<project>_<secret>`` → project id."""
    if not key.startswith(TOKEN_PREFIX):
        return None
    # fty_test_support-bot_abc...  →  ["fty", "test", "support-bot", "abc..."]
    parts = key.split("_", 3)
    if len(parts) < 4:
        return None
    return parts[2] or None


class HexgateClient:
    """Minimal HTTP client scoped to a single project + key."""

    def __init__(
        self,
        config: HexgateConfig,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        refresh_timeout: float = DEFAULT_REFRESH_TIMEOUT,
    ) -> None:
        self.config = config
        self.timeout = timeout
        # Used only by the conditional-GET path (``if_none_match`` set).
        # That path runs on every chat turn via ``refresh_policy`` and
        # tolerates failure (falls back to the cached bundle), so a
        # slow platform shouldn't tax every turn for up to ``timeout``
        # seconds.
        self.refresh_timeout = refresh_timeout
        self._public_key: bytes | None = config.public_key
        self._verified: bool = False
        self._facts: dict[str, list[str | int]] | None = None

    @classmethod
    def from_env(cls, **kwargs: Any) -> HexgateClient:
        return cls(HexgateConfig.from_env(**kwargs))

    def get_agent(
        self, name: str, *, if_none_match: str | None = None
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Fetch ``{agent_yaml, policy_yaml, system_md, ...}`` for a named agent.

        Returns ``(payload, etag)``. When ``if_none_match`` is provided and
        the platform replies ``304 Not Modified`` (the bundle hasn't changed
        since the supplied ETag), ``payload`` is ``None`` and the same etag
        is echoed back — so the caller can keep using its cached
        :class:`PolicyBundle` without re-decoding or re-verifying anything.

        Without ``if_none_match`` the call always returns ``(payload, etag)``
        with a fresh body, matching the pre-Phase-8 behavior aside from
        the now-paired etag.
        """
        self._ensure_key_verified()
        # Token-implicit project: ``/v1/agents/{name}`` resolves the
        # project from the bearer on the server side (Phase 6). The
        # legacy ``/v1/projects/{id}/agents/{name}`` URL still works on
        # the platform but only via cookie auth; we deliberately route
        # the SDK through the new bearer-only route.
        url = f"{self.config.base_url}/v1/agents/{name}"
        return self._raw_get(url, authorize=True, if_none_match=if_none_match)

    def get_bans(
        self, *, if_none_match: str | None = None
    ) -> tuple[list[dict[str, Any]] | None, str | None]:
        """Fetch the project's active bans (project from the bearer, no per-agent
        param). Returns ``(payload, etag)``; ``payload`` is ``None`` on 304.

        ``/v1/bans`` returns a bare JSON array, so we narrow ``_raw_get``'s
        object-typed return here.
        """
        self._ensure_key_verified()
        payload, etag = self._raw_get(
            f"{self.config.base_url}/v1/bans",
            authorize=True,
            if_none_match=if_none_match,
        )
        return cast("list[dict[str, Any]] | None", payload), etag

    # ------------------------------------------------------------------
    # Biscuit verification
    # ------------------------------------------------------------------

    def _ensure_key_verified(self) -> None:
        """Verify the Biscuit signature once before trusting the API key.

        Lazy on first use so that ``HexgateClient(...)`` itself stays cheap
        and side-effect-free. Subsequent calls are no-ops.

        Also caches the token's single-arity facts (``user``, ``scope``,
        numeric limits, …) for the policy engine to consume — see
        :meth:`biscuit_facts`. Extraction happens behind the same signature
        gate so callers can never read facts from an untrusted token.
        """
        if self._verified:
            return
        try:
            _, _, biscuit_b64 = parse_envelope(self.config.api_key)
        except TokenError as exc:
            raise HexgateError(f"HEXGATE_API_KEY is malformed: {exc}") from exc

        pub = self._resolve_public_key()
        try:
            verify_biscuit(biscuit_b64, pub)
            self._facts = extract_facts(biscuit_b64, pub)
        except TokenSignatureError as exc:
            raise HexgateError(
                "HEXGATE_API_KEY signature does not chain to the platform's public key. "
                "Either the key is from a different platform, or it has been tampered with."
            ) from exc
        self._verified = True

    def biscuit_facts(self) -> dict[str, list[str | int]]:
        """Return the cached, verified facts from the current API key.

        Triggers the lazy verify gate on first call, so even direct callers
        can never read facts from an unverified token. Returned dict is a
        copy — mutating it doesn't affect the cached extraction.
        """
        self._ensure_key_verified()
        if self._facts is None:
            # Invariant: _ensure_key_verified populates self._facts on success.
            # Raise so `python -O` can't strip the check.
            raise RuntimeError(
                "biscuit_facts called but _ensure_key_verified did not populate facts"
            )
        return {name: list(values) for name, values in self._facts.items()}

    def public_key_bytes(self) -> bytes:
        """Return the platform's signing public key as raw 32 bytes.

        Triggers the JWKS fetch (or returns the cached / explicitly-configured
        key) without requiring a full verify roundtrip on the API key. Callers
        feed this into :func:`hexgate.cloud.attenuate_for_user` so the
        attenuation primitive can verify the parent envelope before appending.
        """
        return self._resolve_public_key()

    def _resolve_public_key(self) -> bytes:
        """Return the platform's signing public key, fetching JWKS if needed."""
        if self._public_key is not None:
            return self._public_key
        self._public_key = self._fetch_public_key()
        return self._public_key

    def _fetch_public_key(self) -> bytes:
        """GET /v1/.well-known/keys and return the first key's raw bytes."""
        url = f"{self.config.base_url}/v1/.well-known/keys"
        payload, _ = self._raw_get(url, authorize=False)
        try:
            keys = payload["keys"]
            x = keys[0]["x"]
        except (KeyError, IndexError, TypeError) as exc:
            raise HexgateError(
                f"unexpected JWKS shape from {url}: {payload!r}"
            ) from exc
        try:
            padded = x + "=" * (-len(x) % 4)
            return base64.urlsafe_b64decode(padded)
        except (ValueError, TypeError) as exc:
            raise HexgateError(f"JWKS 'x' field is not base64: {exc}") from exc

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _get(self, url: str) -> dict[str, Any]:
        """Body-only GET. ``_raw_get`` is the unified HTTP entry point;
        this drops the ETag tuple for callers that don't care about
        conditional requests."""
        payload, _ = self._raw_get(url, authorize=True)
        if payload is None:
            # Invariant: _get is never called with If-None-Match, so a 304
            # is impossible. Raise so `python -O` can't strip the check.
            raise HexgateError(
                f"_raw_get({url!r}) returned no payload on unconditional GET"
            )
        return payload

    def _raw_get(
        self,
        url: str,
        *,
        authorize: bool,
        if_none_match: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Single HTTP entry point — returns ``(payload, etag)``.

        ``payload`` is ``None`` when the server replies ``304 Not Modified``
        (only possible when ``if_none_match`` is set). All callers go
        through here so tests have one place to mock and the ETag-aware
        refresh path doesn't duplicate the urllib dance.
        """
        headers: dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "hexgate-sdk/0.1",
        }
        if authorize:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        if if_none_match is not None:
            headers["If-None-Match"] = if_none_match
        # Conditional GETs run on the per-turn hot path and fall back to
        # the cached bundle when they fail — use the tight refresh
        # timeout so a slow platform doesn't stall every chat turn for
        # up to ``self.timeout`` seconds.
        timeout = self.refresh_timeout if if_none_match is not None else self.timeout
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                etag = response.headers.get("ETag")
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            # urllib treats 304 as an HTTPError; it's actually a success
            # case for conditional GETs.
            if exc.code == 304:
                return None, exc.headers.get("ETag") or if_none_match
            detail = exc.read().decode("utf-8", errors="replace")
            raise HexgateError(
                f"Hexgate API error {exc.code} calling {url}: {detail[:200]}",
                status=exc.code,
            ) from exc
        except urllib.error.URLError as exc:
            raise HexgateError(
                f"Hexgate API unreachable at {url}: {exc.reason}"
            ) from exc
        try:
            return json.loads(payload), etag
        except json.JSONDecodeError as exc:
            raise HexgateError(f"Hexgate API returned non-JSON from {url}") from exc
