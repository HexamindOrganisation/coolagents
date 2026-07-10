"""Tests for ``HexgateConfig`` and ``HexgateClient`` (SDK side).

Covers configuration resolution (explicit args / env / key prefix),
public-key sourcing precedence, and the lazy verify-before-trust flow
without making any real network calls.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from biscuit_auth import Algorithm, BiscuitBuilder, KeyPair, PrivateKey

from hexgate.cloud.client import (
    HexgateClient,
    HexgateConfig,
    HexgateError,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def keys() -> tuple[bytes, bytes]:
    """Fresh Ed25519 keypair as ``(priv, pub)`` raw bytes."""
    kp = KeyPair()
    return kp.private_key.to_bytes(), kp.public_key.to_bytes()


def _envelope(
    priv: bytes,
    project: str = "support-bot",
    env: str = "live",
    *,
    extra_facts: str = "",
) -> str:
    """Mint a fully-formed ``fty_<env>_<project>_<biscuit_b64>`` envelope.

    Pass ``extra_facts='user("alice"); refund_limit(50);'`` to add
    extraction-test-friendly facts to the authority block.
    """
    pk = PrivateKey.from_bytes(priv, Algorithm.Ed25519)
    source = f'project("{project}"); env("{env}"); {extra_facts}'.strip()
    biscuit = BiscuitBuilder(source).build(pk)
    return f"fty_{env}_{project}_{biscuit.to_base64()}"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear the HEXGATE_* env keys so resolution tests don't leak state."""
    for key in (
        "HEXGATE_API_KEY",
        "HEXGATE_API_URL",
        "HEXGATE_PROJECT_ID",
        "HEXGATE_PUBLIC_KEY",
    ):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# HexgateConfig.from_env — resolution rules
# ---------------------------------------------------------------------------


def test_config_uses_explicit_args(clean_env: None) -> None:
    """Explicit args win over env, env over key prefix."""
    config = HexgateConfig.from_env(
        api_key="fty_live_explicit-proj_abc",
        base_url="http://test.local",
        project_id="overridden",
    )
    assert config.api_key == "fty_live_explicit-proj_abc"
    assert config.base_url == "http://test.local"
    assert config.project_id == "overridden"


def test_config_defaults_to_hexgate_cloud(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """Unset HEXGATE_API_URL resolves to Hexgate Cloud, not localhost."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_proj_secret")
    config = HexgateConfig.from_env()
    assert config.base_url == "https://app.hexgate.ai"


def test_config_strips_trailing_slash_from_base_url(clean_env: None) -> None:
    """A trailing ``/`` on HEXGATE_API_URL would double up in path concatenation."""
    config = HexgateConfig.from_env(
        api_key="fty_live_proj_secret",
        base_url="http://test.local/",
    )
    assert config.base_url == "http://test.local"


def test_config_resolves_project_from_env(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """HEXGATE_PROJECT_ID overrides whatever the key prefix encodes."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_key-proj_secret")
    monkeypatch.setenv("HEXGATE_PROJECT_ID", "env-proj")
    config = HexgateConfig.from_env()
    assert config.project_id == "env-proj"


def test_config_resolves_project_from_key_prefix(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """When neither arg nor env give a project, parse it from the key prefix."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_my-cool-project_secret")
    config = HexgateConfig.from_env()
    assert config.project_id == "my-cool-project"


def test_config_raises_when_key_missing(clean_env: None) -> None:
    """No HEXGATE_API_KEY is fail-fast, not silent default."""
    with pytest.raises(HexgateError, match="HEXGATE_API_KEY not set"):
        HexgateConfig.from_env()


def test_config_allows_unresolvable_project(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """A key without the fty_ prefix is still usable post-Phase-6.

    Project id is display-only now — the bearer carries it for
    routing on the server side, and the CLI/SDK no longer threads
    it through URLs. A missing project_id surfaces as ``None``,
    not an error.
    """
    monkeypatch.setenv("HEXGATE_API_KEY", "completely_unparseable_key")
    config = HexgateConfig.from_env()
    assert config.project_id is None
    # The key still goes through verbatim — the server is the
    # authority on whether it's actually valid.
    assert config.api_key == "completely_unparseable_key"


# ---------------------------------------------------------------------------
# HexgateConfig.from_env — public key sourcing
# ---------------------------------------------------------------------------


def test_config_public_key_from_explicit_arg(
    keys: tuple[bytes, bytes],
    clean_env: None,
) -> None:
    """Explicit ``public_key=`` is preferred over env."""
    _, pub = keys
    config = HexgateConfig.from_env(
        api_key="fty_live_proj_secret",
        public_key=pub,
    )
    assert config.public_key == pub


def test_config_public_key_from_env(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """HEXGATE_PUBLIC_KEY env (urlsafe-b64) decodes into raw bytes."""
    _, pub = keys
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_proj_secret")
    monkeypatch.setenv("HEXGATE_PUBLIC_KEY", _b64url(pub))
    config = HexgateConfig.from_env()
    assert config.public_key == pub


def test_config_public_key_env_handles_missing_padding(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """urlsafe_b64decode requires padding, but operators may strip it."""
    _, pub = keys
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_proj_secret")
    encoded = base64.urlsafe_b64encode(pub).decode("ascii").rstrip("=")
    monkeypatch.setenv("HEXGATE_PUBLIC_KEY", encoded)
    config = HexgateConfig.from_env()
    assert config.public_key == pub


def test_config_invalid_pubkey_env_raises(
    monkeypatch: pytest.MonkeyPatch,
    clean_env: None,
) -> None:
    """Non-base64 HEXGATE_PUBLIC_KEY is a startup-time misconfiguration."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_proj_secret")
    monkeypatch.setenv("HEXGATE_PUBLIC_KEY", "!!!not-base64!!!")
    with pytest.raises(HexgateError, match="not valid base64"):
        HexgateConfig.from_env()


def test_config_no_public_key_when_neither_set(clean_env: None) -> None:
    """Without explicit arg or env var, public_key is None — JWKS fetch later."""
    config = HexgateConfig.from_env(api_key="fty_live_proj_secret")
    assert config.public_key is None


# ---------------------------------------------------------------------------
# HexgateClient — lazy verify on first call
# ---------------------------------------------------------------------------


def _stub_get_agent_response(name: str = "default") -> dict[str, Any]:
    return {
        "id": "agt_test",
        "name": name,
        "agent_yaml": "name: default\n",
        "policy_yaml": "version: 1\n",
        "system_md": "",
        "updated_at": "2026-05-06T00:00:00Z",
    }


def test_client_verifies_on_first_call_then_caches(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First call sets verified=True; second call short-circuits."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key=_envelope(priv),
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    calls: list[tuple[str, bool]] = []

    def fake_raw_get(
        self: HexgateClient,
        url: str,
        *,
        authorize: bool,
        if_none_match: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        calls.append((url, authorize))
        return _stub_get_agent_response(), None

    monkeypatch.setattr(HexgateClient, "_raw_get", fake_raw_get)

    assert not client._verified
    client.get_agent("default")
    assert client._verified
    assert len(calls) == 1
    assert calls[0][1] is True  # authorized

    client.get_agent("default")
    assert len(calls) == 2  # no extra verify call


def test_client_rejects_tampered_key_before_any_http(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tampered envelope fails the sig check; no HTTP request is sent."""
    priv, pub = keys
    tampered = _envelope(priv)[:-4] + "AAAA"
    config = HexgateConfig(
        base_url="http://test",
        api_key=tampered,
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    def must_not_be_called(*args: Any, **kwargs: Any) -> dict[str, Any]:
        pytest.fail("HTTP request fired despite signature failure")

    monkeypatch.setattr(HexgateClient, "_raw_get", must_not_be_called)

    with pytest.raises(HexgateError, match="signature does not chain"):
        client.get_agent("default")


def test_client_rejects_malformed_envelope(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-fty envelope surfaces a clear HexgateError."""
    _, pub = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key="not_an_envelope_at_all",
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    monkeypatch.setattr(
        HexgateClient,
        "_raw_get",
        lambda *a, **kw: pytest.fail("HTTP fired despite malformed key"),
    )

    with pytest.raises(HexgateError, match="malformed"):
        client.get_agent("default")


def test_client_fetches_jwks_when_pubkey_unset(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a cached pubkey, the client fetches /v1/.well-known/keys first."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key=_envelope(priv),
        project_id="support-bot",
        public_key=None,  # forces JWKS fetch
    )
    client = HexgateClient(config)

    calls: list[tuple[str, bool]] = []

    def fake_raw_get(
        self: HexgateClient,
        url: str,
        *,
        authorize: bool,
        if_none_match: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        calls.append((url, authorize))
        if url.endswith("/.well-known/keys"):
            return (
                {
                    "keys": [
                        {"x": _b64url(pub), "fingerprint": "sha256:abcdef0123456789"}
                    ]
                },
                None,
            )
        return _stub_get_agent_response(), None

    monkeypatch.setattr(HexgateClient, "_raw_get", fake_raw_get)

    client.get_agent("default")

    # JWKS first (unauthorized), then agent fetch (authorized).
    assert len(calls) == 2
    assert calls[0][0].endswith("/v1/.well-known/keys")
    assert calls[0][1] is False
    # Phase 6: agent fetch is token-implicit, no project_id in URL.
    assert calls[1][0].endswith("/v1/agents/default")
    assert calls[1][1] is True


def test_client_jwks_response_with_unexpected_shape_raises(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A JWKS response missing 'keys' or 'x' surfaces a clear error."""
    priv, _ = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key=_envelope(priv),
        project_id="support-bot",
        public_key=None,
    )
    client = HexgateClient(config)

    monkeypatch.setattr(
        HexgateClient,
        "_raw_get",
        lambda self, url, *, authorize, if_none_match=None: (
            {"unexpected": "shape"},
            None,
        ),
    )

    with pytest.raises(HexgateError, match="unexpected JWKS shape"):
        client.get_agent("default")


# ---------------------------------------------------------------------------
# HexgateClient.biscuit_facts() — fact extraction behind the verify gate
# ---------------------------------------------------------------------------


def test_client_biscuit_facts_returns_token_facts(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """biscuit_facts() runs the verify gate and returns the cached facts."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key=_envelope(
            priv, extra_facts='user("alice"); refund_limit(50); scope("refund");'
        ),
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    facts = client.biscuit_facts()
    # project + env are stamped by _envelope itself
    assert facts["user"] == ["alice"]
    assert facts["refund_limit"] == [50]
    assert facts["scope"] == ["refund"]
    assert facts["project"] == ["support-bot"]


def test_client_biscuit_facts_runs_verify_gate(
    keys: tuple[bytes, bytes],
) -> None:
    """A tampered token must surface as HexgateError, not return partial facts."""
    priv, pub = keys
    tampered = _envelope(priv)[:-4] + "AAAA"
    config = HexgateConfig(
        base_url="http://test",
        api_key=tampered,
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    with pytest.raises(HexgateError, match="signature does not chain"):
        client.biscuit_facts()


def test_client_biscuit_facts_returns_independent_copy(
    keys: tuple[bytes, bytes],
) -> None:
    """Mutating the returned dict must not poison the cached extraction."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test",
        api_key=_envelope(priv, extra_facts='user("alice");'),
        project_id="support-bot",
        public_key=pub,
    )
    client = HexgateClient(config)

    first = client.biscuit_facts()
    first["user"].append("bob")
    second = client.biscuit_facts()
    assert second["user"] == ["alice"]


# ---------------------------------------------------------------------------
# HexgateClient.get_bans — project-scoped ban feed (kill switch)
# ---------------------------------------------------------------------------


def test_get_bans_builds_token_implicit_url_and_returns_payload(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_bans() hits /v1/bans (project from the bearer), authorized, and
    returns the (payload, etag) tuple verbatim for a 200."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test", api_key=_envelope(priv), public_key=pub
    )
    client = HexgateClient(config)

    calls: list[tuple[str, bool, str | None]] = []
    feed = [{"ban_id": "b1", "ban_type": "agent", "target_agent_name": "bot"}]

    def fake_raw_get(
        self: HexgateClient,
        url: str,
        *,
        authorize: bool,
        if_none_match: str | None = None,
    ) -> tuple[Any, str | None]:
        calls.append((url, authorize, if_none_match))
        return feed, '"etag-1"'

    monkeypatch.setattr(HexgateClient, "_raw_get", fake_raw_get)

    payload, etag = client.get_bans()

    assert payload == feed
    assert etag == '"etag-1"'
    assert len(calls) == 1
    url, authorize, inm = calls[0]
    assert url.endswith("/v1/bans")
    assert authorize is True
    assert inm is None


def test_get_bans_sends_if_none_match_and_handles_304(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A conditional get_bans forwards If-None-Match and surfaces the 304 as
    (None, etag)."""
    priv, pub = keys
    config = HexgateConfig(
        base_url="http://test", api_key=_envelope(priv), public_key=pub
    )
    client = HexgateClient(config)

    seen: list[str | None] = []

    def fake_raw_get(
        self: HexgateClient,
        url: str,
        *,
        authorize: bool,
        if_none_match: str | None = None,
    ) -> tuple[Any, str | None]:
        seen.append(if_none_match)
        return None, '"etag-1"'  # 304 shape

    monkeypatch.setattr(HexgateClient, "_raw_get", fake_raw_get)

    payload, etag = client.get_bans(if_none_match='"etag-1"')

    assert payload is None
    assert etag == '"etag-1"'
    assert seen == ['"etag-1"']


def test_get_bans_verifies_key_before_http(
    keys: tuple[bytes, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tampered envelope fails the sig check; no ban feed request is sent."""
    priv, pub = keys
    tampered = _envelope(priv)[:-4] + "AAAA"
    config = HexgateConfig(base_url="http://test", api_key=tampered, public_key=pub)
    client = HexgateClient(config)

    monkeypatch.setattr(
        HexgateClient,
        "_raw_get",
        lambda *a, **kw: pytest.fail("HTTP fired despite signature failure"),
    )

    with pytest.raises(HexgateError, match="signature does not chain"):
        client.get_bans()
