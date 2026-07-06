"""Tests for the SDK pulling + verifying platform-signed bundles (M2 phase 7b).

The platform (phase 7a) serves a signed WASM bundle in the agent fetch
response. These tests cover the SDK's consumer side:

  * ``_platform_bundle`` rebuilds + verifies the bundle against the
    platform's published key (the same key trusted for biscuits).
  * ``load_hexgate_agent`` picks the bundle (WASM) over policy_yaml
    (pydantic) when one is served, refuses a tampered bundle, and honours
    HEXGATE_BUNDLE_REQUIRE_SIGNATURE.

Bundle compilation needs ``opa``; those tests skip without it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from typing import Any

import pytest

from hexgate.agents import loader
from hexgate.security import (
    PolicyBundle,
    compile_to_rego,
    compile_to_wasm,
    generate_keypair,
    sign_bytes,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


_POLICY_PAYLOAD = {
    "version": 1,
    "roles": {
        "default": {"tools": {"web_search": {"mode": "allow"}}},
        "billing": {
            "tools": {
                "refund_order": {"mode": "allow", "constraints": ["args.amount <= 500"]}
            }
        },
    },
}

_POLICY_YAML = """\
version: 1
roles:
  default:
    tools:
      web_search: { mode: allow }
  billing:
    tools:
      refund_order:
        mode: allow
        constraints:
          - args.amount <= 500
"""

_AGENT_YAML = "name: default\nmodel: openai:gpt-5.4\nsystem_prompt: system.md\ntools: []\npolicy: policy.yaml\n"


def _signed_payload(private_raw: bytes) -> dict:
    """Build a get_agent-shaped response carrying a real signed bundle."""
    rego = compile_to_rego(_POLICY_PAYLOAD)
    wasm = compile_to_wasm(rego).wasm
    manifest = {
        "version": 1,
        "source": "policy.yaml",
        "source_hash": "0" * 64,
        "rego_hash": hashlib.sha256(rego.encode("utf-8")).hexdigest(),
        "wasm_hash": hashlib.sha256(wasm).hexdigest(),
    }
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    signature = sign_bytes(manifest_text.encode("utf-8"), private_raw)
    return {
        "agent_yaml": _AGENT_YAML,
        "policy_yaml": _POLICY_YAML,
        "system_md": "",
        "bundle_wasm_b64": base64.b64encode(wasm).decode("ascii"),
        "bundle_manifest": manifest_text,
        "bundle_signature_b64": base64.b64encode(signature).decode("ascii"),
    }


class _FakeClient:
    """Minimal stand-in for HexgateClient — just what the loader touches.

    Mirrors the Phase 8 ``get_agent(name, *, if_none_match=None) -> (payload, etag)``
    signature, returning the payload unconditionally (no ETag tracking) —
    callers that ignore the etag still work.
    """

    def __init__(self, payload: dict, public_raw: bytes) -> None:
        self._payload = payload
        self._public_raw = public_raw

    def get_agent(
        self, _name: str, *, if_none_match: str | None = None
    ) -> tuple[dict, str | None]:
        return self._payload, None

    def public_key_bytes(self) -> bytes:
        return self._public_raw


# ---------------------------------------------------------------------------
# _platform_bundle
# ---------------------------------------------------------------------------


@needs_opa
def test_platform_bundle_verifies_and_returns(monkeypatch) -> None:
    priv, pub = generate_keypair()
    client = _FakeClient(_signed_payload(priv), pub)
    bundle = loader._platform_bundle(client.get_agent("default")[0], client)
    assert isinstance(bundle, PolicyBundle)
    assert bundle.is_signed
    d = bundle.policy().decide(
        role="billing", tool="refund_order", args={"amount": 200}
    )
    assert d.allow is True


def test_platform_bundle_none_when_no_bundle_served() -> None:
    client = _FakeClient(
        {"agent_yaml": _AGENT_YAML, "policy_yaml": _POLICY_YAML, "system_md": ""},
        generate_keypair()[1],
    )
    assert loader._platform_bundle(client.get_agent("default")[0], client) is None


@needs_opa
def test_platform_bundle_rejects_wrong_key() -> None:
    priv, _ = generate_keypair()
    _, stranger_pub = generate_keypair()
    client = _FakeClient(_signed_payload(priv), stranger_pub)
    with pytest.raises(RuntimeError, match="failed verification"):
        loader._platform_bundle(client.get_agent("default")[0], client)


@needs_opa
def test_platform_bundle_rejects_tampered_wasm() -> None:
    priv, pub = generate_keypair()
    payload = _signed_payload(priv)
    # Flip a byte in the served wasm — signature still matches the manifest,
    # but the wasm no longer matches the manifest's wasm_hash.
    raw = bytearray(base64.b64decode(payload["bundle_wasm_b64"]))
    raw[-1] ^= 1
    payload["bundle_wasm_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    client = _FakeClient(payload, pub)
    with pytest.raises(RuntimeError, match="failed verification"):
        loader._platform_bundle(client.get_agent("default")[0], client)


# ---------------------------------------------------------------------------
# load_hexgate_agent integration (mocked client + agent construction)
# ---------------------------------------------------------------------------


@pytest.fixture
def _patched_loader(monkeypatch):
    """Patch out cloud config, agent construction, and capture enforce_policy.

    Returns a setter that installs a _FakeClient for a given payload+key, so
    each test controls what the platform 'served'.
    """
    import types

    captured: dict[str, Any] = {}

    class _FakeConfig:
        project_id = "support-bot"

        @classmethod
        def from_env(cls, **_kw):
            return cls()

    def fake_create_agent(**_kw):
        # A namespace (not a str) so the loader can set .hexgate_client on it.
        return types.SimpleNamespace(name="agent"), "handler-instance"

    def fake_enforce_policy(
        _agent, policy, *, approval_handler=None, source=None, decision_observer=None
    ):
        captured["policy"] = policy
        captured["approval_handler"] = approval_handler
        captured["source"] = source
        captured["decision_observer"] = decision_observer
        return _agent

    monkeypatch.setattr(loader, "HexgateConfig", _FakeConfig)
    monkeypatch.setattr(loader, "create_agent", fake_create_agent)
    monkeypatch.setattr(loader, "enforce_policy", fake_enforce_policy)
    monkeypatch.setattr(loader, "resolve_tools", lambda *a, **k: [])
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    monkeypatch.delenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", raising=False)

    def install(payload: dict, public_raw: bytes):
        client = _FakeClient(payload, public_raw)
        monkeypatch.setattr(loader, "HexgateClient", lambda _config: client)
        return captured

    return install


@needs_opa
def test_load_hexgate_agent_uses_signed_bundle(_patched_loader) -> None:
    """A served + verified bundle becomes the enforcement policy (WASM path)."""
    priv, pub = generate_keypair()
    captured = _patched_loader(_signed_payload(priv), pub)
    loader.load_hexgate_agent("default")
    assert isinstance(captured["policy"], PolicyBundle)


def test_load_hexgate_agent_falls_back_to_pydantic_without_bundle(
    _patched_loader,
) -> None:
    """No bundle served → enforce with the pydantic PolicySet, not a bundle."""
    from hexgate.security.policy_set import PolicySet

    payload = {"agent_yaml": _AGENT_YAML, "policy_yaml": _POLICY_YAML, "system_md": ""}
    captured = _patched_loader(payload, generate_keypair()[1])
    loader.load_hexgate_agent("default")
    assert isinstance(captured["policy"], PolicySet)
    assert not isinstance(captured["policy"], PolicyBundle)


@needs_opa
def test_load_hexgate_agent_refuses_tampered_bundle(_patched_loader) -> None:
    priv, pub = generate_keypair()
    payload = _signed_payload(priv)
    raw = bytearray(base64.b64decode(payload["bundle_wasm_b64"]))
    raw[-1] ^= 1
    payload["bundle_wasm_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    _patched_loader(payload, pub)
    with pytest.raises(RuntimeError, match="failed verification"):
        loader.load_hexgate_agent("default")


def test_load_hexgate_agent_require_signature_refuses_unsigned(
    _patched_loader, monkeypatch
) -> None:
    """REQUIRE_SIGNATURE + no served bundle → refuse, don't drop to pydantic."""
    payload = {"agent_yaml": _AGENT_YAML, "policy_yaml": _POLICY_YAML, "system_md": ""}
    _patched_loader(payload, generate_keypair()[1])
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "true")
    with pytest.raises(RuntimeError, match="served\\s+no signed bundle"):
        loader.load_hexgate_agent("default")


# ---------------------------------------------------------------------------
# Phase 8a — refresh_policy swaps the enforcer's policy when the source
# returns a new bundle.
# ---------------------------------------------------------------------------


def test_refresh_policy_swaps_enforcer_policy_on_change() -> None:
    """A source returning a new bundle → enforcer.policy is updated in
    place. The shared enforcer means every guarded tool picks it up at the
    next call, without re-wrapping the tools."""
    from types import SimpleNamespace

    from hexgate.agents.factory import HexgateAgent
    from hexgate.security.binding import PolicyBinding

    # Bare HexgateAgent — refresh_policy only touches _binding, so skip the
    # heavy graph construction.
    agent = HexgateAgent.__new__(HexgateAgent)
    enforcer = SimpleNamespace(policy="initial")

    new_bundle = object()  # any new identity will do

    class _Source:
        def fetch(self):
            return new_bundle

    agent._binding = PolicyBinding(enforcer, _Source())  # type: ignore[arg-type]
    agent.refresh_policy()
    assert enforcer.policy is new_bundle


def test_refresh_policy_skips_when_source_returns_same_instance() -> None:
    """Source returning the SAME object (e.g. PlatformPolicySource on 304)
    → no-op. Verified by checking the policy attribute isn't even rewritten."""
    from types import SimpleNamespace

    from hexgate.agents.factory import HexgateAgent
    from hexgate.security.binding import PolicyBinding

    agent = HexgateAgent.__new__(HexgateAgent)
    cached = object()
    enforcer = SimpleNamespace(policy=cached)

    class _Source:
        def fetch(self):
            return cached  # same object every time

    agent._binding = PolicyBinding(enforcer, _Source())  # type: ignore[arg-type]
    agent.refresh_policy()
    assert enforcer.policy is cached  # no swap happened


def test_refresh_policy_noop_without_source_or_enforcer() -> None:
    """Agents constructed programmatically without enforcement: refresh
    is a quiet no-op, not a crash.
    """
    from hexgate.agents.factory import HexgateAgent

    agent = HexgateAgent.__new__(HexgateAgent)
    agent._binding = None
    agent.refresh_policy()  # must not raise


def test_refresh_policy_is_fail_soft_on_source_errors() -> None:
    """Phase 2: the swap logic (and its fail-soft contract) lives in
    PolicyBinding — a raising source logs and keeps the previous policy
    instead of crashing the run."""
    from types import SimpleNamespace

    from hexgate.agents.factory import HexgateAgent
    from hexgate.security.binding import PolicyBinding

    agent = HexgateAgent.__new__(HexgateAgent)
    enforcer = SimpleNamespace(policy="initial", agent_name="support-bot")

    class _Source:
        def fetch(self):
            raise RuntimeError("platform down")

    agent._binding = PolicyBinding(enforcer, _Source())  # type: ignore[arg-type]
    agent.refresh_policy()  # must not raise
    assert enforcer.policy == "initial"
