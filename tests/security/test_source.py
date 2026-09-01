"""Tests for the policy source layer (M2 phase 8a).

``PolicySource`` is the seam that lets the agent runtime refresh policy
at every run without caring whether the bundle came from the platform or
from disk. These tests cover :class:`PlatformPolicySource` (HTTP +
``If-None-Match`` / 304) — local sources land in phase 8b.

Each test uses a tiny in-memory ``FakeClient`` rather than spinning the
real platform, so we control exactly what the platform "served" and on
which call.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
from types import SimpleNamespace

import pytest

from hexgate.security import (
    PolicyBundle,
    compile_to_rego,
    compile_to_wasm,
    generate_keypair,
    sign_bytes,
)
from hexgate.security.source import (
    PlatformPolicySource,
    PolicyContentError,
    SignaturePolicy,
)

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


# ---------------------------------------------------------------------------
# SignaturePolicy.warn_if_unverified — the single signal for a signed local
# bundle loaded without a pubkey, shared by the loader and binding paths.
# ---------------------------------------------------------------------------


def test_warn_if_unverified_warns_for_signed_bundle_without_pubkey(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Signed bundle + no pubkey configured → warn that it wasn't verified."""
    policy = SignaturePolicy(verify_with=None, require_signature=False)

    policy.warn_if_unverified(SimpleNamespace(is_signed=True))

    err = capsys.readouterr().err
    assert "signature NOT verified" in err
    assert "HEXGATE_BUNDLE_PUBKEY_PATH" in err


def test_warn_if_unverified_silent_when_pubkey_configured(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A pubkey is configured (verify_with set) → no warning."""
    policy = SignaturePolicy(verify_with=b"\x00" * 32, require_signature=False)

    policy.warn_if_unverified(SimpleNamespace(is_signed=True))

    assert capsys.readouterr().err == ""


def test_warn_if_unverified_silent_for_unsigned_bundle(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unsigned bundle → nothing to verify, nothing to warn about."""
    policy = SignaturePolicy(verify_with=None, require_signature=False)

    policy.warn_if_unverified(SimpleNamespace(is_signed=False))

    assert capsys.readouterr().err == ""


_POLICY_PAYLOAD = {
    "version": 1,
    "roles": {
        "billing": {
            "tools": {
                "refund_order": {"mode": "allow", "constraints": ["args.amount <= 500"]}
            }
        }
    },
}


def _bundle_response(private_raw: bytes, amount_cap: int = 500) -> dict:
    """Build a get_agent-shaped response carrying a real signed bundle."""
    payload = {
        "version": 1,
        "roles": {
            "billing": {
                "tools": {
                    "refund_order": {
                        "mode": "allow",
                        "constraints": [f"args.amount <= {amount_cap}"],
                    }
                }
            }
        },
    }
    rego = compile_to_rego(payload)
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
        "bundle_wasm_b64": base64.b64encode(wasm).decode("ascii"),
        "bundle_manifest": manifest_text,
        "bundle_signature_b64": base64.b64encode(signature).decode("ascii"),
    }


class _FakeClient:
    """Stand-in for HexgateClient that scripts a sequence of responses.

    ``serve(...)`` queues the next answer the client should return; each
    ``get_agent`` consumes one. The 304 path is triggered when the
    incoming ``If-None-Match`` matches the previously-served etag.
    """

    def __init__(self, public_raw: bytes) -> None:
        self._public_raw = public_raw
        self._queued: list[tuple[dict | None, str | None]] = []
        self.calls: list[str | None] = []

    def serve(self, payload: dict | None, etag: str | None) -> None:
        self._queued.append((payload, etag))

    def serve_304(self, etag: str) -> None:
        self._queued.append((None, etag))

    def get_agent(
        self, _name: str, *, if_none_match: str | None = None
    ) -> tuple[dict | None, str | None]:
        self.calls.append(if_none_match)
        return self._queued.pop(0)

    def public_key_bytes(self) -> bytes:
        return self._public_raw


# ---------------------------------------------------------------------------
# PlatformPolicySource
# ---------------------------------------------------------------------------


@needs_opa
def test_first_fetch_returns_verified_bundle() -> None:
    """A 200 response builds, verifies, caches, and returns the bundle."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(_bundle_response(priv), etag='"abc123"')
    src = PlatformPolicySource(fc, "default")

    bundle = src.fetch()
    assert isinstance(bundle, PolicyBundle)
    assert bundle.is_signed
    # First call has no etag to send.
    assert fc.calls == [None]


@needs_opa
def test_second_fetch_sends_etag_and_304_reuses_cache() -> None:
    """304 returns the SAME instance — no decode, no signature verify."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    payload = _bundle_response(priv)
    fc.serve(payload, etag='"abc123"')
    fc.serve_304('"abc123"')

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()

    assert first is second  # identity match — same Python object reused
    # Second call sent the etag we got from the first.
    assert fc.calls == [None, '"abc123"']


@needs_opa
def test_bundle_change_returns_new_instance() -> None:
    """A different wasm_hash → new bundle returned + new etag tracked."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(_bundle_response(priv, amount_cap=500), etag='"hash-a"')
    fc.serve(_bundle_response(priv, amount_cap=1000), etag='"hash-b"')

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()

    assert first is not second
    assert first.wasm_hash != second.wasm_hash
    assert fc.calls == [None, '"hash-a"']  # second call sent first's etag


def test_no_bundle_in_payload_falls_back_to_pydantic_engine() -> None:
    """When the platform served no compiled bundle (no opa on the control
    plane, common in demo containers), fetch() builds a PolicySet from
    the response's policy_yaml so per-turn refresh can still react to
    policy edits. Without this, the binding's None-check would short-
    circuit and the initial engine would stay frozen forever — see
    fix/policy-refresh-pydantic-fallback for the regression scenario.
    """
    from hexgate.security.policy_set import PolicySet

    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "agent_yaml": "name: x\n",
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n",
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    result = src.fetch()
    assert isinstance(result, PolicySet)


def test_no_bundle_unchanged_yaml_returns_same_engine_instance() -> None:
    """Identity preservation on the pydantic-fallback path: two fetches
    against the same policy_yaml must return the same PolicySet object,
    so PolicyBinding.refresh()'s `is` check skips the rebind.
    """
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    payload = {
        "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n",
    }
    fc.serve(payload, etag=None)
    fc.serve(payload, etag=None)

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()
    assert first is second


def test_no_bundle_changed_yaml_returns_new_engine() -> None:
    """The regression scenario: dashboard edits a policy, platform has
    no opa so the bundle stays null, but the new policy_yaml flows
    through. fetch() must detect the change and return a fresh PolicySet
    (different identity) so the binding swaps.
    """
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n",
        },
        etag=None,
    )
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n",
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()
    assert first is not None and second is not None
    assert first is not second


def test_no_bundle_then_bundle_clears_yaml_hash_state() -> None:
    """Transition test: a source that fell back to pydantic (no opa) must
    cleanly accept a later bundled response (opa came back online) and
    return the bundle, not stay stuck on the prior PolicySet.
    """
    if not _OPA_AVAILABLE:
        pytest.skip("opa not on PATH")
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
        },
        etag=None,
    )
    fc.serve(_bundle_response(priv, amount_cap=500), etag='"hash-a"')

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()
    assert isinstance(second, PolicyBundle)
    assert first is not second


@needs_opa
def test_wrong_pubkey_raises() -> None:
    """A bundle signed by one key, served with a stranger's pubkey on the
    client, fails verification at fetch — never silently downgraded."""
    priv, _ = generate_keypair()
    _, stranger = generate_keypair()
    fc = _FakeClient(stranger)
    fc.serve(_bundle_response(priv), etag=None)

    src = PlatformPolicySource(fc, "default")
    with pytest.raises(RuntimeError, match="failed verification"):
        src.fetch()


@needs_opa
def test_pre_seeded_source_skips_first_round_trip() -> None:
    """When constructed with initial_bundle + initial_etag, the first
    fetch sends If-None-Match and trivially hits 304."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    # Pre-build a bundle the same way load_hexgate_agent would have.
    from hexgate.security.source import decode_and_verify_platform_bundle

    initial = decode_and_verify_platform_bundle(_bundle_response(priv), pub)
    fc.serve_304(f'"{initial.wasm_hash}"')

    src = PlatformPolicySource(
        fc, "default", initial_bundle=initial, initial_etag=f'"{initial.wasm_hash}"'
    )
    result = src.fetch()

    assert result is initial
    assert fc.calls == [f'"{initial.wasm_hash}"']


def test_concurrent_fetches_serialize() -> None:
    """The source owns its cache, so it owns its lock: two threads fetching
    at once never overlap inside fetch() (cached bundle/etag can't interleave)."""
    import threading
    import time

    _, pub = generate_keypair()

    class _SlowOverlapClient(_FakeClient):
        def __init__(self, public_raw: bytes) -> None:
            super().__init__(public_raw)
            self._gauge = threading.Lock()
            self.active = 0
            self.max_active = 0

        def get_agent(self, name, *, if_none_match=None):
            with self._gauge:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            time.sleep(0.02)  # widen the window an overlap would need
            try:
                return super().get_agent(name, if_none_match=if_none_match)
            finally:
                with self._gauge:
                    self.active -= 1

    fc = _SlowOverlapClient(pub)
    # Bundle-less payloads keep this opa-free; fetch() returns None for both.
    fc.serve({"policy_yaml": "version: 1\n"}, etag='"a"')
    fc.serve({"policy_yaml": "version: 1\n"}, etag='"b"')
    src = PlatformPolicySource(fc, "default")

    threads = [threading.Thread(target=src.fetch) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert all(not t.is_alive() for t in threads)
    assert fc.max_active == 1  # serialized — never two fetches in flight


# ---------------------------------------------------------------------------
# Regression tests for the PR #50 review findings:
#   #1 silent strict-signature downgrade on refresh
#   #2 malformed/invalid edited policy silently swallowed
#   #3 non-null ETag on no-bundle response masks policy edits
#   #4 (no behavior change — covered as a doc comment in fetch())
# ---------------------------------------------------------------------------


def test_strict_signature_refuses_no_bundle_on_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1 — Strict mode + no bundle on refresh must raise, not silently
    downgrade to the pydantic engine. The attack: agent boots on a signed
    bundle, opa later goes down mid-session, control plane starts serving
    no-bundle payloads. Without this guard, fetch() would swap in an
    unverified PolicySet built from raw yaml — exactly the downgrade
    decode_and_verify_platform_bundle was written to refuse.
    """
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "1")
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n"
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    with pytest.raises(RuntimeError, match="REQUIRE_SIGNATURE"):
        src.fetch()


def test_strict_signature_off_still_falls_back_to_pydantic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#1 sibling — make sure the strict-mode guard didn't break the
    default permissive path. Without REQUIRE_SIGNATURE set, the no-bundle
    branch must still build a PolicySet (this is what makes the Modal
    demo work)."""
    from hexgate.security.policy_set import PolicySet

    monkeypatch.delenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", raising=False)
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    assert isinstance(src.fetch(), PolicySet)


def test_malformed_yaml_raises_policy_content_error() -> None:
    """#2 — Unparseable yaml (broken indentation, stray tab, etc.) must
    surface as a typed PolicyContentError, not get silently swallowed by
    PolicyBinding.refresh's warning logger. Dashboards would otherwise
    show the edit as saved while the runtime kept the old engine."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    # `:\t` inside the value triggers yaml's "found tab character that
    # cannot start any token" error reliably.
    fc.serve({"policy_yaml": "roles:\n\tdefault: deny\n"}, etag=None)

    src = PlatformPolicySource(fc, "default")
    with pytest.raises(PolicyContentError, match="unparseable"):
        src.fetch()


def test_structurally_invalid_yaml_raises_policy_content_error() -> None:
    """#2 sibling — yaml that parses but fails policy-set validation
    (unknown mode, missing required key, etc.) is the more common case
    of a "dashboard-accepted, runtime-rejected" edit. Same loud surface
    as a parse error so the operator sees the runtime drift from the UI.
    """
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(
        {
            "policy_yaml": (
                "version: 1\nroles:\n  default:\n    default_policy:\n"
                "      mode: TOTALLY_NOT_A_MODE\n"
            )
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    with pytest.raises(PolicyContentError, match="invalid policy_yaml"):
        src.fetch()


def test_no_bundle_response_with_etag_does_not_send_if_none_match() -> None:
    """#3 — Even if the server (or a future server build) attaches an
    ETag to a no-bundle response, the SDK must not send it back as
    If-None-Match. The ETag's semantics on this path aren't defined; a
    304 reply would silently swallow a policy edit. Defensively clear
    the cached ETag so yaml-hash comparison stays the canonical change
    detector for this branch.
    """
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    # Server (buggily) attaches an ETag to a no-bundle response.
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
        },
        etag='"server-attached-etag"',
    )
    # Edited yaml comes through on the second turn. If we'd cached the
    # server's ETag, the test client would consume this; we want to be
    # sure the SDK ignored it on call #2 and didn't send If-None-Match.
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n"
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    first = src.fetch()
    second = src.fetch()

    # Both calls must have sent no If-None-Match — that's the only way
    # to guarantee we never miss an edit on this branch.
    assert fc.calls == [None, None]
    # And the edited policy must take effect (different engine instance).
    assert first is not second


def test_load_time_no_bundle_does_not_pass_etag_to_source() -> None:
    """#3 sibling at load time — platform_policy_from_payload must not
    seed the source with the server's ETag on the no-bundle branch. Same
    rationale as the runtime fix: a non-null ETag here would cause the
    first refresh to send If-None-Match, get a 304, and never reach the
    yaml-hash comparison.
    """
    from hexgate.security.binding import platform_policy_from_payload

    _, pub = generate_keypair()

    class _StubClient:
        def public_key_bytes(self) -> bytes:
            return pub

        def get_agent(self, _name, *, if_none_match=None):
            return (
                {
                    "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n"
                },
                None,
            )

    client = _StubClient()
    payload, _ = client.get_agent("default")
    # Simulate the server sending a non-null ETag on the no-bundle response.
    _, source = platform_policy_from_payload(
        client,  # type: ignore[arg-type]
        "default",
        payload,
        etag='"server-sent-no-bundle-etag"',
    )

    # The source's cached_etag must be None so the next refresh doesn't
    # send If-None-Match and risk a 304 swallowing an edit.
    assert source._cached_etag is None  # noqa: SLF001 — invariant under test
    # The yaml-hash *is* seeded — that's what makes the first refresh
    # cheap when nothing actually changed.
    assert source._cached_yaml_hash is not None  # noqa: SLF001


def test_binding_logs_content_error_at_error_level(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """#2 — PolicyBinding.refresh must distinguish PolicyContentError
    (correctness issue, log at ERROR) from transient RuntimeError (log
    at WARNING). Operators monitoring logs for "policy mismatch with
    dashboard" need to see the loud signal.
    """
    import logging

    from hexgate.security.binding import PolicyBinding

    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    # First fetch seeds a valid engine (good policy).
    fc.serve(
        {
            "policy_yaml": "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
        },
        etag=None,
    )
    # Second fetch: structurally-invalid yaml. Binding.refresh should
    # log at ERROR and keep the previously-loaded engine.
    fc.serve(
        {
            "policy_yaml": (
                "version: 1\nroles:\n  default:\n    default_policy:\n"
                "      mode: TOTALLY_NOT_A_MODE\n"
            )
        },
        etag=None,
    )

    src = PlatformPolicySource(fc, "default")
    initial_engine = src.fetch()
    enforcer = SimpleNamespace(policy=initial_engine, agent_name="default")
    binding = PolicyBinding(enforcer, source=src)  # type: ignore[arg-type]

    with caplog.at_level(logging.ERROR, logger="hexgate.security.binding"):
        binding.refresh()

    assert any(
        rec.levelno == logging.ERROR and "rejected platform content" in rec.message
        for rec in caplog.records
    ), f"expected ERROR-level 'rejected platform content' log, saw {caplog.records}"
    # And the binding kept the original engine (fail-soft).
    assert enforcer.policy is initial_engine
