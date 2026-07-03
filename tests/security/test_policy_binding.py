"""Tests for :class:`hexgate.security.binding.PolicyBinding` (spec phase 1).

The binding is the one resolve/refresh primitive every agent surface
shares (docs/policy-binding-spec.md). These tests cover:

  * resolve precedence — local override → platform → raise
  * platform resolution — verified bundle, pydantic fallback,
    REQUIRE_SIGNATURE, bad signature, 404 propagation
  * the explicit static path — plain constructor, no source, no refresh
  * refresh — 304 identity short-circuit, swap on change, fail-soft on
    fetch errors

Pattern mirrors tests/security/test_source.py: a scripted ``_FakeClient``
controls exactly what the platform "served" on each call.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil

import pytest

from hexgate.cloud.client import HexgateError
from hexgate.security import (
    AgentPolicy,
    BaseToolPolicy,
    PolicyBinding,
    PolicyBindingError,
    PolicyBundle,
    PolicySet,
    ResolvedPolicy,
    compile_to_rego,
    resolve_policy,
    compile_to_wasm,
    generate_keypair,
    sign_bytes,
)
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME
from hexgate.security.source import PlatformPolicySource

_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


_POLICY_YAML = """\
version: 1
roles:
  billing:
    tools:
      refund_order:
        mode: allow
        constraints: ["args.amount <= 500"]
"""


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
        "policy_yaml": _POLICY_YAML,
        "bundle_wasm_b64": base64.b64encode(wasm).decode("ascii"),
        "bundle_manifest": manifest_text,
        "bundle_signature_b64": base64.b64encode(signature).decode("ascii"),
    }


class _FakeClient:
    """Scripted HexgateClient stand-in.

    ``serve(...)`` queues the next get_agent answer; a queued exception is
    raised instead.
    """

    def __init__(self, public_raw: bytes) -> None:
        self._public_raw = public_raw
        self._queued: list[tuple[dict | None, str | None] | Exception] = []
        self.calls: list[str | None] = []

    def serve(self, payload: dict | None, etag: str | None = None) -> None:
        self._queued.append((payload, etag))

    def serve_304(self, etag: str) -> None:
        self._queued.append((None, etag))

    def serve_error(self, exc: Exception) -> None:
        self._queued.append(exc)

    def get_agent(
        self, _name: str, *, if_none_match: str | None = None
    ) -> tuple[dict | None, str | None]:
        self.calls.append(if_none_match)
        item = self._queued.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def public_key_bytes(self) -> bytes:
        return self._public_raw


def _static_engine(tool_names: list[str]) -> PolicySet:
    """A tiny explicit engine for the static-constructor tests."""
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy(
                tools={name: BaseToolPolicy(mode="allow") for name in tool_names}
            )
        }
    )


def _resolved_binding(agent_name: str, **kwargs) -> PolicyBinding:
    """resolve_policy + build the enforcer/binding — what each surface does."""

    resolved = resolve_policy(agent_name, **kwargs)
    return PolicyBinding(
        PolicyEnforcer(resolved.engine, agent_name=agent_name), resolved.source
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolution must be driven by each test, not the developer's shell."""
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    monkeypatch.delenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", raising=False)
    monkeypatch.delenv("HEXGATE_BUNDLE_PUBKEY_PATH", raising=False)
    monkeypatch.delenv("HEXGATE_BUNDLE_SIGN_KEY_PATH", raising=False)


# ---------------------------------------------------------------------------
# resolve() — precedence
# ---------------------------------------------------------------------------


def test_static_constructor_is_the_explicit_ungoverned_path() -> None:
    """PolicyBinding(PolicyEnforcer(engine)) — no source, refresh no-ops."""
    engine = _static_engine(["read_file"])
    binding = PolicyBinding(PolicyEnforcer(engine, agent_name="support-bot"))

    assert binding.enforcer.policy is engine
    assert binding.source is None
    binding.refresh()  # no source → no-op, not an error
    assert binding.enforcer.policy is engine


def test_local_override_beats_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    """HEXGATE_LOCAL_POLICY wins outright — the platform is never contacted."""
    from hexgate.security import binding as binding_mod

    sentinel_policy = _static_engine(["x"])  # any PolicyEngine works

    class _StubSource:
        def fetch(self) -> object:
            return sentinel_policy

    stub_source = _StubSource()
    monkeypatch.setattr(
        binding_mod,
        "_local_policy_override",
        lambda: (sentinel_policy, stub_source),
    )

    _, pub = generate_keypair()
    fc = _FakeClient(pub)  # nothing queued — any get_agent call would crash
    binding = _resolved_binding("support-bot", client=fc)

    assert binding.enforcer.policy is sentinel_policy
    assert binding.source is stub_source
    assert fc.calls == []


# ---------------------------------------------------------------------------
# resolve() — platform
# ---------------------------------------------------------------------------


@needs_opa
def test_platform_bundle_resolved_and_source_seeded() -> None:
    """A 200 with a signed bundle → wasm engine + ETag-seeded source."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(_bundle_response(priv), etag='"hash-a"')

    binding = _resolved_binding("support-bot", client=fc)

    assert isinstance(binding.enforcer.policy, PolicyBundle)
    assert binding.enforcer.policy.is_signed
    assert isinstance(binding.source, PlatformPolicySource)
    assert fc.calls == [None]

    # The source was pre-seeded: the next refresh sends If-None-Match and
    # a 304 keeps the exact same policy object (no swap).
    fc.serve_304('"hash-a"')
    before = binding.enforcer.policy
    binding.refresh()
    assert binding.enforcer.policy is before
    assert fc.calls == [None, '"hash-a"']


def test_platform_bundleless_payload_falls_back_to_pydantic() -> None:
    """No compiled bundle served → pydantic engine on policy_yaml."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve({"policy_yaml": _POLICY_YAML}, etag=None)

    binding = _resolved_binding("support-bot", client=fc)

    assert isinstance(binding.enforcer.policy, PolicySet)
    assert "billing" in binding.enforcer.policy
    # Refresh seam still attached: a later platform-side compile can
    # upgrade this agent to the wasm engine.
    assert isinstance(binding.source, PlatformPolicySource)


def test_bundleless_with_require_signature_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_BUNDLE_REQUIRE_SIGNATURE", "1")
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve({"policy_yaml": _POLICY_YAML}, etag=None)

    with pytest.raises(PolicyBindingError, match="no signed bundle"):
        _resolved_binding("support-bot", client=fc)


@needs_opa
def test_bad_signature_raises_never_downgrades() -> None:
    """A bundle signed by a stranger's key is fatal at resolve."""
    priv, _ = generate_keypair()
    _, stranger_pub = generate_keypair()
    fc = _FakeClient(stranger_pub)
    fc.serve(_bundle_response(priv), etag=None)

    with pytest.raises(RuntimeError, match="failed verification"):
        _resolved_binding("support-bot", client=fc)


def test_404_propagates_with_status() -> None:
    """Registration is not the binding's job — a 404 surfaces as-is so the
    caller can register with the platform (``hexgate register``) and resolve
    again."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve_error(HexgateError("Hexgate API error 404 calling …", status=404))

    with pytest.raises(HexgateError) as excinfo:
        _resolved_binding("ghost-agent", client=fc)
    assert excinfo.value.status == 404


def test_composed_binding_from_preseeded_source() -> None:
    """The loader path: callers with payload + etag in hand compose the
    binding directly — no extra fetch, first refresh is a 304."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    policy = _static_engine(["refund_order"])
    source = PlatformPolicySource(
        fc, "support-bot", initial_bundle=None, initial_etag='"etag-x"'
    )

    binding = PolicyBinding(PolicyEnforcer(policy, agent_name="support-bot"), source)
    assert fc.calls == []  # composition cost: zero round trips

    fc.serve_304('"etag-x"')
    binding.refresh()
    assert binding.enforcer.policy is policy  # 304 + None bundle → no swap
    assert fc.calls == ['"etag-x"']


# ---------------------------------------------------------------------------
# refresh()
# ---------------------------------------------------------------------------


@needs_opa
def test_refresh_swaps_policy_on_change() -> None:
    """A 200 with a different bundle rebinds enforcer.policy in place."""
    priv, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve(_bundle_response(priv, amount_cap=500), etag='"hash-a"')
    fc.serve(_bundle_response(priv, amount_cap=1000), etag='"hash-b"')

    binding = _resolved_binding("support-bot", client=fc)
    first = binding.enforcer.policy
    binding.refresh()
    second = binding.enforcer.policy

    assert first is not second
    assert first.wasm_hash != second.wasm_hash
    # The decision actually changed: 700 was over the old cap, under the new.
    old = first.evaluate(role="billing", tool="refund_order", args={"amount": 700})
    new = second.evaluate(role="billing", tool="refund_order", args={"amount": 700})
    assert not old.allowed
    assert new.allowed


def test_refresh_swaps_policy_on_pydantic_fallback_path() -> None:
    """Regression for the demo-notebook bug: when the platform has no
    opa (Modal container, fresh deploy without the opa binary), bundles
    never compile and every GET /v1/agents/:name returns 200 with the
    raw policy_yaml and null bundle fields. Before the fix,
    PlatformPolicySource.fetch() returned None on this path, the
    binding's None-check short-circuited, and edits in /policies were
    silently ignored at runtime. After the fix, fetch() builds a fresh
    PolicySet whenever policy_yaml changes, the binding swaps, and the
    next tool-call decision reflects the edit.

    The opa-on path is already covered by
    `test_refresh_swaps_policy_on_change` above.
    """
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    # First load + first refresh both see the deny policy.
    deny_payload = {
        "agent_yaml": "name: support-bot\n",
        "policy_yaml": (
            "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
        ),
        "system_md": "",
    }
    # Then a /policies edit flips the tool to allow.
    allow_payload = {
        "agent_yaml": "name: support-bot\n",
        "policy_yaml": (
            "version: 1\nroles:\n  default:\n    default_policy:\n      mode: allow\n"
        ),
        "system_md": "",
    }
    fc.serve(deny_payload, etag=None)
    fc.serve(allow_payload, etag=None)

    binding = _resolved_binding("support-bot", client=fc)
    first = binding.enforcer.policy
    # Initial engine should be a PolicySet (pydantic fallback path).
    assert isinstance(first, PolicySet)
    pre = first.evaluate(role="default", tool="anything", args={})
    assert not pre.allowed  # deny

    binding.refresh()
    second = binding.enforcer.policy
    assert second is not first, (
        "refresh must swap the pydantic engine when policy_yaml changes; "
        "the binding's None-check used to swallow this case"
    )
    post = second.evaluate(role="default", tool="anything", args={})
    assert post.allowed  # the edit took effect


def test_refresh_failure_keeps_previous_policy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail-soft: a fetch error logs a warning, the old policy survives."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve({"policy_yaml": _POLICY_YAML}, etag='"hash-a"')
    fc.serve_error(HexgateError("Hexgate API unreachable at …"))

    binding = _resolved_binding("support-bot", client=fc)
    before = binding.enforcer.policy
    with caplog.at_level("WARNING", logger="hexgate.security.binding"):
        binding.refresh()  # must not raise

    assert binding.enforcer.policy is before
    assert any("keeping" in r.getMessage() for r in caplog.records)


@needs_opa
def test_refresh_tampered_bundle_keeps_previous_policy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A bundle failing verification at refresh cannot install itself."""
    priv, _ = generate_keypair()
    _, stranger_pub = generate_keypair()
    fc = _FakeClient(stranger_pub)
    # Resolve via the pydantic path (no bundle), then serve a bad bundle.
    fc.serve({"policy_yaml": _POLICY_YAML}, etag=None)
    fc.serve(_bundle_response(priv), etag='"evil"')

    binding = _resolved_binding("support-bot", client=fc)
    before = binding.enforcer.policy
    with caplog.at_level("WARNING", logger="hexgate.security.binding"):
        binding.refresh()  # verification fails inside source.fetch()

    assert binding.enforcer.policy is before


# ---------------------------------------------------------------------------
# resolve_policy — fail-loud resolution (no auto-register; a 404 surfaces so
# the caller registers via `hexgate register` and resolves again)
# ---------------------------------------------------------------------------


def test_resolve_policy_returns_engine_and_source_no_enforcer() -> None:
    """resolve_policy yields a ResolvedPolicy(engine, source) — no enforcer."""

    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve({"policy_yaml": _POLICY_YAML}, etag='"hash-a"')

    resolved = resolve_policy("support-bot", client=fc)

    assert isinstance(resolved, ResolvedPolicy)
    assert isinstance(resolved.engine, PolicySet)
    assert isinstance(resolved.source, PlatformPolicySource)


def test_resolve_policy_requires_agent_name() -> None:

    with pytest.raises(PolicyBindingError, match="agent name"):
        resolve_policy("")


def test_resolve_policy_no_credentials_raises() -> None:

    with pytest.raises(PolicyBindingError, match="no policy available"):
        resolve_policy("support-bot")


def test_resolve_policy_404_propagates_fail_loud() -> None:
    """An unregistered agent surfaces the 404 — resolve never auto-creates it."""
    _, pub = generate_keypair()
    fc = _FakeClient(pub)
    fc.serve_error(HexgateError("404", status=404))

    with pytest.raises(HexgateError) as excinfo:
        resolve_policy("new-agent", client=fc)

    assert excinfo.value.status == 404
    assert fc.calls == [None]  # one fetch, no register-and-retry
