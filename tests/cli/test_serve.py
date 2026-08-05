"""Tests for the serve-mode → HexgateContext scope handoff.

After Phase 3.5, serve.py owns only the WebSocket plumbing: it parses
``user_attenuation`` metadata into a :class:`hexgate.runtime.HexgateContext`, wraps
the agent invocation in ``async with HexgateContext(...)``, and lets the runtime
attenuate lazily. These tests cover the parsing helper and the
end-to-end handler shape (with stream_agent monkeypatched out).
"""

from __future__ import annotations

from typing import Any

import pytest
from rich.console import Console

from hexgate.cli import serve
from hexgate.cli.serve import ServeContext, _context_from_payload
from hexgate.cli.state import ChatState
from hexgate.runtime import HexgateContext, get_current_context


# ---------------------------------------------------------------------------
# _context_from_payload — happy / malformed
# ---------------------------------------------------------------------------


def test_context_from_payload_returns_user_with_all_fields() -> None:
    """A complete payload yields a fully-populated HexgateContext."""
    user = _context_from_payload(
        {
            "user": "alice",
            "role": "billing",
            "session_id": "sess_abc",
            "ttl_seconds": 300,
        }
    )
    assert user is not None
    assert user.user_id == "alice"
    assert user.primary_role == "billing"
    assert user.user_roles == ["billing"]
    assert user.session_id == "sess_abc"
    assert user.ttl_seconds == 300


def test_context_from_payload_maps_roles_list() -> None:
    """A ``roles`` list is carried verbatim; ``primary_role`` is the first."""
    user = _context_from_payload({"user": "alice", "roles": ["billing", "support"]})
    assert user is not None
    assert user.user_roles == ["billing", "support"]
    assert user.primary_role == "billing"


def test_context_from_payload_maps_legacy_single_role() -> None:
    """The legacy singular ``role`` wire key maps to a one-element list."""
    user = _context_from_payload({"user": "alice", "role": "billing"})
    assert user is not None
    assert user.user_roles == ["billing"]


def test_context_from_payload_no_role_yields_empty_roles() -> None:
    """Neither ``roles`` nor ``role`` present → empty list (falls back to default)."""
    user = _context_from_payload({"user": "bob"})
    assert user is not None
    assert user.user_roles == []


def test_context_from_payload_returns_user_with_just_user_id() -> None:
    """Minimal ``{"user": ...}`` is enough."""
    user = _context_from_payload({"user": "bob"})
    assert user is not None
    assert user.user_id == "bob"
    assert user.primary_role is None


def test_context_from_payload_returns_none_for_empty_dict() -> None:
    """An empty dict means no user requested → no scope."""
    assert _context_from_payload({}) is None


def test_context_from_payload_returns_none_for_missing_user_key() -> None:
    """Without a ``user`` key the payload doesn't drive a scope."""
    assert _context_from_payload({"scope": ["read"]}) is None


def test_context_from_payload_returns_none_for_non_dict() -> None:
    """Lists / strings / Nones all yield no HexgateContext."""
    assert _context_from_payload(None) is None
    assert _context_from_payload("alice") is None
    assert _context_from_payload(["alice"]) is None


def test_context_from_payload_returns_none_on_invalid_shape() -> None:
    """A payload with the wrong type for ttl trips Pydantic validation."""
    assert (
        _context_from_payload({"user": "alice", "ttl_seconds": "not-a-number"}) is None
    )


# ---------------------------------------------------------------------------
# _handle_message wraps the agent invocation in the HexgateContext scope
# ---------------------------------------------------------------------------


class _FakeWebSocket:
    """Minimal ws stub recording every outbound frame."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, frame: str) -> None:
        self.sent.append(frame)


class _FakeRuntime:
    """Runtime stand-in — what `_handle_message` reads off ``context.runtime``."""

    def __init__(self) -> None:
        self.agent_name = "fake-agent"
        self.agent = object()
        self.handler = object()


@pytest.mark.asyncio
async def test_handle_message_chat_with_attenuation_enters_user_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chat payload with ``user_attenuation`` enters a HexgateContext scope around stream_agent."""
    captured: dict[str, Any] = {"user_during_stream": None}

    async def fake_stream_agent(
        agent: object, handler: object, input: object, **kw: Any
    ):
        captured["user_during_stream"] = get_current_context()
        if False:
            yield None  # pragma: no cover

    monkeypatch.setattr(serve, "stream_agent", fake_stream_agent)

    # ``api_key`` is required on ServeContext post-Phase-6 (used to
    # build the WS bearer subprotocol). _handle_message doesn't touch
    # it, so a placeholder is fine for these unit-level tests.
    context = ServeContext(runtime=_FakeRuntime(), state=ChatState(), api_key="")
    ws = _FakeWebSocket()

    await serve._handle_message(
        context,
        ws,
        {
            "type": "chat",
            "message": "refund 30",
            "user_attenuation": {
                "user": "alice",
                "role": "billing",
            },
        },
    )

    captured_user: HexgateContext | None = captured["user_during_stream"]
    assert captured_user is not None
    assert captured_user.user_id == "alice"
    assert captured_user.primary_role == "billing"

    # After the handler returns the scope must be cleanly popped.
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_handle_message_chat_without_attenuation_runs_with_no_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backward-compat: messages without ``user_attenuation`` see no HexgateContext scope."""
    captured: dict[str, Any] = {"user_during_stream": "sentinel"}

    async def fake_stream_agent(
        agent: object, handler: object, input: object, **kw: Any
    ):
        captured["user_during_stream"] = get_current_context()
        if False:
            yield None  # pragma: no cover

    monkeypatch.setattr(serve, "stream_agent", fake_stream_agent)

    # ``api_key`` is required on ServeContext post-Phase-6 (used to
    # build the WS bearer subprotocol). _handle_message doesn't touch
    # it, so a placeholder is fine for these unit-level tests.
    context = ServeContext(runtime=_FakeRuntime(), state=ChatState(), api_key="")
    ws = _FakeWebSocket()

    await serve._handle_message(context, ws, {"type": "chat", "message": "hello"})

    assert captured["user_during_stream"] is None


@pytest.mark.asyncio
async def test_handle_message_malformed_attenuation_runs_without_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed user_attenuation payload still lets the turn run (no scope)."""
    captured: dict[str, Any] = {"user_during_stream": "sentinel"}

    async def fake_stream_agent(
        agent: object, handler: object, input: object, **kw: Any
    ):
        captured["user_during_stream"] = get_current_context()
        if False:
            yield None  # pragma: no cover

    monkeypatch.setattr(serve, "stream_agent", fake_stream_agent)

    # ``api_key`` is required on ServeContext post-Phase-6 (used to
    # build the WS bearer subprotocol). _handle_message doesn't touch
    # it, so a placeholder is fine for these unit-level tests.
    context = ServeContext(runtime=_FakeRuntime(), state=ChatState(), api_key="")
    ws = _FakeWebSocket()

    await serve._handle_message(
        context,
        ws,
        {
            "type": "chat",
            "message": "hello",
            "user_attenuation": "not-a-dict",  # ignored, no scope
        },
    )

    assert captured["user_during_stream"] is None


# ---------------------------------------------------------------------------
# Phase 6 — bearer-subprotocol WS handshake
# ---------------------------------------------------------------------------


class _FakeWsForLoop:
    """``async with`` stand-in matching what ``connect()`` returns."""

    def __init__(self, subprotocol: str | None = "hexgate.v1") -> None:
        self.subprotocol = subprotocol
        self.sent: list[str] = []

    async def __aenter__(self) -> "_FakeWsForLoop":
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def send(self, frame: str) -> None:
        self.sent.append(frame)

    def __aiter__(self):
        async def _empty():
            if False:
                yield None  # pragma: no cover

        return _empty()


@pytest.mark.asyncio
async def test_serve_loop_offers_bearer_and_marker_subprotocols(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_serve_loop`` connects with ``bearer.<key>`` + ``hexgate.v1``.

    Pins the Phase 6 WS auth contract: the CLI offers the bearer in
    ``Sec-WebSocket-Protocol`` (the only way to authenticate a WS
    handshake from a browser; we match the contract from native
    Python for consistency). Without the bearer subprotocol the
    server closes with 4401 before accept.

    Real biscuit tokens end with ``=`` padding, which the RFC 7230
    token grammar (inherited by WebSocket subprotocols) forbids. The
    CLI percent-encodes the envelope before placing it in the
    subprotocol value — exercised here with a key containing ``=``.
    """
    captured: dict[str, Any] = {}

    def fake_connect(url: str, **kwargs: Any) -> _FakeWsForLoop:
        captured["url"] = url
        captured["subprotocols"] = kwargs.get("subprotocols")
        captured["ping_interval"] = kwargs.get("ping_interval")
        return _FakeWsForLoop(subprotocol="hexgate.v1")

    monkeypatch.setattr(serve, "connect", fake_connect)

    # Realistic shape: includes the ``=`` padding biscuit emits.
    api_key = "fty_live_acme_AbCdEf123-_=="
    context = ServeContext(
        runtime=_FakeRuntime(),
        state=ChatState(),
        api_key=api_key,
    )
    await serve._serve_loop(context, "ws://test/v1/serve", Console())

    assert captured["url"] == "ws://test/v1/serve"
    # The bearer subprotocol carries the percent-encoded envelope:
    # ``=`` → ``%3D`` (the only non-token char in URL-safe base64).
    assert captured["subprotocols"] == [
        "bearer.fty_live_acme_AbCdEf123-_%3D%3D",
        "hexgate.v1",
    ]
    # No ``=`` survives into the wire format — sanity check for
    # anyone inspecting the subprotocol grammar.
    assert "=" not in captured["subprotocols"][0]
    assert captured["ping_interval"] == serve.PING_INTERVAL


@pytest.mark.asyncio
async def test_serve_loop_aborts_when_marker_not_echoed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Server didn't negotiate ``hexgate.v1`` → HexgateError before any send.

    Defense against accidentally talking to a pre-Phase-6 server that
    silently ignores the unknown ``bearer.`` subprotocol and accepts
    the handshake without honoring the auth contract. Without this
    check the CLI would happily relay chats with no auth at all.
    """

    def fake_connect(url: str, **kwargs: Any) -> _FakeWsForLoop:
        return _FakeWsForLoop(subprotocol=None)  # no marker echoed

    monkeypatch.setattr(serve, "connect", fake_connect)

    context = ServeContext(
        runtime=_FakeRuntime(),
        state=ChatState(),
        api_key="fty_live_acme_secret",
    )

    with pytest.raises(serve.HexgateError, match="hexgate.v1"):
        await serve._serve_loop(context, "ws://test/v1/serve", Console())


# ---------------------------------------------------------------------------
# Phase 7 step 2 — uvicorn-style spec loading + auto-register
# ---------------------------------------------------------------------------


from hexgate.cli._common import build_runtime_from_local_agent, load_spec  # noqa: E402  — section-scoped import keeps phase-7 tests visually grouped


def test_load_spec_resolves_module_attr_form() -> None:
    """``module:attr`` round-trips through importlib + getattr.

    Pins the uvicorn-style contract: the spec is the user-facing shape
    for ``hexgate register --agent ...`` AND ``hexgate serve ...``;
    both subcommands share this helper.
    """
    # The serve module itself is a convenient real target — it has
    # a ``main`` attribute we can pin to. No setup required.
    loaded = load_spec("hexgate.cli.serve:main")
    assert loaded is serve.main


def test_load_spec_rejects_bad_format() -> None:
    """A spec without a colon → ValueError naming the expected form."""
    with pytest.raises(ValueError, match="module.path:attr"):
        load_spec("no_colon_here")


def test_load_spec_rejects_missing_attribute() -> None:
    """Valid module but unknown attr → AttributeError."""
    with pytest.raises(AttributeError, match="no attribute"):
        load_spec("hexgate.cli.serve:does_not_exist")


def _stub_settings() -> object:
    """A minimal Settings stand-in. Only .model is touched by
    build_runtime_from_local_agent for the AgentRuntime envelope."""

    class _S:
        model = "gpt-4o-mini"
        search_engine = "test"

    return _S()


@pytest.fixture
def _patched_runtime_deps(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub out the network + tracing calls in build_runtime_from_local_agent.

    Records what got passed to post_manifest, get_agent, and
    enforce_policy so each test can assert on the relevant slice.
    """
    captured: dict[str, Any] = {}

    # Pre-built manifest the test rebuilds the spy responses around.
    fake_manifest_obj = type("FakeManifest", (), {"name": "customer_bot"})()

    def fake_create_manifest(agent_obj: Any, *, description: str | None = None):
        captured["create_manifest_called_with"] = agent_obj
        captured["description"] = description
        return fake_manifest_obj

    def fake_post_manifest(manifest: Any, *, timeout: float = 5.0) -> dict:
        captured["posted_manifest"] = manifest
        return captured.get("post_response", {"created": True, "version": 1})

    class _FakeClient:
        def __init__(self, _config: Any) -> None:
            pass

        def get_agent(self, name: str):
            captured["get_agent_name"] = name
            return (
                # Minimal payload with a parseable policy_yaml. The
                # roles map gives load_policy_set_from_dict something
                # to chew on without needing real role inheritance.
                # No bundle_* fields → decode_and_verify_platform_bundle
                # returns None, so the pydantic engine path applies.
                {
                    "policy_yaml": (
                        "version: 1\nroles:\n  default:\n    "
                        "default_policy:\n      mode: allow\n"
                    )
                },
                "etag-abc",
            )

        def public_key_bytes(self) -> bytes:
            # Never consulted on the bundle-less path (the payload above
            # omits the bundle fields, so decode_and_verify_platform_bundle
            # returns before touching this key). 32 zero bytes are enough
            # to satisfy the type contract.
            return b"\x00" * 32

    def fake_enforce_policy(agent_obj: Any, policy: Any, **kw: Any):
        captured["enforced_agent"] = agent_obj
        captured["enforced_policy"] = policy
        captured["enforce_kwargs"] = kw
        return agent_obj

    def fake_get_handler(**kw: Any) -> object:
        return object()

    monkeypatch.setattr("hexgate.manifest.create_manifest", fake_create_manifest)
    monkeypatch.setattr(
        "hexgate.cli.register.register.post_manifest", fake_post_manifest
    )
    monkeypatch.setattr("hexgate.cloud.client.HexgateClient", _FakeClient)

    class _FakeConfig:
        @classmethod
        def from_env(cls, **kw: Any) -> "_FakeConfig":
            return cls()

        base_url = "http://test"
        api_key = "fty_live_test_secret"
        project_id = "proj-1"
        public_key = None

    monkeypatch.setattr("hexgate.cloud.client.HexgateConfig", _FakeConfig)
    monkeypatch.setattr("hexgate.agents.factory.enforce_policy", fake_enforce_policy)
    monkeypatch.setattr(
        "hexgate.tracing.langfuse.get_langfuse_handler", fake_get_handler
    )
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_live_test_secret")
    return captured


def test_build_runtime_auto_registers_on_first_run(
    _patched_runtime_deps: dict[str, Any],
) -> None:
    """``auto_register=True`` POSTs the manifest before fetching policy.

    Auto-register is the dev-loop convenience — first time a Python
    file is served, it lands on the platform automatically. The
    response's ``created`` flag distinguishes first-create from
    no-op idempotent re-register.
    """
    captured = _patched_runtime_deps
    captured["post_response"] = {"created": True, "version": 1}

    runtime = build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=object(),
        description="hello",
        approval_handler=None,
        auto_register=True,
        console=Console(),
    )

    # Manifest got built from the agent object.
    assert "create_manifest_called_with" in captured
    assert captured["description"] == "hello"
    # POST fired.
    assert captured["posted_manifest"].name == "customer_bot"
    # Fetched the same name back.
    assert captured["get_agent_name"] == "customer_bot"
    # Runtime envelope carries the resolved name + the enforced agent.
    assert runtime.agent_name == "customer_bot"
    assert runtime.agent_source == "hexgate"


def test_build_runtime_skips_auto_register_when_disabled(
    _patched_runtime_deps: dict[str, Any],
) -> None:
    """``auto_register=False`` doesn't POST — only fetches the existing one.

    The CI / deliberate-deployment shape: registration is a separate
    step, serve should fail loud if the agent isn't already on the
    platform rather than silently registering.
    """
    captured = _patched_runtime_deps

    build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=object(),
        description=None,
        approval_handler=None,
        auto_register=False,
        console=Console(),
    )

    assert "posted_manifest" not in captured  # POST was skipped
    assert captured["get_agent_name"] == "customer_bot"


def test_build_runtime_applies_fetched_policy_to_local_agent(
    _patched_runtime_deps: dict[str, Any],
) -> None:
    """The policy used at runtime is the one fetched from the cloud,
    not anything baked into the local agent object.

    Pins the Phase 7 contract: local code = source of truth for tools;
    cloud = source of truth for policy. An operator's edit in the
    dashboard's /policies viewer takes effect on next serve start
    (and also at the next chat turn via ETag refresh).
    """
    captured = _patched_runtime_deps
    user_agent = object()

    build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=user_agent,
        description=None,
        approval_handler=None,
        auto_register=True,
        console=Console(),
    )

    # enforce_policy was called with the LOCAL agent + the CLOUD policy.
    assert captured["enforced_agent"] is user_agent
    # The fetched policy_yaml had the ``default`` role declared.
    assert "default" in captured["enforced_policy"].roles


def test_build_runtime_attaches_platform_policy_source_for_per_turn_refresh(
    _patched_runtime_deps: dict[str, Any],
) -> None:
    """Regression: serve must attach a PolicySource so dashboard edits land
    at the next chat turn, not only at the next ``hexgate serve`` restart.

    The previous implementation parsed ``policy_yaml`` straight into a
    PolicySet and called ``enforce_policy(agent, policy, approval_handler=...)``
    with no ``source=`` kwarg, leaving the binding's source as ``None``
    and the per-turn ``refresh_policy()`` a no-op. The canonical helper
    ``platform_policy_from_payload`` returns both the engine AND a
    pre-seeded :class:`PlatformPolicySource` — wiring the source through
    is the difference between "policy reloads on next turn" and "policy
    only reloads on serve restart".
    """
    from hexgate.security.source import PlatformPolicySource

    captured = _patched_runtime_deps

    build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=object(),
        description=None,
        approval_handler=None,
        auto_register=True,
        console=Console(),
    )

    kwargs = captured["enforce_kwargs"]
    assert "source" in kwargs, (
        "enforce_policy must be called with source= so per-turn refresh works"
    )
    assert isinstance(kwargs["source"], PlatformPolicySource), (
        f"expected PlatformPolicySource, got {type(kwargs['source']).__name__}"
    )
