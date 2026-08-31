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
    context = _context_from_payload(
        {
            "user": "alice",
            "role": "billing",
            "session_id": "sess_abc",
            "ttl_seconds": 300,
        }
    )
    assert context is not None
    assert context.user_id == "alice"
    assert context.user_roles == ["billing"]
    assert context.session_id == "sess_abc"
    assert context.ttl_seconds == 300


def test_context_from_payload_maps_roles_list() -> None:
    """A ``roles`` list is carried verbatim — every entry is enforced."""
    context = _context_from_payload({"user": "alice", "roles": ["billing", "support"]})
    assert context is not None
    assert context.user_roles == ["billing", "support"]


def test_context_from_payload_maps_legacy_single_role() -> None:
    """The legacy singular ``role`` wire key maps to a one-element list."""
    context = _context_from_payload({"user": "alice", "role": "billing"})
    assert context is not None
    assert context.user_roles == ["billing"]


def test_context_from_payload_no_role_yields_empty_roles() -> None:
    """Neither ``roles`` nor ``role`` present → empty list (falls back to default)."""
    context = _context_from_payload({"user": "bob"})
    assert context is not None
    assert context.user_roles == []


def test_context_from_payload_returns_user_with_just_user_id() -> None:
    """Minimal ``{"user": ...}`` is enough."""
    context = _context_from_payload({"user": "bob"})
    assert context is not None
    assert context.user_id == "bob"
    assert context.user_roles == []


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
    """Runtime stand-in — what `_handle_message` reads off ``context.runtime``.

    Records the ``(input, ctx, query)`` the serve loop threads into the
    framework streaming seam. Post-refactor, serve's job is to parse
    ``user_attenuation`` and hand the resulting context to the seam; opening
    the HexgateContext scope is each framework closure's own responsibility.
    """

    def __init__(self) -> None:
        self.agent_name = "fake-agent"
        self.agent = object()
        self.handler = object()
        self.received: dict[str, Any] = {}

    async def astream_normalized(self, agent_input: object, ctx: object, query: str):
        self.received["input"] = agent_input
        self.received["ctx"] = ctx
        self.received["query"] = query
        if False:
            yield None  # pragma: no cover — empty async generator


@pytest.mark.asyncio
async def test_handle_message_chat_threads_attenuation_context_to_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A chat payload with ``user_attenuation`` reaches the seam as a parsed context."""
    runtime = _FakeRuntime()
    context = ServeContext(runtime=runtime, state=ChatState(), api_key="")
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

    ctx: HexgateContext | None = runtime.received["ctx"]
    assert ctx is not None
    assert ctx.user_id == "alice"
    assert ctx.user_roles == ["billing"]
    # The user's message is threaded as the query for the run-start event.
    assert runtime.received["query"] == "refund 30"
    # serve itself never opens a scope now — it stays clean.
    assert get_current_context() is None


@pytest.mark.asyncio
async def test_handle_message_chat_without_attenuation_passes_none_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Messages without ``user_attenuation`` reach the seam with ``ctx=None``."""
    runtime = _FakeRuntime()
    context = ServeContext(runtime=runtime, state=ChatState(), api_key="")
    ws = _FakeWebSocket()

    await serve._handle_message(context, ws, {"type": "chat", "message": "hello"})

    assert runtime.received["ctx"] is None


@pytest.mark.asyncio
async def test_handle_message_malformed_attenuation_passes_none_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A malformed ``user_attenuation`` payload still runs the turn with ``ctx=None``."""
    runtime = _FakeRuntime()
    context = ServeContext(runtime=runtime, state=ChatState(), api_key="")
    ws = _FakeWebSocket()

    await serve._handle_message(
        context,
        ws,
        {
            "type": "chat",
            "message": "hello",
            "user_attenuation": "not-a-dict",  # ignored → ctx None
        },
    )

    assert runtime.received["ctx"] is None


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
from hexgate.manifest.models import AgentFramework  # noqa: E402  — section-scoped


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

    def fake_create_manifest(agent_obj: Any, *, description: str | None = None):
        captured["create_manifest_called_with"] = agent_obj
        captured["description"] = description
        # Framework drives dispatch in build_runtime_from_local_agent; default
        # to the native path, tests override via ``captured["framework"]``.
        framework = captured.get("framework", AgentFramework.HEXGATE)
        return type(
            "FakeManifest", (), {"name": "customer_bot", "framework": framework}
        )()

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


# ---------------------------------------------------------------------------
# Framework dispatch — serve builds the right runtime per manifest.framework
# ---------------------------------------------------------------------------


def test_build_runtime_native_binds_streaming_seam(
    _patched_runtime_deps: dict[str, Any],
) -> None:
    """The native (hexgate) path binds an ``astream_normalized`` seam.

    serve streams exclusively through this seam, so a runtime built
    without one would raise at the first chat turn.
    """
    runtime = build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=object(),
        description=None,
        approval_handler=None,
        auto_register=False,
        console=Console(),
    )
    assert runtime.astream_normalized is not None


def test_build_runtime_openai_uses_runner_and_skips_enforce(
    _patched_runtime_deps: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OpenAI agent builds a HexgateRunner and binds the OpenAI seam.

    The OpenAI runner owns enforcement (it fetches + hot-reloads its own
    binding per run), so the native ``enforce_policy`` / ``get_agent``
    path must NOT run for an OpenAI agent.
    """
    captured = _patched_runtime_deps
    captured["framework"] = AgentFramework.OPENAI

    class _FakeRunner:
        def __init__(self, *, approval_handler: Any = None) -> None:
            captured["runner_approval_handler"] = approval_handler

    monkeypatch.setattr("hexgate.adapters.openai.runner.HexgateRunner", _FakeRunner)

    sentinel_agent = object()
    handler = object()
    runtime = build_runtime_from_local_agent(
        _stub_settings(),
        agent_obj=sentinel_agent,
        description=None,
        approval_handler=handler,
        auto_register=False,
        console=Console(),
    )

    # The OpenAI runner was constructed with the serve approval handler.
    assert captured["runner_approval_handler"] is handler
    # The runtime wraps the raw OpenAI agent and binds a streaming seam.
    assert runtime.agent is sentinel_agent
    assert runtime.astream_normalized is not None
    assert runtime.agent_name == "customer_bot"
    # The native policy-fetch path did NOT run for OpenAI.
    assert "get_agent_name" not in captured
    assert "enforced_agent" not in captured


@pytest.mark.parametrize(
    "framework", [AgentFramework.GOOGLE, AgentFramework.PYDANTIC_AI]
)
def test_build_runtime_rejects_unsupported_framework(
    _patched_runtime_deps: dict[str, Any],
    framework: AgentFramework,
) -> None:
    """Google / Pydantic AI serve isn't built yet — fail loud, not obscure."""
    captured = _patched_runtime_deps
    captured["framework"] = framework

    with pytest.raises(NotImplementedError, match="does not yet support"):
        build_runtime_from_local_agent(
            _stub_settings(),
            agent_obj=object(),
            description=None,
            approval_handler=None,
            auto_register=False,
            console=Console(),
        )
