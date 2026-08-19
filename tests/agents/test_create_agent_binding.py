"""Tests for ``create_agent(bind_policy=...)`` (policy-binding spec, phase 3).

Covers the dispatch matrix (auto / True / False), the full bind path
(tools guarded, source attached, client attached), fail-loud on a platform
404 (no auto-register), and the ``enforce_policy`` source-detach guard that
keeps an explicit policy from being silently swapped back at the next run.

The LangChain graph build and the Langfuse handler are stubbed exactly
like tests/agents/test_factory.py does; the platform is a scripted fake
client patched over ``hexgate.cloud.client.HexgateClient``.
"""

from __future__ import annotations


import pytest
from langchain_core.tools import tool

from hexgate.agents import factory
from hexgate.adapters.langchain.tools import GuardedTool
from hexgate.cloud.client import HexgateError
from hexgate.security import AgentPolicy, PolicySet
from hexgate.security.policy_set import DEFAULT_ROLE_NAME
from hexgate.security.source import PlatformPolicySource

_POLICY_YAML = """\
version: 1
roles:
  billing:
    tools:
      echo:
        mode: allow
"""


@tool
def echo(text: str) -> str:
    """Echo the input back."""
    return text


class _FakeClient:
    """Scripted HexgateClient stand-in (same shape as the binding tests)."""

    def __init__(self) -> None:
        self._queued: list[tuple[dict | None, str | None] | Exception] = []
        self.calls: list[str | None] = []

    def serve(self, payload: dict | None, etag: str | None = None) -> None:
        self._queued.append((payload, etag))

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
        return b"\x00" * 32  # never consulted on the bundle-less path


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the graph build + handler, and clear governance env vars."""
    monkeypatch.setattr(
        factory, "create_langchain_agent", lambda **kwargs: "graph-instance"
    )
    monkeypatch.setattr(
        factory, "get_langfuse_handler", lambda **kwargs: "handler-instance"
    )
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    monkeypatch.delenv("HEXGATE_BIND_AGENTS", raising=False)
    monkeypatch.delenv("HEXGATE_LOCAL_MODE", raising=False)


def _patch_platform(monkeypatch: pytest.MonkeyPatch, client: _FakeClient) -> None:
    """Route _bind_policy's client construction to the scripted fake.

    Sets both the key and the HEXGATE_BIND_AGENTS opt-in toggle — the
    platform bind path is gated on both (a bare key never auto-binds).
    """
    import hexgate.cloud.client as client_mod

    monkeypatch.setenv("HEXGATE_API_KEY", "fty_test_demo_dummybiscuit")
    monkeypatch.setenv("HEXGATE_BIND_AGENTS", "1")
    monkeypatch.setattr(client_mod, "HexgateClient", lambda config: client)


# ---------------------------------------------------------------------------
# Dispatch matrix
# ---------------------------------------------------------------------------


def test_auto_mode_without_governance_env_returns_bare_agent() -> None:
    """No HEXGATE_API_KEY / HEXGATE_LOCAL_POLICY → today's bare graph."""
    agent, handler = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    assert handler == "handler-instance"
    assert agent.tools == [echo]  # unwrapped
    assert agent._binding is None


def test_auto_mode_without_name_skips_even_with_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nameless agents have nothing to resolve against — silent skip."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_test_demo_dummybiscuit")

    agent, _ = factory.create_agent(model="openai:gpt-5.4", tools=[echo])

    assert agent.tools == [echo]
    assert agent._binding is None


def test_auto_mode_bare_key_does_not_bind_without_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A HEXGATE_API_KEY present for some *other* agent must not auto-bind a
    named prototype — that would surprise-404 at construction. The platform
    bind path needs HEXGATE_BIND_AGENTS=1 (or an explicit bind_policy=True)."""
    import hexgate.cloud.client as client_mod

    monkeypatch.setenv("HEXGATE_API_KEY", "fty_test_demo_dummybiscuit")
    monkeypatch.delenv("HEXGATE_BIND_AGENTS", raising=False)
    # The platform must never be contacted — fail hard if a client is built.
    monkeypatch.setattr(
        client_mod,
        "HexgateClient",
        lambda config: pytest.fail("create_agent contacted the platform"),
    )

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="my_local_prototype"
    )

    assert agent.tools == [echo]  # unwrapped, no construction-time 404
    assert agent._binding is None


def test_auto_mode_respects_hexgate_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`HEXGATE_LOCAL_MODE` is the one-way kill switch the local-mode bootstrap
    sets; the auto-bind path must respect it just like ``audit.configure``
    does. Even with both the platform key and the opt-in toggle set, a
    create_agent under local mode stays bare — the user explicitly asked
    for no platform IO from this process."""
    import hexgate.cloud.client as client_mod
    from hexgate.tracing._senders import _LOCAL_MODE_ENV

    monkeypatch.setenv("HEXGATE_API_KEY", "fty_test_demo_dummybiscuit")
    monkeypatch.setenv("HEXGATE_BIND_AGENTS", "1")
    monkeypatch.setenv(_LOCAL_MODE_ENV, "1")
    # The platform must never be contacted — fail hard if a client is built.
    monkeypatch.setattr(
        client_mod,
        "HexgateClient",
        lambda config: pytest.fail(
            "create_agent contacted the platform under local mode"
        ),
    )

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    assert agent.tools == [echo]
    assert agent._binding is None


def test_bind_policy_true_overrides_hexgate_local_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``bind_policy=True`` is the explicit-caller form — local mode shouldn't
    silently veto it. The kill switch only short-circuits the auto-detect path."""
    from hexgate.tracing._senders import _LOCAL_MODE_ENV

    monkeypatch.setenv(_LOCAL_MODE_ENV, "1")
    monkeypatch.setattr(
        factory,
        "_bind_policy",
        lambda agent, name, approval_handler, **kwargs: agent.with_tools(
            ["bound-sentinel"]
        ),
    )

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4",
        tools=[echo],
        name="support-bot",
        bind_policy=True,
    )

    assert agent.tools == ["bound-sentinel"]


def test_bind_policy_false_skips_even_with_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The explicit escape hatch for bare graphs in keyed environments."""
    monkeypatch.setenv("HEXGATE_API_KEY", "fty_test_demo_dummybiscuit")

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot", bind_policy=False
    )

    assert agent.tools == [echo]
    assert agent._binding is None


def test_bind_policy_true_requires_name() -> None:
    with pytest.raises(ValueError, match="requires name="):
        factory.create_agent(model="openai:gpt-5.4", tools=[echo], bind_policy=True)


# ---------------------------------------------------------------------------
# The bind path
# ---------------------------------------------------------------------------


def test_bind_wraps_tools_and_attaches_source_and_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Auto mode + HEXGATE_API_KEY + name → guarded tools, seeded source, client."""
    fc = _FakeClient()
    fc.serve({"policy_yaml": _POLICY_YAML}, etag='"hash-a"')
    _patch_platform(monkeypatch, fc)

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    assert len(agent.tools) == 1
    assert isinstance(agent.tools[0], GuardedTool)
    assert isinstance(agent._binding.source, PlatformPolicySource)
    assert isinstance(agent._binding.enforcer.policy, PolicySet)
    assert agent.hexgate_client is fc
    assert fc.calls == [None]  # exactly one fetch at creation


def test_bind_failure_is_loud_not_a_bare_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Binding was requested (key present) — a platform error must raise,
    never silently degrade to an unguarded agent."""
    fc = _FakeClient()
    fc.serve_error(HexgateError("Hexgate API error 500 calling …", status=500))
    _patch_platform(monkeypatch, fc)

    with pytest.raises(HexgateError, match="500"):
        factory.create_agent(model="openai:gpt-5.4", tools=[echo], name="support-bot")


def test_404_is_loud_does_not_auto_register(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unregistered agent surfaces the 404 — create_agent never silently
    auto-creates it on the platform (register-on-404 is deferred)."""
    fc = _FakeClient()
    fc.serve_error(HexgateError("Hexgate API error 404 calling …", status=404))
    _patch_platform(monkeypatch, fc)

    with pytest.raises(HexgateError) as excinfo:
        factory.create_agent(model="openai:gpt-5.4", tools=[echo], name="new-agent")

    assert excinfo.value.status == 404
    assert fc.calls == [None]  # one fetch, no register-and-retry


def test_local_override_binds_without_a_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HEXGATE_LOCAL_POLICY alone triggers auto mode; resolve takes the
    override branch and the platform is never contacted."""
    import hexgate.security.binding as binding_mod

    override_policy = PolicySet({DEFAULT_ROLE_NAME: AgentPolicy()})

    class _StubSource:
        def fetch(self) -> object:
            return override_policy

    stub = _StubSource()
    monkeypatch.setenv("HEXGATE_LOCAL_POLICY", "/tmp/override-bundle")
    monkeypatch.setattr(
        binding_mod, "_local_policy_override", lambda: (override_policy, stub)
    )

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    assert isinstance(agent.tools[0], GuardedTool)
    assert agent._binding.source is stub
    assert agent.hexgate_client is None


# ---------------------------------------------------------------------------
# enforce_policy detaches the inherited source
# ---------------------------------------------------------------------------


def test_enforce_policy_detaches_inherited_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit enforce_policy after binding must not be silently
    swapped back to the platform policy by the next run's refresh."""
    fc = _FakeClient()
    fc.serve({"policy_yaml": _POLICY_YAML}, etag='"hash-a"')
    _patch_platform(monkeypatch, fc)

    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )
    assert agent._binding.source is not None

    custom = agent.enforce_policy(AgentPolicy())

    assert custom._binding.source is None  # refresh can't overwrite the custom policy
    custom.refresh_policy()  # no source → quiet no-op


# ---------------------------------------------------------------------------
# enforce_policy — the (policy, source) matrix
# ---------------------------------------------------------------------------


def test_enforce_policy_none_with_source_is_rejected() -> None:
    """(policy=None, source=X) is a caller mistake — reject loudly rather than
    leave the agent silently unguarded with a dangling refresh source."""
    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    with pytest.raises(ValueError, match="no policy to enforce"):
        agent.enforce_policy(None, source=object())  # type: ignore[arg-type]


def test_enforce_policy_none_without_source_is_noop() -> None:
    """(policy=None, source=None) is the documented no-op — unguarded rebuild."""
    agent, _ = factory.create_agent(
        model="openai:gpt-5.4", tools=[echo], name="support-bot"
    )

    rebuilt = agent.enforce_policy(None)

    assert rebuilt.tools == [echo]  # unwrapped
    assert rebuilt._binding is None
