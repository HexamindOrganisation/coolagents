"""Tests for the LangChain adapter wrapper entry point (phase 4).

The allow-all ``build_policy_set`` placeholder is gone: wrap-time policy
comes from :func:`resolve_policy` (platform / local override; fail-loud on
a 404). These tests stub that seam so no platform is needed, and cover:
key resolution, enforcer installation with the resolved policy, and the
proxy's per-call refresh.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import BaseTool, tool

from hexgate.adapters.langchain import wrapper as wrapper_mod
from hexgate.adapters.langchain.agent import HexgateLangchainAgent
from hexgate.adapters.langchain.wrapper import wrap_langchain_agent
from hexgate.runtime import HexgateContext
from hexgate.security import AgentPolicy, BaseToolPolicy, PolicySet, ResolvedPolicy
from hexgate.security.enforcer import PolicyEnforcer
from hexgate.security.policy_set import DEFAULT_ROLE_NAME


class _FakeCompiledGraph:
    """Stand in for a CompiledStateGraph during construction-only tests."""

    name = "fake-graph"


def _make_tool(name: str = "echo") -> BaseTool:
    """Create a StructuredTool-style tool for wrapper tests."""

    @tool(name)
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    return echo


def _engine(tool_names: list[str], mode: str = "allow") -> PolicySet:
    return PolicySet(
        {
            DEFAULT_ROLE_NAME: AgentPolicy(
                tools={name: BaseToolPolicy(mode=mode) for name in tool_names}
            )
        }
    )


@pytest.fixture()
def resolved(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub the resolve seam with an allow-all engine; capture the call."""
    captured: dict[str, Any] = {}

    def fake_resolve(
        name: str, *, api_key: str, client: object = None
    ) -> ResolvedPolicy:
        captured.update(name=name, key=api_key)
        return ResolvedPolicy(_engine(["a", "b"]), None)

    monkeypatch.setattr(wrapper_mod, "resolve_policy", fake_resolve)
    return captured


# ---------------------------------------------------------------------------
# wrap_langchain_agent — API key resolution
# ---------------------------------------------------------------------------


def test_wrap_returns_hexgate_proxy_with_supplied_tool_names(
    resolved: dict[str, Any],
) -> None:
    graph = _FakeCompiledGraph()
    tools = [_make_tool("a"), _make_tool("b")]

    wrapped = wrap_langchain_agent(agent=graph, tools=tools, api_key="hexgate-key")

    assert isinstance(wrapped, HexgateLangchainAgent)
    assert wrapped._tool_names == ["a", "b"]
    assert wrapped._agent is graph
    assert wrapped._api_key == "hexgate-key"
    assert wrapped._usage_handler._agent_name == "fake-graph"
    assert resolved["name"] == "fake-graph"
    assert resolved["key"] == "hexgate-key"


def test_wrap_falls_back_to_env_var(
    monkeypatch: pytest.MonkeyPatch, resolved: dict[str, Any]
) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")

    wrapped = wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=[])

    assert wrapped._api_key == "from-env"


def test_wrap_prefers_explicit_api_key_over_env(
    monkeypatch: pytest.MonkeyPatch, resolved: dict[str, Any]
) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")

    wrapped = wrap_langchain_agent(
        agent=_FakeCompiledGraph(), tools=[], api_key="explicit"
    )

    assert wrapped._api_key == "explicit"


def test_wrap_raises_when_no_api_key_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)

    with pytest.raises(ValueError, match="No API key provided"):
        wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=[])


def test_wrap_treats_empty_api_key_string_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "")

    with pytest.raises(ValueError, match="No API key provided"):
        wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=[], api_key="")


# ---------------------------------------------------------------------------
# wrap_langchain_agent — enforcer installation with the RESOLVED policy
# ---------------------------------------------------------------------------


def test_wrap_installs_enforcer_on_each_tool_in_place(
    resolved: dict[str, Any],
) -> None:
    """Every tool gets the install marker — graph keeps its references."""
    tools = [_make_tool("a"), _make_tool("b")]

    wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=tools, api_key="k")

    for t in tools:
        assert getattr(t, "_hexgate_enforcer_installed") is True
        assert t.handle_tool_error is True


def test_wrap_enforces_the_resolved_policy_not_allow_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deny rule from the resolved policy actually blocks the tool."""
    monkeypatch.setattr(
        wrapper_mod,
        "resolve_policy",
        lambda name, *, api_key, client=None: ResolvedPolicy(
            _engine(["a"], mode="deny"), None
        ),
    )
    tools = [_make_tool("a")]

    wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=tools, api_key="k")

    result = tools[0].func(text="hi")
    assert result["ok"] is False
    assert result["error"]["type"] == "policy_denied"


def test_wrap_is_idempotent_on_already_wrapped_tools(
    resolved: dict[str, Any],
) -> None:
    """Re-wrapping rebinds the enforcer; doesn't stack gates."""
    tools = [_make_tool("a")]
    wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=tools, api_key="k")
    first_func = tools[0].func

    wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=tools, api_key="k")

    assert tools[0].func is not first_func
    assert tools[0].func(text="hi") == "echo:hi"


def test_wrap_attaches_binding_with_audited_enforcer(
    resolved: dict[str, Any],
) -> None:
    """The proxy carries a binding whose enforcer is the one the tools got."""
    tools = [_make_tool("a")]

    wrapped = wrap_langchain_agent(agent=_FakeCompiledGraph(), tools=tools, api_key="k")

    assert wrapped._binding is not None
    # The tools' installed gate and the binding share one enforcer, so a
    # refresh swap reaches the wrapped tools.
    assert isinstance(wrapped._binding.enforcer, PolicyEnforcer)
    assert wrapped._binding.enforcer.agent_name == "fake-graph"


def test_wrap_shares_one_client_across_policy_and_ban_resolvers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One HexgateClient is threaded into both resolvers (no duplicate verify)."""
    seen: dict[str, Any] = {}

    def fake_resolve(name, *, api_key, client=None):
        seen["policy"] = client
        return ResolvedPolicy(_engine(["a"]), None)

    def fake_ban(name, *, api_key=None, client=None):
        seen["ban"] = client
        return None

    monkeypatch.setattr(wrapper_mod, "resolve_policy", fake_resolve)
    monkeypatch.setattr(wrapper_mod, "resolve_ban_gate", fake_ban)

    wrap_langchain_agent(
        agent=_FakeCompiledGraph(), tools=[_make_tool("a")], api_key="k"
    )

    assert seen["policy"] is not None
    assert seen["policy"] is seen["ban"]


# ---------------------------------------------------------------------------
# HexgateLangchainAgent — per-call refresh
# ---------------------------------------------------------------------------


class _CountingBinding:
    def __init__(self) -> None:
        self.refreshes = 0

    def refresh(self) -> None:
        self.refreshes += 1

    async def refresh_async(self) -> None:
        self.refreshes += 1


class _RunnableGraph:
    name = "fake-graph"

    def invoke(self, input: dict, config: Any = None, **kwargs: Any) -> dict:
        return {"ok": True}

    async def ainvoke(self, input: dict, config: Any = None, **kwargs: Any) -> dict:
        return {"ok": True}


def _user() -> HexgateContext:
    return HexgateContext(user_id="u-1", session_id="s-1", user_roles=["developer"])


def test_invoke_refreshes_binding_first() -> None:
    binding = _CountingBinding()
    proxy = HexgateLangchainAgent(
        agent=_RunnableGraph(),
        api_key="k",
        tool_names=[],
        binding=binding,  # type: ignore[arg-type]
    )

    proxy.invoke({"messages": []}, hexgate_context=_user())
    proxy.invoke({"messages": []}, hexgate_context=_user())

    assert binding.refreshes == 2


@pytest.mark.asyncio
async def test_ainvoke_refreshes_binding_first() -> None:
    binding = _CountingBinding()
    proxy = HexgateLangchainAgent(
        agent=_RunnableGraph(),
        api_key="k",
        tool_names=[],
        binding=binding,  # type: ignore[arg-type]
    )

    await proxy.ainvoke({"messages": []}, hexgate_context=_user())

    assert binding.refreshes == 1


def test_proxy_without_binding_runs_fine() -> None:
    """Back-compat: a binding-less proxy (direct construction) still works."""
    proxy = HexgateLangchainAgent(agent=_RunnableGraph(), api_key="k", tool_names=[])

    assert proxy.invoke({"messages": []}, hexgate_context=_user()) == {"ok": True}
