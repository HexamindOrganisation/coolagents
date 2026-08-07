"""End-to-end verification that a real (wrapped) LangGraph agent's policy
comes from the live platform API and that both its tool-call decision and
its LLM-usage event land in ClickHouse.

Not a test of answer quality — the model is a scripted fake, never a real
LLM provider — this only proves Hexgate's own plumbing: policy fetch at
wrap time, tool-call auditing, and usage ingestion.

Requires: `make clickhouse-up` and `make platform-api` running, and
`HEXGATE_API_KEY` set to a token minted via the dashboard (or the
platform API directly).

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import uuid

import pytest
from langchain.agents import create_agent
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from hexgate.adapters.langchain.wrapper import wrap_langchain_agent
from hexgate.cli.register.register import register_agent
from hexgate.runtime import HexgateContext
from tests.adapters.conftest import HexgatePlatformEnv
from tests.adapters.helpers import (
    AGENT_NAME_PREFIX,
    USER_ID_PREFIX,
    assert_policy_and_usage_events_landed,
)

pytestmark = pytest.mark.integration

FAKE_MODEL_NAME = "hexgate-integration-fake-model"


class _ScriptedToolCallingModel(FakeMessagesListChatModel):
    """`FakeMessagesListChatModel` plus a no-op `bind_tools`.

    `create_agent` calls `model.bind_tools(tools)` once at graph-build
    time; the base `BaseChatModel.bind_tools` raises `NotImplementedError`
    and the fake never inspects tool schemas anyway (responses are
    pre-scripted), so identity is enough — no real provider, no network,
    no API key beyond `HEXGATE_API_KEY` for the platform.
    """

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):  # type: ignore[no-untyped-def]
        return self


def _make_get_weather_tool():
    """A `get_weather`-named tool: a "get_" prefix is a read-shape pattern
    (see `platform/api/hexgate_api/features/agents/compiler.py`'s
    `_READ_PATTERNS`), so a freshly-registered agent's starter policy puts
    it in the `read_only` mixin at `mode: allow` for every role — including
    the `default` role that an unrecognized `HexgateContext.primary_role` falls back to.
    That makes the expected `policy_decision` outcome deterministic
    ('allow'), not something this test needs to special-case per role.

    Defined as an `async def` (not a sync `def`) so LangGraph's ToolNode
    calls the installed `coroutine` directly on the running event loop
    instead of via a thread-pool executor — the enforcer's `decide()`
    reads the active `HexgateContext` off a contextvar, which a plain
    `run_in_executor` thread would not see.
    """

    @tool
    async def get_weather(city: str) -> str:
        """Look up the weather for a city."""
        return f"{city}: sunny, 21C"

    return get_weather


def _scripted_responses() -> list[AIMessage]:
    """One tool-calling turn, then one final answer — deterministically
    triggers exactly one `get_weather` call and two `on_llm_end` events."""
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "get_weather",
                    "args": {"city": "Paris"},
                    "id": "call_1",
                    "type": "tool_call",
                }
            ],
            response_metadata={"model_name": FAKE_MODEL_NAME},
            usage_metadata={"input_tokens": 12, "output_tokens": 4, "total_tokens": 16},
        ),
        AIMessage(
            content="It's sunny and 21C in Paris.",
            response_metadata={"model_name": FAKE_MODEL_NAME},
            usage_metadata={"input_tokens": 20, "output_tokens": 9, "total_tokens": 29},
        ),
    ]


@pytest.mark.asyncio
async def test_agent_run_lands_policy_decision_and_llm_usage_events(
    hexgate_platform_env: HexgatePlatformEnv,
) -> None:
    """Register + wrap a real minimal LangGraph agent, run it through a
    prompt that deterministically triggers one tool call, then poll
    ClickHouse for the resulting policy_decision and llm_invocation rows."""
    agent_name = f"{AGENT_NAME_PREFIX}langchain_{uuid.uuid4().hex[:8]}"
    session_id = f"s-{uuid.uuid4().hex[:8]}"

    tools = [_make_get_weather_tool()]
    model = _ScriptedToolCallingModel(responses=_scripted_responses())
    raw_agent = create_agent(model=model, tools=tools, name=agent_name)

    # `tools`/`model`/`system_prompt` are only consulted for LangChain
    # graphs — a compiled graph doesn't reliably expose them post-compile.
    register_agent(
        raw_agent,
        tools=tools,
        model=FAKE_MODEL_NAME,
        system_prompt="You are a test agent that exercises Hexgate's plumbing.",
    )
    # Policy is resolved from the platform right here, at wrap time
    # (fail-loud on a 404 if `register_agent` above didn't land first).
    wrapped = wrap_langchain_agent(
        agent=raw_agent, tools=tools, api_key=hexgate_platform_env.api_key
    )

    context = HexgateContext(
        user_id=f"{USER_ID_PREFIX}langchain",
        session_id=session_id,
        user_roles=["tester"],
    )
    result = await wrapped.ainvoke(
        {"messages": [{"role": "user", "content": "What's the weather in Paris?"}]},
        hexgate_context=context,
    )
    assert result["messages"][-1].content

    assert_policy_and_usage_events_landed(
        hexgate_platform_env, agent_name, session_id, "get_weather"
    )
