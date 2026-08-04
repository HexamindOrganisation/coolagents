"""End-to-end verification that a real (wrapped) openai-agents-SDK agent's
run (1) pulls its policy from the live platform API, (2) lands a
policy_decision row for its tool call, and (3) lands an llm_invocation row
for its model call. Not a test of answer quality — a test of Hexgate's own
plumbing (policy fetch + audit ingestion), mirroring
tests/adapters/pydantic_ai/test_integration.py.

Requires: `make clickhouse-up` and `make platform-api` running, and
`HEXGATE_API_KEY` set to a token minted via the dashboard (or the
platform API directly).

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import json
import uuid

import pytest
from agents import Agent, FunctionTool
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

from hexgate.adapters.openai.runner import HexgateRunner
from hexgate.cli.register.register import register_agent
from hexgate.runtime import HexgateContext
from tests.adapters.conftest import HexgatePlatformEnv
from tests.adapters.helpers import (
    AGENT_NAME_PREFIX,
    USER_ID_PREFIX,
    assert_policy_and_usage_events_landed,
)

pytestmark = pytest.mark.integration


class _ScriptedModel(Model):
    """Deterministic, $0, no-network fake model.

    openai-agents-sdk ships no TestModel/FakeModel equivalent to
    pydantic_ai's `pydantic_ai.models.test.TestModel` (verified against
    `agents/models/interface.py` — only the abstract `Model`/`ModelProvider`
    contract is exposed). `run_internal/turn_preparation.get_model` returns
    `agent.model` as-is whenever it's already a `Model` instance, without
    touching `ModelProvider`/the OpenAI network client — so implementing
    that public seam directly is the free/deterministic path here. First
    call scripts a tool call; every call after scripts a final text answer,
    so the run always terminates regardless of how many turns the loop
    takes to settle.
    """

    def __init__(self, *, tool_name: str, tool_args: dict, final_text: str) -> None:
        self._tool_name = tool_name
        self._tool_args = tool_args
        self._final_text = final_text
        self._calls = 0

    async def get_response(
        self,
        system_instructions,
        input,
        model_settings,
        tools,
        output_schema,
        handoffs,
        tracing,
        *,
        previous_response_id,
        conversation_id,
        prompt,
    ) -> ModelResponse:
        self._calls += 1
        usage = Usage(requests=1, input_tokens=10, output_tokens=5, total_tokens=15)
        if self._calls == 1:
            output = [
                ResponseFunctionToolCall(
                    id="fc_1",
                    call_id="call_1",
                    name=self._tool_name,
                    arguments=json.dumps(self._tool_args),
                    type="function_call",
                    status="completed",
                )
            ]
        else:
            output = [
                ResponseOutputMessage(
                    id="msg_1",
                    role="assistant",
                    status="completed",
                    type="message",
                    content=[
                        ResponseOutputText(
                            type="output_text",
                            text=self._final_text,
                            annotations=[],
                        )
                    ],
                )
            ]
        return ModelResponse(
            output=output, usage=usage, response_id=f"resp_{self._calls}"
        )

    def stream_response(self, *_args, **_kwargs):
        raise NotImplementedError("_ScriptedModel does not support streaming")


def _weather_tool() -> FunctionTool:
    """A single real tool — needed for a policy_decision row to exist at
    all. `get_weather` deliberately matches `compiler.py`'s `_READ_PATTERNS`
    heuristic so a brand-new agent's generated policy allows it under the
    fallback `default` role (see below)."""

    async def on_invoke(_ctx, _raw_args: str) -> str:
        return "sunny, 22C"

    return FunctionTool(
        name="get_weather",
        description="Get the current weather for a city",
        params_json_schema={
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
        },
        on_invoke_tool=on_invoke,
    )


def test_tool_call_records_policy_decision_and_llm_usage(
    hexgate_platform_env: HexgatePlatformEnv,
) -> None:
    """Register + run a real wrapped Agent whose scripted turn 1 forces a
    `get_weather` tool call: proves policy is pulled from the live platform
    (register_agent fails loud on 404, HexgateRunner._binding_for resolves
    for real) and that both audit tables get a row for this run.

    Outcome assertion: a just-registered agent's generated policy_yaml
    (compiler.py's `_default_policy_for_manifest`) gives the `default` role
    (used because `HexgateContext(user_roles=["tester"])` matches no role and PolicySet.get
    falls back to `default`) an inherited `read_only` mixin with
    `default_policy: mode: deny` plus an allowlist of read-shape tools.
    `get_weather` matches the read heuristic, so this is a deterministic
    `allow`, not a guess.
    """
    agent_name = f"{AGENT_NAME_PREFIX}openai_{uuid.uuid4().hex[:8]}"
    session_id = f"s-{uuid.uuid4().hex[:8]}"
    tool_name = "get_weather"

    model = _ScriptedModel(
        tool_name=tool_name,
        tool_args={"city": "Paris"},
        final_text="It's sunny in Paris.",
    )
    raw_agent = Agent(name=agent_name, model=model, tools=[_weather_tool()])
    register_agent(raw_agent)

    runner = HexgateRunner(api_key=hexgate_platform_env.api_key)
    user = HexgateContext(
        user_id=f"{USER_ID_PREFIX}openai", session_id=session_id, user_roles=["tester"]
    )
    result = runner.run_sync(raw_agent, "What's the weather in Paris?", user=user)
    assert result.final_output

    assert_policy_and_usage_events_landed(
        hexgate_platform_env, agent_name, session_id, tool_name
    )
