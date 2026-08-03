"""Tests for HexgateUsageHooks's usage extraction from ModelResponse."""

from __future__ import annotations

from typing import Any

import pytest
from agents import Agent
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage

from hexgate.adapters.openai import usage as usage_mod
from hexgate.adapters.openai.usage import HexgateUsageHooks


class _StubModel(Model):
    """Minimal concrete Model for testing agent.model resolution."""

    async def get_response(self, *args: object, **kwargs: object) -> object:
        raise NotImplementedError

    def stream_response(self, *args: object, **kwargs: object) -> object:
        raise NotImplementedError


class _ModelWithId(_StubModel):
    def __init__(self, model_id: str) -> None:
        self.model = model_id


def _response(input_tokens: int = 10, output_tokens: int = 20) -> ModelResponse:
    return ModelResponse(
        output=[],
        usage=Usage(input_tokens=input_tokens, output_tokens=output_tokens),
        response_id=None,
    )


@pytest.fixture()
def emitted(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture emit_llm_usage() calls without touching the sender registry."""
    calls: list[dict[str, Any]] = []

    def fake_emit(
        agent_name: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        api_key: str,
    ) -> None:
        calls.append(
            dict(
                agent_name=agent_name,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                api_key=api_key,
            )
        )

    monkeypatch.setattr(usage_mod, "emit_llm_usage", fake_emit)
    return calls


@pytest.mark.asyncio
async def test_on_llm_end_emits_usage_from_response(
    emitted: list[dict[str, Any]],
) -> None:
    hooks = HexgateUsageHooks(api_key="k")
    agent = Agent(name="my-agent", model="gpt-4o")

    await hooks.on_llm_end(context=object(), agent=agent, response=_response(10, 20))

    [call] = emitted
    assert call == {
        "agent_name": "my-agent",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 20,
        "api_key": "k",
    }


@pytest.mark.asyncio
async def test_on_llm_end_when_model_is_none_then_model_is_default(
    emitted: list[dict[str, Any]],
) -> None:
    """agent.model defaults to None when unset -- the agent uses whatever
    model the runner/SDK resolves at call time, which this hook never sees.
    "default" is an honest placeholder rather than a guess. Not "" -- the
    platform rejects an empty `model` outright (min_length=1), which would
    silently drop the event."""
    hooks = HexgateUsageHooks(api_key="k")
    agent = Agent(name="my-agent")  # model defaults to None

    await hooks.on_llm_end(context=object(), agent=agent, response=_response())

    [call] = emitted
    assert call["model"] == "default"


@pytest.mark.asyncio
async def test_on_llm_end_when_model_is_a_model_instance_then_model_is_its_id(
    emitted: list[dict[str, Any]],
) -> None:
    """Standard Model impls (e.g. OpenAIResponsesModel) expose the real
    model id via .model -- that should be reported, not the class name."""
    hooks = HexgateUsageHooks(api_key="k")
    agent = Agent(name="my-agent", model=_ModelWithId("gpt-4o"))

    await hooks.on_llm_end(context=object(), agent=agent, response=_response())

    [call] = emitted
    assert call["model"] == "gpt-4o"


@pytest.mark.asyncio
async def test_on_llm_end_when_model_is_an_exotic_model_then_model_is_class_name(
    emitted: list[dict[str, Any]],
) -> None:
    """A Model implementation with no .model attribute has no guaranteed
    name field (agents.models.interface.Model exposes none), so it falls
    back to the instance's class name."""
    hooks = HexgateUsageHooks(api_key="k")
    agent = Agent(name="my-agent", model=_StubModel())

    await hooks.on_llm_end(context=object(), agent=agent, response=_response())

    [call] = emitted
    assert call["model"] == "_StubModel"
