"""Tests for HexgateUsageHooks's usage extraction from ModelResponse."""

from __future__ import annotations

from typing import Any

import pytest
from agents import Agent
from agents.items import ModelResponse
from agents.usage import Usage

from hexgate.adapters.openai import usage as usage_mod
from hexgate.adapters.openai.usage import HexgateUsageHooks


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
async def test_on_llm_end_when_model_is_not_a_string_then_model_is_class_name(
    emitted: list[dict[str, Any]],
) -> None:
    """agent.model is `str | Model | None` — a Model instance (or None) has
    no guaranteed name field, so it's reported as the instance's class name
    rather than guessed at. Not "" — the platform rejects an empty `model`
    outright (min_length=1), which would silently drop the event."""
    hooks = HexgateUsageHooks(api_key="k")
    agent = Agent(name="my-agent")  # model defaults to None

    await hooks.on_llm_end(context=object(), agent=agent, response=_response())

    [call] = emitted
    assert call["model"] == "NoneType"
