"""Tests for HexgateUsageCallbackHandler's usage extraction from LLMResult."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, LLMResult

from hexgate.adapters.langchain import usage as usage_mod
from hexgate.adapters.langchain.usage import HexgateUsageCallbackHandler


def _result(
    *, usage_metadata: dict | None = None, llm_output: dict | None = None
) -> LLMResult:
    message = AIMessage(content="hi", usage_metadata=usage_metadata)
    return LLMResult(
        generations=[[ChatGeneration(message=message)]],
        llm_output=llm_output or {},
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
async def test_on_llm_end_emits_usage_from_standardized_metadata(
    emitted: list[dict[str, Any]],
) -> None:
    handler = HexgateUsageCallbackHandler(agent_name="my-agent", api_key="k")
    response = _result(
        usage_metadata={"input_tokens": 10, "output_tokens": 20, "total_tokens": 30},
        llm_output={"model_name": "gpt-4o"},
    )

    await handler.on_llm_end(response, run_id=uuid4())

    [call] = emitted
    assert call == {
        "agent_name": "my-agent",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 20,
        "api_key": "k",
    }


@pytest.mark.asyncio
async def test_on_llm_end_falls_back_to_legacy_token_usage(
    emitted: list[dict[str, Any]],
) -> None:
    """Providers that don't populate the standardized UsageMetadata field
    still report usage via the legacy llm_output shape."""
    handler = HexgateUsageCallbackHandler(agent_name="my-agent", api_key="k")
    response = _result(
        usage_metadata=None,
        llm_output={
            "model_name": "legacy-model",
            "token_usage": {"prompt_tokens": 5, "completion_tokens": 7},
        },
    )

    await handler.on_llm_end(response, run_id=uuid4())

    [call] = emitted
    assert call["model"] == "legacy-model"
    assert call["input_tokens"] == 5
    assert call["output_tokens"] == 7


@pytest.mark.asyncio
async def test_on_llm_end_does_nothing_when_no_usage_reported(
    emitted: list[dict[str, Any]],
) -> None:
    handler = HexgateUsageCallbackHandler(agent_name="my-agent", api_key="k")
    response = _result(usage_metadata=None, llm_output={"model_name": "gpt-4o"})

    await handler.on_llm_end(response, run_id=uuid4())

    assert emitted == []


@pytest.mark.asyncio
async def test_on_llm_end_reads_model_from_response_metadata_when_streaming(
    emitted: list[dict[str, Any]],
) -> None:
    """Streaming aggregates llm_output to None (confirmed against a real
    streaming ChatOpenAI call — LangChain's default _combine_llm_outputs,
    and ChatOpenAI's override, both skip None per-chunk outputs, which
    streaming chunks are). model_name must still come from the per-message
    response_metadata, which streaming does populate — not "" (which the
    platform's schema rejects, min_length=1)."""
    handler = HexgateUsageCallbackHandler(agent_name="my-agent", api_key="k")
    message = AIMessage(
        content="hi",
        usage_metadata={"input_tokens": 1, "output_tokens": 8, "total_tokens": 9},
        response_metadata={"model_name": "gpt-4o-mini", "finish_reason": "stop"},
    )
    response = LLMResult(
        generations=[[ChatGeneration(message=message)]], llm_output=None
    )

    await handler.on_llm_end(response, run_id=uuid4())

    [call] = emitted
    assert call["model"] == "gpt-4o-mini"
    assert call["input_tokens"] == 1
    assert call["output_tokens"] == 8
