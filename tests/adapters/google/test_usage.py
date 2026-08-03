"""Tests for HexgateUsagePlugin's usage extraction from LlmResponse."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

from hexgate.adapters.google import usage as usage_mod
from hexgate.adapters.google.usage import HexgateUsagePlugin


def _context(agent_name: str = "my-agent") -> Any:
    """Minimal duck-typed stand-in for CallbackContext — the hook only
    reads .agent_name, and a real one needs a full InvocationContext."""
    return SimpleNamespace(agent_name=agent_name)


def _response(
    *, prompt_tokens: int | None = 10, candidates_tokens: int | None = 20
) -> LlmResponse:
    return LlmResponse(
        model_version="gemini-2.0-flash",
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=prompt_tokens,
            candidates_token_count=candidates_tokens,
        ),
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
async def test_after_model_callback_emits_usage_from_response(
    emitted: list[dict[str, Any]],
) -> None:
    plugin = HexgateUsagePlugin(api_key="k")

    result = await plugin.after_model_callback(
        callback_context=_context("my-agent"), llm_response=_response()
    )

    assert result is None  # never rewrites the response
    [call] = emitted
    assert call == {
        "agent_name": "my-agent",
        "model": "gemini-2.0-flash",
        "input_tokens": 10,
        "output_tokens": 20,
        "api_key": "k",
    }


@pytest.mark.asyncio
async def test_after_model_callback_does_nothing_when_no_usage_metadata(
    emitted: list[dict[str, Any]],
) -> None:
    plugin = HexgateUsagePlugin(api_key="k")
    response = LlmResponse(model_version="gemini-2.0-flash", usage_metadata=None)

    await plugin.after_model_callback(
        callback_context=_context(), llm_response=response
    )

    assert emitted == []


@pytest.mark.asyncio
async def test_after_model_callback_defaults_missing_token_counts_to_zero(
    emitted: list[dict[str, Any]],
) -> None:
    """usage_metadata present but a count field is None (provider-specific
    gaps) must not crash — reported as 0, not skipped."""
    plugin = HexgateUsagePlugin(api_key="k")
    response = _response(prompt_tokens=None, candidates_tokens=None)

    await plugin.after_model_callback(
        callback_context=_context(), llm_response=response
    )

    [call] = emitted
    assert call["input_tokens"] == 0
    assert call["output_tokens"] == 0
