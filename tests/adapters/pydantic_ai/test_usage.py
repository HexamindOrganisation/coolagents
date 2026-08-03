"""Tests for emit_run_usage's usage extraction from pydantic_ai run results."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage

from hexgate.adapters.pydantic_ai import usage as usage_mod
from hexgate.adapters.pydantic_ai.usage import emit_run_usage


class _FakeResult:
    """Minimal stand-in for AgentRunResult/StreamedRunResult/AgentRun."""

    def __init__(
        self, *, input_tokens: int = 10, output_tokens: int = 20, response: Any = None
    ) -> None:
        self._usage = RunUsage(input_tokens=input_tokens, output_tokens=output_tokens)
        self.response = response

    def usage(self) -> RunUsage:
        return self._usage


class _FakePropertyResult(_FakeResult):
    """usage exposed as a property — pydantic_ai 2.x form (RunUsage, non-callable)."""

    @property
    def usage(self) -> RunUsage:  # type: ignore[override]
        return self._usage


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


def test_emit_run_usage_reads_model_from_response_when_available(
    emitted: list[dict[str, Any]],
) -> None:
    """The run's actual response model wins over the agent's static config
    — pydantic_ai supports per-call model overrides."""
    agent = Agent(model=TestModel())  # agent's own model would be "test"
    response = SimpleNamespace(model_name="gpt-4o")
    result = _FakeResult(input_tokens=10, output_tokens=20, response=response)

    emit_run_usage("my-agent", agent, result, api_key="k")

    [call] = emitted
    assert call == {
        "agent_name": "my-agent",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 20,
        "api_key": "k",
    }


def test_when_emit_llm_usage_fails_then_agent_does_not_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raising_emit(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(usage_mod, "emit_llm_usage", raising_emit)
    agent = Agent(model=TestModel())
    response = SimpleNamespace(model_name="gpt-4o")
    result = _FakeResult(input_tokens=10, output_tokens=20, response=response)

    # Must not raise — called inline before returning the result to the
    # caller, so an unhandled exception here would fail a completed run.
    emit_run_usage("my-agent", agent, result, api_key="k")


def test_emit_run_usage_falls_back_to_agent_model_when_response_has_no_model_name(
    emitted: list[dict[str, Any]],
) -> None:
    agent = Agent(model=TestModel())
    result = _FakeResult(response=SimpleNamespace(model_name=None))

    emit_run_usage("my-agent", agent, result, api_key="k")

    [call] = emitted
    assert call["model"] == "test"


def test_emit_run_usage_falls_back_to_agent_model_when_response_is_none(
    emitted: list[dict[str, Any]],
) -> None:
    agent = Agent(model="some-model", defer_model_check=True)
    result = _FakeResult(response=None)

    emit_run_usage("my-agent", agent, result, api_key="k")

    [call] = emitted
    assert call["model"] == "some-model"


def test_emit_run_usage_when_agent_has_no_model_then_model_is_empty(
    emitted: list[dict[str, Any]],
) -> None:
    agent = Agent()  # no model configured at all
    result = _FakeResult(response=None)

    emit_run_usage("my-agent", agent, result, api_key="k")

    [call] = emitted
    assert call["model"] == ""


def test_emit_run_usage_handles_usage_exposed_as_property(
    emitted: list[dict[str, Any]],
) -> None:
    """pydantic_ai 2.x exposes usage as a property, not a callable method —
    both forms must resolve without raising."""
    agent = Agent(model=TestModel())
    response = SimpleNamespace(model_name="gpt-4o")
    result = _FakePropertyResult(input_tokens=10, output_tokens=20, response=response)

    emit_run_usage("my-agent", agent, result, api_key="k")

    [call] = emitted
    assert call == {
        "agent_name": "my-agent",
        "model": "gpt-4o",
        "input_tokens": 10,
        "output_tokens": 20,
        "api_key": "k",
    }
