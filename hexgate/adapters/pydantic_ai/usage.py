"""Pydantic AI has no per-call usage hook — usage is read from the run
result after the call completes and reported as one aggregate event per
agent run (not per LLM call), a documented limitation vs. the other three
adapters.
"""

from __future__ import annotations

from typing import Any

from pydantic_ai import Agent

from hexgate.manifest.pydantic_ai import extract_model
from hexgate.tracing.usage import emit_llm_usage


def emit_run_usage(agent_name: str, agent: Agent, result: Any, *, api_key: str) -> None:
    """Emit one aggregate LlmUsageEvent for a completed pydantic_ai run.

    ``result`` is anything exposing usage and ``.response`` —
    ``AgentRunResult``, ``StreamedRunResult``, and ``AgentRun`` (from
    ``run``/``run_sync``, ``run_stream``, and ``iter`` respectively) all
    qualify. Model name comes from the actual run's response when
    available (pydantic_ai supports per-call model overrides), else the
    agent's statically configured model.

    ``usage`` is a callable method in pydantic_ai 1.x but a property in 2.x
    (returning ``RunUsage``); resolve both so a 2.x run doesn't raise
    ``TypeError: 'RunUsage' object is not callable``.
    """
    usage_attr = result.usage
    usage = usage_attr() if callable(usage_attr) else usage_attr
    response = getattr(result, "response", None)
    model_name = (
        getattr(response, "model_name", None) or extract_model(agent.model) or ""
    )
    emit_llm_usage(
        agent_name,
        model_name,
        usage.input_tokens,
        usage.output_tokens,
        api_key=api_key,
    )
