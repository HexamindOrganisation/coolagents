"""Pydantic AI has no per-call usage hook — usage is read from the run
result after the call completes and reported as one aggregate event per
agent run (not per LLM call), a documented limitation vs. the other three
adapters.
"""

from __future__ import annotations

from typing import Any

from pydantic_ai import Agent

from hexgate.tracing.usage import emit_llm_usage


def _agent_model_name(agent: Agent) -> str:
    """``Agent.model`` is ``None``, a raw ``str`` (only with
    ``defer_model_check=True``), or a resolved ``Model`` instance (the
    common case — the constructor eagerly calls ``infer_model``).
    ``Model.model_name`` is a required abstract property on every concrete
    ``Model``, so it's safe to read once the ``None``/``str`` cases are
    ruled out."""
    model = agent.model
    if model is None:
        return ""
    if isinstance(model, str):
        return model
    return model.model_name


def emit_run_usage(agent_name: str, agent: Agent, result: Any, *, api_key: str) -> None:
    """Emit one aggregate LlmUsageEvent for a completed pydantic_ai run.

    ``result`` is anything exposing ``.usage()`` and ``.response`` —
    ``AgentRunResult``, ``StreamedRunResult``, and ``AgentRun`` (from
    ``run``/``run_sync``, ``run_stream``, and ``iter`` respectively) all
    qualify. Model name comes from the actual run's response when
    available (pydantic_ai supports per-call model overrides), else the
    agent's statically configured model.
    """
    usage = result.usage()
    response = getattr(result, "response", None)
    model_name = getattr(response, "model_name", None) or _agent_model_name(agent)
    emit_llm_usage(
        agent_name,
        model_name,
        usage.input_tokens,
        usage.output_tokens,
        api_key=api_key,
    )
