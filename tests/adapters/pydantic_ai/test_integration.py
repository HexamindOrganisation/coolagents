"""End-to-end verification that HexgatePydanticAgent.run_sync() (1) pulls
its policy from the live platform, (2) delivers its LLM-usage event even
with no asyncio event loop anywhere in the process — the sender's span
export runs on its own worker thread, with no loop affinity — and (3) lands
a policy_decision row for its tool call.

Requires the full OTLP ingest pipeline — Postgres, ClickHouse, Redpanda,
`make platform-api-pg`, `make collector-run` and `make enricher-run` — plus
`HEXGATE_API_KEY` set to a token minted against that Postgres-backed API.
`make platform-api` (SQLite) is NOT enough: the Collector authenticates
keys against the `devtoken` table in Postgres. See
.claude/skills/integration-tests for the exact sequence.

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from pydantic_ai.tools import Tool

from hexgate.adapters.pydantic_ai.wrapper import wrap_pydantic_agent
from hexgate.cli.register.register import register_agent
from hexgate.runtime import HexgateContext
from tests.adapters.conftest import HexgatePlatformEnv
from tests.adapters.helpers import (
    AGENT_NAME_PREFIX,
    USER_ID_PREFIX,
    assert_policy_and_usage_events_landed,
)

pytestmark = pytest.mark.integration


def _get_weather(city: str) -> str:
    """A `get_weather`-named tool: a "get_" prefix is a read-shape pattern
    (see `platform/api/hexgate_api/features/agents/compiler.py`'s
    `_READ_PATTERNS`), so a freshly-registered agent's starter policy puts
    it in the `read_only` mixin at `mode: allow` for every role — including
    the `default` role that an unrecognized `user_roles` entry falls back to.
    That makes the expected `policy_decision` outcome deterministic
    ('allow'), not something this test needs to special-case per role.
    """
    return f"{city}: sunny, 21C"


def test_run_sync_with_no_event_loop_delivers_llm_usage_event(
    hexgate_platform_env: HexgatePlatformEnv,
) -> None:
    """Regression: run_sync(), called from a plain synchronous test with no
    asyncio.run() anywhere, used to silently drop its usage event — the
    pre-OTel AuditSender.emit() had no loop to schedule its POST on. The
    span exporter's worker thread has no such dependency.

    The agent carries one tool (`get_weather`) so the run also produces a
    policy_decision row — TestModel's default `call_tools='all'` calls
    every registered tool automatically, no scripted response needed."""
    agent_name = f"{AGENT_NAME_PREFIX}pydantic_ai_{uuid.uuid4().hex[:8]}"
    session_id = f"s-{uuid.uuid4().hex[:8]}"

    raw_agent = Agent(
        model=TestModel(),
        name=agent_name,
        tools=[Tool(_get_weather, name="get_weather")],
    )
    register_agent(raw_agent)
    wrapped = wrap_pydantic_agent(agent=raw_agent, api_key=hexgate_platform_env.api_key)

    context = HexgateContext(
        user_id=f"{USER_ID_PREFIX}pydantic_ai",
        session_id=session_id,
        user_roles=["tester"],
    )
    result = wrapped.run_sync("What's the weather in Paris?", hexgate_context=context)
    assert result.output

    assert_policy_and_usage_events_landed(
        hexgate_platform_env, agent_name, session_id, "get_weather"
    )
