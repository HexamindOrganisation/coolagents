"""End-to-end verification that HexgatePydanticAgent.run_sync() delivers
its LLM-usage event even with no asyncio event loop anywhere in the
process — the exact condition AuditSender.emit()'s no-loop fallback
exists for.

Requires: `make clickhouse-up` and `make platform-api` running, and
`HEXGATE_API_KEY` set to a token minted via the dashboard (or the
platform API directly).

Opt in with: `pytest -m integration`.
"""

from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel

from hexgate.adapters.pydantic_ai.wrapper import wrap_pydantic_agent
from hexgate.cli.register.register import register_agent
from hexgate.runtime import User

pytestmark = pytest.mark.integration

PLATFORM_URL = os.environ.get("HEXGATE_API_URL", "http://localhost:8000").rstrip("/")
CLICKHOUSE_URL = os.environ.get("HEXGATE_CLICKHOUSE_URL", "http://localhost:8124")
CLICKHOUSE_USER = os.environ.get("HEXGATE_CLICKHOUSE_USER", "hexgate")
CLICKHOUSE_PASSWORD = os.environ.get(
    "HEXGATE_CLICKHOUSE_PASSWORD", "hexgate-dev-password"
)
TOKEN = os.environ.get("HEXGATE_API_KEY")


def _need_token() -> None:
    if not TOKEN:
        pytest.skip("HEXGATE_API_KEY not set; mint a token via the dashboard")


def _clickhouse_count(agent_name: str, session_id: str) -> int:
    """Parameterized query via ClickHouse's HTTP interface — no string
    interpolation of test-controlled values into SQL."""
    response = httpx.get(
        CLICKHOUSE_URL,
        params={
            "query": (
                "SELECT count() FROM hexgate_audit.llm_invocation "
                "WHERE agent_name = {agent_name:String} "
                "AND session_id = {session_id:String}"
            ),
            "param_agent_name": agent_name,
            "param_session_id": session_id,
        },
        auth=(CLICKHOUSE_USER, CLICKHOUSE_PASSWORD),
        timeout=5,
    )
    response.raise_for_status()
    return int(response.text.strip())


def test_run_sync_with_no_event_loop_delivers_llm_usage_event() -> None:
    """Regression: run_sync(), called from a plain synchronous test with no
    asyncio.run() anywhere, used to silently drop its usage event —
    AuditSender.emit() had no loop to fall back to and just warned once.
    It now delivers via a bounded, non-daemon background thread instead."""
    _need_token()
    os.environ["HEXGATE_API_KEY"] = TOKEN
    os.environ["HEXGATE_API_URL"] = PLATFORM_URL

    agent_name = f"integration_test_agent_{uuid.uuid4().hex[:8]}"
    session_id = f"s-{uuid.uuid4().hex[:8]}"

    raw_agent = Agent(model=TestModel(), name=agent_name)
    register_agent(raw_agent)
    wrapped = wrap_pydantic_agent(agent=raw_agent, api_key=TOKEN)

    user = User(user_id="u-integration", session_id=session_id, role="tester")
    result = wrapped.run_sync("Say hello", user=user)
    assert result.output

    # The send runs on a background thread — poll briefly rather than
    # assuming it's landed the instant run_sync() returns.
    for _ in range(20):
        if _clickhouse_count(agent_name, session_id) == 1:
            return
        time.sleep(0.5)
    pytest.fail("LLM-usage event never landed in ClickHouse")
