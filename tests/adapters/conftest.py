"""Shared fixture for the (opt-in) adapter integration test suite — one
live platform + ClickHouse backend, common to all four frameworks.

Centralizes what would otherwise be copy-pasted per adapter: reading
HEXGATE_API_KEY/HEXGATE_API_URL/ClickHouse creds, skipping cleanly when no
key is configured, and querying the audit tables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import httpx
import pytest


@dataclass(frozen=True)
class HexgatePlatformEnv:
    api_key: str
    platform_url: str
    clickhouse_url: str
    clickhouse_user: str
    clickhouse_password: str

    def clickhouse_query(self, query: str, **params: str) -> str:
        """Parameterized query via ClickHouse's HTTP interface — never
        string-interpolate test-controlled values into SQL."""
        response = httpx.get(
            self.clickhouse_url,
            params={"query": query, **{f"param_{k}": v for k, v in params.items()}},
            auth=(self.clickhouse_user, self.clickhouse_password),
            timeout=5,
        )
        response.raise_for_status()
        return response.text.strip()

    def policy_decision_outcome(
        self, agent_name: str, session_id: str, tool_name: str
    ) -> str | None:
        """The most recent policy_decision outcome for this run, or None
        while the row hasn't landed yet."""
        text = self.clickhouse_query(
            "SELECT outcome FROM hexgate_audit.policy_decision "
            "WHERE agent_name = {agent_name:String} "
            "AND session_id = {session_id:String} "
            "AND tool_name = {tool_name:String} "
            "ORDER BY occurred_at DESC LIMIT 1",
            agent_name=agent_name,
            session_id=session_id,
            tool_name=tool_name,
        )
        return text or None

    def llm_invocation_count(self, agent_name: str, session_id: str) -> int:
        text = self.clickhouse_query(
            "SELECT count() FROM hexgate_audit.llm_invocation "
            "WHERE agent_name = {agent_name:String} "
            "AND session_id = {session_id:String}",
            agent_name=agent_name,
            session_id=session_id,
        )
        return int(text)


@pytest.fixture
def hexgate_platform_env(monkeypatch: pytest.MonkeyPatch) -> HexgatePlatformEnv:
    """Skip cleanly if HEXGATE_API_KEY isn't set; otherwise pin
    HEXGATE_API_KEY/HEXGATE_API_URL in os.environ for this test only —
    monkeypatch reverts them afterward, so a value set here can't leak
    into another test the way a bare `os.environ[...] = ...` could — and
    hand back a small client for polling the audit tables.
    """
    api_key = os.environ.get("HEXGATE_API_KEY")
    if not api_key:
        pytest.skip("HEXGATE_API_KEY not set; mint a token via the dashboard")
    platform_url = os.environ.get("HEXGATE_API_URL", "http://localhost:8000").rstrip(
        "/"
    )
    monkeypatch.setenv("HEXGATE_API_KEY", api_key)
    monkeypatch.setenv("HEXGATE_API_URL", platform_url)
    return HexgatePlatformEnv(
        api_key=api_key,
        platform_url=platform_url,
        clickhouse_url=os.environ.get(
            "HEXGATE_CLICKHOUSE_URL", "http://localhost:8124"
        ),
        clickhouse_user=os.environ.get("HEXGATE_CLICKHOUSE_USER", "hexgate"),
        clickhouse_password=os.environ.get(
            "HEXGATE_CLICKHOUSE_PASSWORD", "hexgate-dev-password"
        ),
    )
