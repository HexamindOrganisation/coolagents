"""Plain (non-fixture) helpers for the adapter integration test suite.

Kept separate from ``conftest.py``: nothing here is a pytest fixture or
hook, so none of it benefits from pytest's auto-discovery — every symbol
is imported explicitly wherever it's used, exactly like any other module.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from tests.adapters.conftest import HexgatePlatformEnv

# Shared across all four framework adapters' integration tests, each of
# which appends its own random suffix to build a unique agent_name per run.
AGENT_NAME_PREFIX = "integration_test_agent_"

# Shared across all four framework adapters' integration tests, each of
# which appends its own adapter name to build a per-adapter user_id.
USER_ID_PREFIX = "u-integration-"


def poll_until(
    fetch: Callable[[], Any],
    *,
    timeout: float = 30.0,
    interval: float = 0.5,
    message: str,
) -> Any:
    """Poll ``fetch()`` every ``interval`` seconds until it returns a
    truthy value, then return it.

    ``pytest.fail(message)`` if ``timeout`` seconds elapse first. A real
    wall-clock deadline, not an iteration-count proxy for one — a slow
    individual ``fetch()`` call eats into the budget instead of silently
    extending the total wait past ``timeout``.

    The default is sized for the OTLP pipeline's worst case rather than the
    happy path: the SDK's batch processor delay (cut to 500ms by the
    ``hexgate_platform_env`` fixture) + the Collector's 5s ``batch.timeout``
    + the enricher's 1s Kafka poll + the ClickHouse insert. The old 10s was
    calibrated on the pre-OTel path, where emit() was a direct POST.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = fetch()
        if value:
            return value
        time.sleep(interval)
    pytest.fail(message)


def assert_policy_and_usage_events_landed(
    env: "HexgatePlatformEnv",
    agent_name: str,
    session_id: str,
    tool_name: str,
    *,
    expected_outcome: str = "allow",
) -> None:
    """Poll ClickHouse for the audit row and the usage row a wrapped run produces.

    ``policy_decision`` is the audit trail (the allow/deny outcome);
    ``llm_invocation`` is usage telemetry (SDK usage ingest), a distinct
    concept that happens to land in the same ClickHouse database. Neither
    is written by the process under test: both leave as OTLP spans on the
    exporter's worker thread and cross the Collector, Redpanda and the
    enricher before any row exists — so poll rather than assume they've
    landed the instant the run call returns. Common to all four framework
    adapters' integration tests, which each wrap one ``tool_name``-calling
    agent the same way.
    """
    outcome = poll_until(
        lambda: env.policy_decision_outcome(agent_name, session_id, tool_name),
        message=f"policy_decision row for {tool_name!r} never landed in ClickHouse",
    )
    assert outcome == expected_outcome

    poll_until(
        lambda: env.llm_invocation_count(agent_name, session_id) >= 1,
        message="llm_invocation row never landed in ClickHouse",
    )
