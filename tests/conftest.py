"""Shared pytest fixtures for the hexgate test suite."""

from __future__ import annotations

import os

import pytest

from hexgate.runtime.srt import SrtUnavailableError, ensure_srt_available


def pytest_configure(config: pytest.Config) -> None:
    """Silence Langfuse's background span export when no real project
    credentials are configured.

    ``Langfuse()`` defaults ``tracing_enabled=True`` even with no/empty
    public+secret key, so any ``@observe``-wrapped ``@agent_tool`` call in a
    unit test still queues spans and tries to flush them against the real
    Langfuse host — failing with a 401 that has nothing to do with the test
    itself. Must run in ``pytest_configure`` (before collection), not a
    per-test fixture: whatever first constructs the client during this suite
    does so early enough that a function-scoped ``monkeypatch.setenv`` in an
    autouse fixture is already too late to gate it. Leaves tracing untouched
    when a real key is already in the environment (e.g. `pytest -m
    integration` with `.env` sourced), so that path still exercises the real
    client.
    """
    _ = config
    if not (
        os.environ.get("LANGFUSE_PUBLIC_KEY") and os.environ.get("LANGFUSE_SECRET_KEY")
    ):
        os.environ["LANGFUSE_TRACING_ENABLED"] = "false"


@pytest.fixture
def srt_required() -> None:
    """Skip the test when the `srt` binary is not installed.

    Use for true integration tests that actually spawn `srt`. Pure unit
    tests should mock `ensure_srt_available` and `asyncio.create_subprocess_exec`
    instead so they run anywhere.
    """
    try:
        ensure_srt_available()
    except SrtUnavailableError as error:
        pytest.skip(f"srt not installed; {error}")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip @pytest.mark.integration tests unless run with `pytest -m integration`."""
    if config.getoption("-m") == "integration":
        return
    skip_integration = pytest.mark.skip(
        reason="opt-in: run with `pytest -m integration`"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
