"""Pytest config shared across the platform-api test suite.

Two session-wide behaviours:

1. Enables the ``X-Dev-User`` test seam by default — production servers
   leave ``HEXGATE_ALLOW_DEV_USER_HEADER`` unset, but every test in this
   package uses the header to assert tenant-isolation and route gating
   without going through a real cookie login. The seam is gated in
   ``hexgate_api.main.require_user`` (which all the cookie-side deps —
   ``require_org_member``, ``require_org_membership``,
   ``require_project_admin`` — chain through) so a deployment that
   forgets to disable it doesn't accidentally expose identity-asserting
   headers.

2. Skips ``@pytest.mark.integration`` tests unless run with
   ``pytest -m integration`` (they require a running ClickHouse).
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config) -> None:  # noqa: ARG001 — pytest hook
    """Flip the X-Dev-User gate on for the entire test session.

    Set early (in pytest_configure, not a fixture) so route-mounting
    code that reads the env at import time sees it. Tests that need
    to verify the prod-safe disabled behaviour can monkeypatch.delenv
    inside the test body.
    """
    os.environ.setdefault("HEXGATE_ALLOW_DEV_USER_HEADER", "1")


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    # Substring, not equality: the user may select integration tests via a
    # compound expression like `-m "integration and not slow"`. If integration
    # is named at all, let pytest's own marker filtering decide what runs.
    if "integration" in config.getoption("-m"):
        return
    skip_integration = pytest.mark.skip(
        reason="opt-in: run with `pytest -m integration` (requires running ClickHouse)"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
