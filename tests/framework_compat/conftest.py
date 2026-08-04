"""Fixtures for the framework version-compatibility suite.

Default mode is **local + offline**: policy resolves from the bundled
``probe_policy.yaml`` via ``HEXGATE_LOCAL_POLICY`` (opa-compiled to WASM),
``HEXGATE_LOCAL_MODE=1`` makes the audit sender inert, and the ban gate
auto-disables whenever ``HEXGATE_LOCAL_POLICY`` is set. So a red result
means "the framework version broke the wrap," never "the platform 404'd."

Set ``HEXGATE_PROBE_MODE=saas`` to instead resolve each ``version-probe-*``
agent from the platform using the ambient ``HEXGATE_API_KEY`` (register the
agent names + policy first — the wrappers fail-loud on a 404).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hexgate.runtime import HexgateContext
from tests.framework_compat import _probe

PROBE_DIR = Path(__file__).parent
PROBE_POLICY = PROBE_DIR / "probe_policy.yaml"

SAAS_MODE = os.environ.get("HEXGATE_PROBE_MODE", "local").strip().lower() == "saas"

# Agent names each probe registers under. In local mode the name is only a
# non-empty lookup key (the local override ignores it); in SaaS mode these
# must exist on the platform with the probe policy attached. Underscores
# only — Google ADK requires agent names to be valid Python identifiers.
AGENT_NAMES = {
    "pydantic": "version_probe_pydantic",
    "openai": "version_probe_openai",
    "google": "version_probe_google",
    "langchain": "version_probe_langchain",
    "deepagents": "version_probe_deepagents",
}


@pytest.fixture(scope="session", autouse=True)
def _probe_environment():
    """Configure the offline local-policy environment (unless SaaS mode)."""
    keys = ("HEXGATE_LOCAL_POLICY", "HEXGATE_LOCAL_MODE", "HEXGATE_API_KEY")
    saved = {k: os.environ.get(k) for k in keys}
    if not SAAS_MODE:
        os.environ["HEXGATE_LOCAL_POLICY"] = str(PROBE_POLICY)
        os.environ["HEXGATE_LOCAL_MODE"] = "1"
        # The wrappers require a truthy key even on the local path; the value
        # is never used for network I/O while local mode is on.
        os.environ.setdefault("HEXGATE_API_KEY", "local-probe-key")
    yield
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture(autouse=True)
def _reset_executions():
    """Clear the tool-execution record around every test."""
    _probe.reset_executions()
    yield
    _probe.reset_executions()


@pytest.fixture
def probe_user() -> HexgateContext:
    """A representative caller; role ``member`` falls back to the default role."""
    return HexgateContext(
        user_id="probe-user", user_roles=["member"], session_id="probe-session"
    )
