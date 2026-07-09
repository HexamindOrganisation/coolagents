"""Tests for bootstrap helpers."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from hexgate import audit, bootstrap
from hexgate.tracing import _senders


def _stub_dotenv_with_required_keys(
    monkeypatch: pytest.MonkeyPatch, **extra: str
) -> dict[str, Path]:
    """Replace ``load_dotenv`` with a stub that populates the provider keys
    a typical CLI run reads into ``Settings``. Returns a dict the caller can
    inspect for the captured env path."""
    seen: dict[str, Path] = {}

    def fake_load_dotenv(path: Path, override: bool) -> None:
        seen["path"] = path
        # Phase 7: ``override=False`` so the shell wins over .env,
        # matching uvicorn/vite/cargo/npm convention.
        assert override is False
        monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
        monkeypatch.setenv("LINKUP_API_KEY", "linkup-key")
        monkeypatch.setenv("TAVILY_API_KEY", "tavily-key")
        monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "public-key")
        monkeypatch.setenv("LANGFUSE_SECRET_KEY", "secret-key")
        for k, v in extra.items():
            monkeypatch.setenv(k, v)

    monkeypatch.setattr(bootstrap, "load_dotenv", fake_load_dotenv)
    return seen


@pytest.fixture(autouse=True)
def _isolate_audit_and_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Reset audit + the env vars bootstrap touches between tests."""
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv("HEXGATE_LOCAL_POLICY", raising=False)
    monkeypatch.delenv(_senders._LOCAL_MODE_ENV, raising=False)
    yield
    _senders._senders.clear()
    _senders._logged_local_mode_suppressed.clear()


def test_bootstrap_loads_requested_env_file(monkeypatch: pytest.MonkeyPatch) -> None:
    """Load environment values from the requested repo-relative env file."""
    seen = _stub_dotenv_with_required_keys(monkeypatch)

    settings = bootstrap.bootstrap("test.env")

    assert seen["path"] == Path(bootstrap.__file__).parent.parent / "test.env"
    assert settings.langfuse_public_key == "public-key"
    assert settings.langfuse_secret_key == "secret-key"


# ---------------------------------------------------------------------------
# local_only mode — gates audit on the loader side rather than env-only
# ---------------------------------------------------------------------------


def test_local_only_sets_env_var_before_audit_configure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``local_only=True`` must set HEXGATE_LOCAL_MODE BEFORE audit.configure
    runs — otherwise an adapter wrapper re-configuring right after would
    spin up a real sender against a key still in env."""
    _stub_dotenv_with_required_keys(monkeypatch, HEXGATE_API_KEY="key_in_dotenv")

    # Spy: when audit.configure runs, the env var must already be set.
    observed_env: dict[str, str | None] = {}
    real_configure = audit.configure

    def spy_configure(*args, **kwargs):
        observed_env["HEXGATE_LOCAL_MODE"] = os.environ.get(_senders._LOCAL_MODE_ENV)
        return real_configure(*args, **kwargs)

    monkeypatch.setattr(audit, "configure", spy_configure)

    bootstrap.bootstrap("test.env", local_only=True)
    assert observed_env["HEXGATE_LOCAL_MODE"] == "1"
    # Sanity: with the gate on, configure returned None even though a key
    # was in env — registry is empty.
    assert _senders._senders == {}


def test_local_only_false_leaves_env_var_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default ``local_only=False`` must NOT set HEXGATE_LOCAL_MODE —
    ``hexgate serve`` and any other platform-bound caller rely on this."""
    _stub_dotenv_with_required_keys(monkeypatch)
    bootstrap.bootstrap("test.env")  # default
    assert os.environ.get(_senders._LOCAL_MODE_ENV) is None


def test_bootstrap_warns_when_key_and_local_policy_both_set(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Both HEXGATE_API_KEY and HEXGATE_LOCAL_POLICY almost always means a
    dev forgot to clean their env. Log a single WARNING at startup so
    the surprise lands now, not three debug sessions later."""
    _stub_dotenv_with_required_keys(
        monkeypatch,
        HEXGATE_API_KEY="lingering_key",
        HEXGATE_LOCAL_POLICY="/tmp/some-bundle",
    )
    with caplog.at_level(logging.WARNING, logger="hexgate.bootstrap"):
        bootstrap.bootstrap("test.env", local_only=True)
    msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("HEXGATE_API_KEY and HEXGATE_LOCAL_POLICY" in m for m in msgs)


def test_bootstrap_no_warning_when_only_one_set(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Only HEXGATE_LOCAL_POLICY → quiet. The warning fires only on the
    ambiguous combination."""
    _stub_dotenv_with_required_keys(
        monkeypatch, HEXGATE_LOCAL_POLICY="/tmp/some-bundle"
    )
    with caplog.at_level(logging.WARNING, logger="hexgate.bootstrap"):
        bootstrap.bootstrap("test.env", local_only=True)
    msgs = [r.message for r in caplog.records]
    assert not any("HEXGATE_API_KEY and HEXGATE_LOCAL_POLICY" in m for m in msgs)
