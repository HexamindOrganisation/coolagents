"""Tests for Langfuse helpers."""

from __future__ import annotations

import pytest

from hexgate.tracing import langfuse as lf
from hexgate.tracing import langfuse_core as lf_core


class LegacyCallbackHandler:
    """Mimic the older Langfuse callback signature."""

    def __init__(
        self,
        *,
        session_id: str | None = None,
        user_id: str | None = None,
        tags: list[str] | None = None,
    ) -> None:
        """Store callback metadata passed in at construction."""
        self.session_id = session_id
        self.user_id = user_id
        self.tags = tags


class ModernCallbackHandler:
    """Mimic the newer Langfuse callback signature."""

    def __init__(self) -> None:
        """Create a modern callback instance."""
        self.last_trace_id = "trace-123"


class DummyClient:
    """Mimic the Langfuse client used for trace URLs."""

    def __init__(self, should_fail: bool = False) -> None:
        """Configure whether URL lookup should fail."""
        self.should_fail = should_fail
        self.trace_ids: list[str | None] = []

    def get_trace_url(self, *, trace_id: str | None = None) -> str | None:
        """Return a fake trace URL or raise an error."""
        self.trace_ids.append(trace_id)
        if self.should_fail:
            raise RuntimeError("no trace")
        return f"https://langfuse.example/{trace_id or 'current'}"


def test_get_langfuse_handler_supports_legacy_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Construct a callback with legacy constructor arguments when available."""
    monkeypatch.setattr(lf, "CallbackHandler", LegacyCallbackHandler)

    handler = lf.get_langfuse_handler(
        session_id="session-1",
        user_id="user-1",
        tags=["hexgate", "linkup"],
    )

    assert handler.session_id == "session-1"
    assert handler.user_id == "user-1"
    assert handler.tags == ["hexgate", "linkup"]


def test_get_langfuse_handler_supports_modern_signature(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Attach metadata manually for modern callback signatures."""
    monkeypatch.setattr(lf, "CallbackHandler", ModernCallbackHandler)

    handler = lf.get_langfuse_handler(
        session_id="session-1",
        user_id="user-1",
        tags=["hexgate", "linkup"],
    )

    assert handler.langfuse_metadata == {
        "langfuse_session_id": "session-1",
        "langfuse_user_id": "user-1",
        "langfuse_tags": ["hexgate", "linkup"],
    }


def test_get_langfuse_runnable_config_includes_metadata() -> None:
    """Expose metadata in runnable config when present on the handler."""

    class Handler:
        """Provide a tiny handler object with metadata."""

        langfuse_metadata = {
            "langfuse_session_id": "session-1",
            "langfuse_user_id": None,
            "langfuse_tags": ["hexgate"],
        }

    config = lf.get_langfuse_runnable_config(Handler())

    assert len(config["callbacks"]) == 1
    assert config["metadata"] == {
        "langfuse_session_id": "session-1",
        "langfuse_tags": ["hexgate"],
    }


def test_maybe_get_trace_url_uses_handler_trace_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolve the trace URL for the last streamed trace id."""
    client = DummyClient()
    # ``maybe_get_trace_url`` moved from ``langfuse`` to ``langfuse_core`` in
    # the SDK-slimming refactor; the ``langfuse`` module re-exports it for BC.
    # Patch the callee's home so the closure over ``get_client`` picks up the
    # dummy client.
    monkeypatch.setattr(lf_core, "get_client", lambda: client)

    class Handler:
        """Provide a last trace id for lookup."""

        last_trace_id = "trace-123"

    trace_url = lf.maybe_get_trace_url(Handler())

    assert trace_url == "https://langfuse.example/trace-123"
    assert client.trace_ids == ["trace-123"]


def test_maybe_get_trace_url_returns_none_on_client_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Return none when the Langfuse client cannot resolve the trace URL."""
    monkeypatch.setattr(lf_core, "get_client", lambda: DummyClient(should_fail=True))

    assert lf.maybe_get_trace_url() is None
