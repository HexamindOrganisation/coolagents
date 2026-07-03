"""``main._cors_origins`` env parsing.

Unit-tested directly since the middleware reads it once at import time.
"""

from __future__ import annotations

from hexgate_api import main


def test_cors_default_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("HEXGATE_CORS_ORIGINS", raising=False)
    assert main._cors_origins() == ["http://localhost:5173"]


def test_cors_blank_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("HEXGATE_CORS_ORIGINS", "   ")
    assert main._cors_origins() == ["http://localhost:5173"]


def test_cors_single_origin(monkeypatch) -> None:
    monkeypatch.setenv("HEXGATE_CORS_ORIGINS", "https://app.hexgate.ai")
    assert main._cors_origins() == ["https://app.hexgate.ai"]


def test_cors_multi_strips_whitespace_and_trailing_slash(monkeypatch) -> None:
    monkeypatch.setenv("HEXGATE_CORS_ORIGINS", " https://a.com/ , https://b.com ")
    assert main._cors_origins() == ["https://a.com", "https://b.com"]


def test_cors_malformed_commas_only_falls_back(monkeypatch) -> None:
    # Must not silently lock every origin out.
    monkeypatch.setenv("HEXGATE_CORS_ORIGINS", " , ,")
    assert main._cors_origins() == ["http://localhost:5173"]
