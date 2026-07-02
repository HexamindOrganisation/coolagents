"""``db._database_url`` resolution + Postgres URL assembly.

The deploy path supplies only ``HEXGATE_POSTGRES_PASSWORD`` and the app
assembles the URL, percent-encoding the password so a secret containing
reserved chars (``@ : / # ?``) can't corrupt the connection string. These
pin that contract plus the precedence order.
"""

from __future__ import annotations

from urllib.parse import unquote, urlsplit

from hexgate_api.core import db

_PG_VARS = (
    "DATABASE_URL",
    "HEXGATE_POSTGRES_PASSWORD",
    "HEXGATE_POSTGRES_USER",
    "HEXGATE_POSTGRES_HOST",
    "HEXGATE_POSTGRES_PORT",
    "HEXGATE_POSTGRES_DB",
)


def _clear(monkeypatch) -> None:
    for var in _PG_VARS:
        monkeypatch.delenv(var, raising=False)


def test_falls_back_to_sqlite_when_nothing_set(monkeypatch) -> None:
    _clear(monkeypatch)
    assert db._database_url().startswith("sqlite+aiosqlite:///")


def test_explicit_database_url_rewrites_to_asyncpg(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@h:5432/d")
    assert db._database_url() == "postgresql+asyncpg://u:p@h:5432/d"


def test_components_assemble_url_with_defaults(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("HEXGATE_POSTGRES_PASSWORD", "plainpw")
    assert (
        db._database_url()
        == "postgresql+asyncpg://hexgate:plainpw@postgres:5432/hexgate"
    )


def test_special_char_password_is_percent_encoded(monkeypatch) -> None:
    _clear(monkeypatch)
    # A generated secret full of URL-reserved chars — the old verbatim-embed
    # path would have produced a malformed URL and crash-looped the api.
    monkeypatch.setenv("HEXGATE_POSTGRES_PASSWORD", "p@ss:w/rd#?x")
    url = db._database_url()
    parts = urlsplit(url)
    # The authority parses cleanly and the password decodes back to the original.
    assert parts.hostname == "postgres"
    assert parts.port == 5432
    assert parts.username == "hexgate"
    assert unquote(parts.password) == "p@ss:w/rd#?x"
    # The raw (unencoded) secret never appears in the URL string.
    assert "p@ss:w/rd#?x" not in url


def test_explicit_url_wins_over_components(monkeypatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@explicit:5432/d")
    monkeypatch.setenv("HEXGATE_POSTGRES_PASSWORD", "ignored")
    assert urlsplit(db._database_url()).hostname == "explicit"
