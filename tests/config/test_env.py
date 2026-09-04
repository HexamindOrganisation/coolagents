import pytest

from hexgate.config.env import (
    DEFAULT_API_URL,
    resolve_api_key,
    resolve_api_url,
    resolve_otlp_endpoint,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HEXGATE_API_KEY", raising=False)
    monkeypatch.delenv("HEXGATE_API_URL", raising=False)
    monkeypatch.delenv("HEXGATE_OTLP_ENDPOINT", raising=False)


def test_explicit_arg_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "from-env")
    assert resolve_api_key("explicit") == "explicit"


def test_reads_primary_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_KEY", "primary")
    assert resolve_api_key() == "primary"


def test_returns_none_when_unset() -> None:
    assert resolve_api_key() is None


def test_url_explicit_arg_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "http://from-env")
    assert resolve_api_url("http://explicit") == "http://explicit"


def test_url_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "http://localhost:8000")
    assert resolve_api_url() == "http://localhost:8000"


def test_url_defaults_when_unset() -> None:
    assert resolve_api_url() == DEFAULT_API_URL


def test_url_empty_string_falls_back_to_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "")
    assert resolve_api_url() == DEFAULT_API_URL


def test_url_strips_trailing_slash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "http://localhost:8000/")
    assert resolve_api_url() == "http://localhost:8000"


def test_otlp_endpoint_happy_path() -> None:
    """Unset: the Collector is assumed to sit behind the API URL."""
    assert resolve_otlp_endpoint() == f"{DEFAULT_API_URL}/v1/traces"


def test_otlp_endpoint_when_env_set_then_it_wins_over_api_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "http://api:8000")
    monkeypatch.setenv("HEXGATE_OTLP_ENDPOINT", "http://collector:4318/v1/traces")
    assert resolve_otlp_endpoint() == "http://collector:4318/v1/traces"


def test_otlp_endpoint_when_explicit_arg_then_it_wins_over_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_OTLP_ENDPOINT", "http://from-env/v1/traces")
    assert (
        resolve_otlp_endpoint("http://explicit/v1/traces")
        == "http://explicit/v1/traces"
    )


def test_otlp_endpoint_when_base_url_given_then_it_is_used_for_the_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_API_URL", "http://from-env")
    assert (
        resolve_otlp_endpoint(base_url="http://explicit/")
        == "http://explicit/v1/traces"
    )


def test_otlp_endpoint_when_env_empty_then_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HEXGATE_OTLP_ENDPOINT", "")
    monkeypatch.setenv("HEXGATE_API_URL", "http://localhost:8000")
    assert resolve_otlp_endpoint() == "http://localhost:8000/v1/traces"
