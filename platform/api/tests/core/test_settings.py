"""Settings validation — the dev-default-password-on-remote-host guard."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hexgate_api.settings import _DEV_CLICKHOUSE_PASSWORD, Settings


def _settings(**kwargs) -> Settings:
    # _env_file=None so a developer's local .env can't flip test outcomes.
    return Settings(_env_file=None, **kwargs)


def test_local_host_with_dev_password_is_fine() -> None:
    s = _settings(
        clickhouse_host="localhost",
        clickhouse_password=_DEV_CLICKHOUSE_PASSWORD,
    )
    assert s.clickhouse_password == _DEV_CLICKHOUSE_PASSWORD


def test_remote_host_with_dev_password_refused() -> None:
    with pytest.raises(ValidationError, match="dev default"):
        _settings(
            clickhouse_host="clickhouse.prod.internal",
            clickhouse_password=_DEV_CLICKHOUSE_PASSWORD,
        )


def test_remote_host_with_real_password_is_fine() -> None:
    s = _settings(
        clickhouse_host="clickhouse.prod.internal",
        clickhouse_password="s3cret-rotated",
    )
    assert s.clickhouse_host == "clickhouse.prod.internal"
