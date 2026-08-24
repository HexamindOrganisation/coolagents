"""Process-wide configuration. HEXGATE_ env prefix matches existing convention."""

from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_CLICKHOUSE_PASSWORD = "hexgate-dev-password"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="HEXGATE_")

    clickhouse_host: str = "localhost"
    # 8124 matches platform/docker-compose.yml's host-port offset.
    clickhouse_port: int = 8124
    clickhouse_user: str = "hexgate"
    clickhouse_password: str = _DEV_CLICKHOUSE_PASSWORD
    clickhouse_database: str = "hexgate_audit"
    clickhouse_secure: bool = False

    # Span-enricher job (jobs/enricher). Redpanda is Kafka-protocol-compatible,
    # so these feed a stock Kafka client (aiokafka). localhost:9092 is the host
    # listener (platform/docker-compose.yml); in-compose consumers use
    # redpanda:29092. Same env var the collector and create-topics.sh read.
    redpanda_bootstrap_server: str = "localhost:9092"
    redpanda_raw_topic: str = "hexgate.otlp.raw"
    redpanda_dlq_topic: str = "hexgate.otlp.dlq"
    enricher_consumer_group: str = "hexgate-enricher"
    enricher_poll_timeout_ms: int = 1000
    enricher_max_poll_records: int = 500
    enricher_insert_max_backoff_s: float = 30.0

    @model_validator(mode="after")
    def _refuse_dev_password_on_remote_host(self) -> "Settings":
        # The dev default keeps `make clickhouse-up` zero-setup, but pointing
        # it at a remote instance is always a misconfiguration — fail fast.
        if (
            self.clickhouse_password == _DEV_CLICKHOUSE_PASSWORD
            and self.clickhouse_host not in _LOCAL_HOSTS
        ):
            raise ValueError(
                f"clickhouse_host={self.clickhouse_host!r} is non-local but "
                "clickhouse_password is the committed dev default — set "
                "HEXGATE_CLICKHOUSE_PASSWORD to the real credential."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
