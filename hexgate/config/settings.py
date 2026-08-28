"""Runtime settings for hexgate."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    """Runtime settings loaded from environment.

    Provider credentials (OpenAI / Linkup / Tavily) are intentionally absent:
    each is consumed lazily by the tool or model provider that reads it
    straight from the environment, and is only required if that piece runs.
    """

    langfuse_public_key: str | None
    langfuse_secret_key: str | None
    langfuse_host: str
    model: str
    search_engine: str

    @classmethod
    def from_env(cls) -> "Settings":
        """Create settings from process environment."""
        return cls(
            langfuse_public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            langfuse_secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            langfuse_host=os.getenv("LANGFUSE_HOST", "https://cloud.langfuse.com"),
            model=os.getenv("HEXGATE_DEFAULT_MODEL", "openai:gpt-5.4"),
            search_engine=os.getenv("HEXGATE_DEFAULT_SEARCH_ENGINE", "linkup"),
        )
