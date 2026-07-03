"""Tavily-backed URL fetch tool."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from hexgate.tools.decorators import agent_tool


def _get_env_or_raise(key: str) -> str:
    """Return an environment variable value or raise when missing."""
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return value


def _truncate_url(url: str, *, max_length: int = 48) -> str:
    """Return a compact display version of a URL."""
    parsed = urlparse(url)
    compact = f"{parsed.netloc}{parsed.path}" if parsed.netloc else url
    if len(compact) <= max_length:
        return compact
    return f"{compact[: max_length - 3]}..."


def _format_fetch_call(arguments: dict[str, object]) -> str:
    """Format a compact label for a fetch invocation."""
    url = arguments.get("url")
    if isinstance(url, str) and url.strip():
        return f"fetching {_truncate_url(url.strip())}"
    return "fetching page"


@agent_tool(
    name="tavily_fetch",
    call_formatter=_format_fetch_call,
    failure_mode="result",
)
async def fetch(
    url: str,
    extract_depth: str = "basic",
) -> dict:
    """Fetch and extract the contents of a specific URL."""
    api_key = _get_env_or_raise("TAVILY_API_KEY")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "urls": url,
        "extract_depth": extract_depth,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://api.tavily.com/extract",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()

    raw = response.json().get("results", [{}])[0]
    content = raw.get("raw_content", "") or ""
    return {
        "url": url,
        "title": raw.get("title"),
        "content": content[:20_000],
    }
