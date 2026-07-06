"""Linkup-backed web search tool."""

from __future__ import annotations

import os

import httpx

from hexgate.tools.decorators import agent_tool


def _get_env_or_raise(key: str) -> str:
    """Return an environment variable value or raise when missing."""
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {key}")
    return value


def _format_web_search_call(arguments: dict[str, object]) -> str:
    """Format a compact label for a web search invocation."""
    query = arguments.get("query")
    if isinstance(query, str) and query.strip():
        words = query.strip().split()
        preview = " ".join(words[:4])
        if len(words) > 4:
            preview += "..."
        return f"searching {preview}"
    return "searching web"


@agent_tool(
    name="linkup_web_search",
    call_formatter=_format_web_search_call,
    failure_mode="result",
)
async def web_search(
    query: str,
    max_results: int = 8,
    depth: str = "standard",
) -> dict:
    """Search the web for fresh public information using Linkup."""
    url = "https://api.linkup.so/v1/search"
    api_key = _get_env_or_raise("LINKUP_API_KEY")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "q": query,
        "outputType": "searchResults",
        "depth": depth,
    }

    async with httpx.AsyncClient(timeout=45.0) as client:
        response = await client.post(url, headers=headers, json=payload)
        response.raise_for_status()

    results = response.json().get("results", [])
    normalized = [
        {
            "title": result.get("name", ""),
            "url": result.get("url", ""),
            "content": result.get("content", ""),
            "favicon": result.get("favicon"),
        }
        for result in results[:max_results]
    ]
    return {
        "query": query,
        "results": normalized,
    }
