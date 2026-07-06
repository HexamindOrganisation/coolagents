from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib import error, request

from hexgate.config.env import resolve_api_key, resolve_api_url
from hexgate.manifest import create_manifest
from hexgate.manifest.models import AgentManifest, AgentType

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

DEFAULT_REGISTER_TIMEOUT = 5.0


def post_manifest(
    manifest: AgentManifest, *, timeout: float = DEFAULT_REGISTER_TIMEOUT
) -> dict:
    """POST a pre-built manifest to ``/v1/agents``. Returns the response dict.

    Split out from :func:`register_agent` so callers (e.g. ``hexgate
    serve``'s auto-register flow) can build the manifest themselves —
    inspect it, log its name, then ship it.
    """
    api_key = resolve_api_key()
    if api_key is None:
        raise ValueError("HEXGATE_API_KEY must be set")
    api_url = resolve_api_url()

    payload = json.dumps({"manifest": manifest.model_dump()}).encode("utf-8")
    req = request.Request(
        f"{api_url}/v1/agents",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as e:
        raise ValueError(f"Failed to register agent: {e}") from e


def register_agent(
    agent: AgentType,
    *,
    description: str | None = None,
    tools: list[BaseTool] | None = None,
    model: str | None = None,
    system_prompt: str | None = None,
    timeout: float = DEFAULT_REGISTER_TIMEOUT,
) -> dict:
    """Create and register an agent manifest to platform /agents.

    `tools`, `model` and `system_prompt` are only consulted for LangChain graphs —
    every other framework reads them off the agent object directly.
    See `create_manifest` for the dispatch logic.
    """
    manifest = create_manifest(
        agent,
        description=description,
        tools=tools,
        model=model,
        system_prompt=system_prompt,
    )
    return post_manifest(manifest, timeout=timeout)
