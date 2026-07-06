from __future__ import annotations

from typing import TYPE_CHECKING

from hexgate.agents.factory import HexgateAgent
from hexgate.manifest.models import AgentManifest, AgentType

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


def create_manifest(
    agent: AgentType,
    *,
    description: str | None = None,
    tools: list[BaseTool] | None = None,
    model: object | None = None,
    system_prompt: object | None = None,
) -> AgentManifest:
    """Create an AgentManifest from an Agent.

    `tools` is required and used explicitly only when `agent` is a raw LangChain
    compiled graph, since those graphs do not reliably expose their tool nodes.
    The same is true of `model` and `system_prompt`.

    Framework-specific submodules (and their SDK imports) are loaded lazily so
    callers only import the SDK they actually use.
    """
    if isinstance(agent, HexgateAgent):
        from hexgate.manifest.native import create_hexgate_manifest

        return create_hexgate_manifest(agent, description=description)

    module = type(agent).__module__
    if module == "agents" or module.startswith("agents."):
        from hexgate.manifest.openai import create_openai_manifest

        return create_openai_manifest(agent, description=description)

    if module.startswith("google.adk"):
        from hexgate.manifest.google import create_google_manifest

        return create_google_manifest(agent, description=description)

    if module == "langgraph" or module.startswith("langgraph."):
        from hexgate.manifest.langchain import create_langchain_manifest

        if tools is None:
            raise ValueError(
                "LangChain graphs require `tools` to be passed explicitly to create_manifest()"
            )
        return create_langchain_manifest(
            agent,
            tools,
            description=description,
            model=model,
            system_prompt=system_prompt,
        )

    if module == "pydantic_ai" or module.startswith("pydantic_ai."):
        from hexgate.manifest.pydantic_ai import create_pydantic_ai_manifest

        return create_pydantic_ai_manifest(agent, description=description)

    raise ValueError(f"Unsupported agent type: {type(agent)}")
