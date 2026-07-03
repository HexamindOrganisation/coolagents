from __future__ import annotations

from typing import Any

from hexgate.manifest.models import (
    AgentFramework,
    AgentManifest,
    InputProperty,
    InputSchema,
    ToolDefinition,
)

from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph


def create_langchain_manifest(
    graph: CompiledStateGraph,
    tools: list[BaseTool],
    *,
    description: str | None = None,
    model: str | None = None,
    system_prompt: str | None = None,
) -> AgentManifest:
    """Build an AgentManifest from a LangChain/LangGraph agent.

    Tools — and, for the same reason, ``model`` and ``system_prompt`` — are
    passed explicitly because compiled LangGraph graphs do not reliably expose
    these fields after compilation.
    """
    agent_name = getattr(graph, "name", None)
    if agent_name is None:
        raise ValueError(
            "LangChain graph has no name — set a name on the graph so the "
            "manifest can identify it on the platform."
        )
    return AgentManifest(
        name=agent_name,
        description=description,
        framework=AgentFramework.LANGCHAIN,
        model=model,
        system_prompt=system_prompt,
        tools=[_to_tool_definition(t) for t in tools],
    )


def _to_tool_definition(tool: BaseTool) -> ToolDefinition:
    """Convert a LangChain/LangGraph tool to a ToolDefinition."""
    schema = _tool_schema(tool)
    properties = {
        prop_name: InputProperty(
            title=prop.get("title", prop_name),
            type=prop.get("type", "string"),
        )
        for prop_name, prop in schema.get("properties", {}).items()
    }
    return ToolDefinition(
        name=tool.name,
        description=tool.description or "",
        input_schema=InputSchema(
            properties=properties,
            required=list(schema.get("required", [])),
        ),
    )


def _tool_schema(tool: BaseTool) -> dict[str, Any]:
    """Return a JSON schema describing a LangChain tool's arguments."""
    args_schema = tool.args_schema
    if args_schema is None:
        return {}
    if isinstance(args_schema, dict):
        return args_schema
    if hasattr(args_schema, "model_json_schema"):
        return args_schema.model_json_schema()
    return {}
