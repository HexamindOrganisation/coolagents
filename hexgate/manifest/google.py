from __future__ import annotations

from typing import Any

from hexgate.manifest.models import (
    AgentFramework,
    AgentManifest,
    InputProperty,
    InputSchema,
    ToolDefinition,
)

from google.adk.agents import Agent
from google.adk.models.base_llm import BaseLlm
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.function_tool import FunctionTool


def create_google_manifest(
    agent: Agent, *, description: str | None = None
) -> AgentManifest:
    """Build an AgentManifest from a Google ADK agent."""

    tools: list[ToolDefinition] = []
    for entry in agent.tools:
        tool = entry if hasattr(entry, "_get_declaration") else FunctionTool(func=entry)
        definition = _to_tool_definition(tool)
        if definition is not None:
            tools.append(definition)

    # resolve description from agent or provided description
    description = description or agent.description or None

    return AgentManifest(
        name=agent.name,
        description=description,
        framework=AgentFramework.GOOGLE,
        model=_extract_model(agent.model),
        system_prompt=_extract_system_prompt(agent.instruction),
        tools=tools,
    )


def _extract_model(model: str | BaseLlm) -> str | None:
    """Return the model id for a Google ADK agent.

    Returns None when neither the string form nor ``BaseLlm.model``
    yields an identifier — better than baking a Python class name into
    content_hash and making the hash drift on SDK refactors.
    """
    if isinstance(model, str):
        return model or None
    # BaseLlm exposes the model under .model
    name = getattr(model, "model", None)
    if isinstance(name, str) and name:
        return name
    return None


def _extract_system_prompt(instruction: object) -> str | None:
    """Return the static instruction string for a Google ADK agent.

    ``LlmAgent.instruction`` is ``str | InstructionProvider`` where the
    provider form is a callable resolved per invocation. We only snapshot
    the static string variant.
    """
    if isinstance(instruction, str):
        return instruction or None
    return None


def _to_tool_definition(tool: BaseTool) -> ToolDefinition | None:
    """Convert a Google ADK tool to a ToolDefinition."""
    declaration = tool._get_declaration()
    if declaration is None:
        return None

    parameters = declaration.parameters
    raw_properties: dict[str, Any] = (
        dict(parameters.properties or {}) if parameters else {}
    )
    properties = {
        prop_name: InputProperty(
            title=prop_name,
            type=_schema_type(prop),
        )
        for prop_name, prop in raw_properties.items()
    }
    required = list(parameters.required or []) if parameters else []

    return ToolDefinition(
        name=tool.name,
        description=tool.description or "",
        input_schema=InputSchema(properties=properties, required=required),
    )


def _schema_type(schema: Any) -> str:
    """Convert a Google ADK Schema's Type enum to a JSON-Schema type string."""
    type_value = getattr(schema, "type", None)
    if type_value is None:
        return "string"
    raw = getattr(type_value, "value", type_value)
    return str(raw).lower()
