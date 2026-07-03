from __future__ import annotations

from typing import Any

from hexgate.cli.register.models import (
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
    """Convert a Google ADK tool to a ToolDefinition.

    Reads schema from BOTH declaration fields: ``parameters`` (the typed
    ``google.genai.types.Schema`` shape ADK's native ``FunctionTool``
    populates from Python signatures) AND ``parametersJsonSchema`` (the
    raw JSON Schema dict path used by tools that came from a source
    without Python type hints — hexgate's MCP wrapper is the canonical
    case). Without the JSON-Schema fallback, every MCP tool registers
    with an empty argument schema and any policy generated from that
    (write-vs-read classification, arg-level rules) is computed
    against zero fields — silently mis-gated.
    """
    declaration = tool._get_declaration()
    if declaration is None:
        return None

    parameters = declaration.parameters
    if parameters is not None:
        raw_properties: dict[str, Any] = dict(parameters.properties or {})
        properties = {
            prop_name: InputProperty(
                title=prop_name,
                type=_schema_type(prop),
            )
            for prop_name, prop in raw_properties.items()
        }
        required = list(parameters.required or [])
    else:
        properties, required = _properties_from_json_schema(
            declaration.parameters_json_schema
        )

    return ToolDefinition(
        name=tool.name,
        description=tool.description or "",
        input_schema=InputSchema(properties=properties, required=required),
    )


def _properties_from_json_schema(
    schema: Any,
) -> tuple[dict[str, InputProperty], list[str]]:
    """Extract properties + required list from a raw JSON Schema dict.

    Falls back to empty maps when the schema is missing, malformed, or
    doesn't declare object properties. The registered ToolDefinition
    still carries name + description; only the arg surface goes empty.
    """
    if not isinstance(schema, dict):
        return {}, []
    raw_properties = schema.get("properties")
    if not isinstance(raw_properties, dict):
        raw_properties = {}
    properties = {
        prop_name: InputProperty(
            title=prop_name,
            type=_json_schema_prop_type(prop),
        )
        for prop_name, prop in raw_properties.items()
    }
    raw_required = schema.get("required")
    required = (
        [str(r) for r in raw_required if isinstance(r, str)]
        if isinstance(raw_required, list)
        else []
    )
    return properties, required


def _json_schema_prop_type(prop: Any) -> str:
    """Read the ``type`` field off a raw JSON Schema property dict."""
    if isinstance(prop, dict):
        t = prop.get("type")
        if isinstance(t, str):
            return t.lower()
    return "string"


def _schema_type(schema: Any) -> str:
    """Convert a Google ADK Schema's Type enum to a JSON-Schema type string."""
    type_value = getattr(schema, "type", None)
    if type_value is None:
        return "string"
    raw = getattr(type_value, "value", type_value)
    return str(raw).lower()
