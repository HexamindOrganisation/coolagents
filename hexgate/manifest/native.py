from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages.system import SystemMessage
from langchain_core.tools import BaseTool, StructuredTool

from hexgate.agents.factory import HexgateAgent
from hexgate.manifest.models import (
    AgentFramework,
    AgentManifest,
    InputProperty,
    InputSchema,
    ToolDefinition,
)


def create_hexgate_manifest(
    agent: HexgateAgent, *, description: str | None = None
) -> AgentManifest:
    """Build an AgentManifest from a Hexgate agent created by `create_agent`."""
    if not agent.name:
        raise ValueError(
            "Hexgate agent has no name — set a name on the HexgateAgent so the "
            "manifest can identify it on the platform."
        )
    return AgentManifest(
        name=agent.name,
        description=description,
        framework=AgentFramework.HEXGATE,
        model=_extract_model(agent.model),
        system_prompt=_extract_system_prompt(agent.system_prompt),
        tools=[_to_tool_definition(t) for t in agent.tools],
    )


def _extract_model(model: str | BaseChatModel | None) -> str | None:
    """Return a human-readable identifier for a HexgateAgent's model.

    ``HexgateAgent.model`` is typed as ``str | BaseChatModel``.
    """
    if model is None:
        return None
    if isinstance(model, str):
        return model or None
    # BaseChatModel expose the model under .model or .model_name
    for attr in ("model", "model_name"):
        value = getattr(model, attr, None)
        if isinstance(value, str) and value:
            return value
    # No introspectable id — return None so content_hash isn't sensitive to
    # SDK class renames. The dashboard renders "—" for the missing field.
    return None


def _extract_system_prompt(prompt: str | SystemMessage | None) -> str | None:
    """Return the system-prompt text from a HexgateAgent's resolved prompt.

    ``create_agent`` resolves file paths to text before constructing the
    agent (see ``load_system_prompt`` in ``agents/factory.py``), so by the
    time we see ``agent.system_prompt`` it's always either a string or a
    ``SystemMessage`` — never a Path."""
    if prompt is None:
        return None
    if isinstance(prompt, str):
        return prompt or None
    content = prompt.content
    if isinstance(content, str):
        return content or None
    # LangChain allows SystemMessage.content to be a list of str/dict parts.
    # Join with a blank line so multi-part prompts read as distinct sections
    # rather than running together — matches what pydantic_ai's extractor does.
    parts = [
        item if isinstance(item, str) else item.get("text", "")
        for item in content
        if isinstance(item, (str, dict))
    ]
    joined = "\n\n".join(p for p in parts if isinstance(p, str) and p)
    return joined or None


def _to_tool_definition(spec: Any) -> ToolDefinition:
    """Convert a hexgate ToolSpec (BaseTool | Callable | dict) to a ToolDefinition."""
    if isinstance(spec, dict):
        return _dict_to_tool_definition(spec)
    tool = spec if isinstance(spec, BaseTool) else StructuredTool.from_function(spec)
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


def _dict_to_tool_definition(spec: dict[str, Any]) -> ToolDefinition:
    """Convert an OpenAI-style tool dict to a ToolDefinition."""
    fn = spec.get("function", spec)
    name = fn.get("name") or "tool"
    description = fn.get("description") or ""
    parameters = fn.get("parameters") or {}
    raw_props = parameters.get("properties", {})
    properties = {
        prop_name: InputProperty(
            title=prop.get("title", prop_name),
            type=prop.get("type", "string"),
        )
        for prop_name, prop in raw_props.items()
    }
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=InputSchema(
            properties=properties,
            required=list(parameters.get("required", [])),
        ),
    )
