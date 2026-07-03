from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field, field_validator

# Hard cap on the serialized system prompt. The dashboard renders the full
# prompt inside a <pre> block; a multi-MB prompt would lock the browser tab.
# 64 KiB is well above any realistic hand-written prompt and still cheap to
# render. Measured in UTF-8 bytes so the limit is meaningful for non-ASCII
# prompts too.
MAX_SYSTEM_PROMPT_BYTES = 64 * 1024
_TRUNCATION_MARKER = "\n\n… [truncated by hexgate register]"

# Enable AgentType type checking, without requiring the agents package to be installed
if TYPE_CHECKING:
    from agents import Agent as OpenAIAgent
    from google.adk.agents import Agent as GoogleAgent
    from langgraph.graph.state import CompiledStateGraph as LangChainAgent
    from pydantic_ai import Agent as PydanticAIAgent

    from hexgate.agents.factory import HexgateAgent as HexgateAgent

    AgentType = (
        OpenAIAgent | GoogleAgent | LangChainAgent | PydanticAIAgent | HexgateAgent
    )
else:
    AgentType = object


class AgentFramework(StrEnum):
    """Enum for the framework of an agent."""

    HEXGATE = "hexgate"
    PYDANTIC_AI = "pydantic-ai"
    LANGCHAIN = "langchain"
    GOOGLE = "google"
    OPENAI = "openai"


class AgentManifest(BaseModel):
    """Schema for the manifest of an agent."""

    name: str = Field(description="The name of the agent")
    description: str | None = Field(
        default=None, description="The description of the agent"
    )
    framework: AgentFramework = Field(description="The framework of the agent")
    model: str | None = Field(
        default=None,
        description=(
            "Human-readable identifier of the LLM the agent runs on, when the "
            "framework exposes it. Best-effort: None for raw LangGraph graphs "
            "and for callable / runtime-resolved models we cannot stringify."
        ),
    )
    system_prompt: str | None = Field(
        default=None,
        description=(
            "Resolved system prompt text, when the framework exposes a static "
            "one. None when the prompt is a callable, dynamically composed, "
            "or otherwise not introspectable at registration time. "
            f"Capped at {MAX_SYSTEM_PROMPT_BYTES // 1024} KiB UTF-8 — anything "
            "longer is truncated with a marker so the dashboard can render "
            "it safely."
        ),
    )
    tools: list[ToolDefinition] = Field(description="The tools of the agent")

    @field_validator("system_prompt")
    @classmethod
    def _cap_system_prompt(cls, value: str | None) -> str | None:
        if value is None:
            return None
        encoded = value.encode("utf-8")
        if len(encoded) <= MAX_SYSTEM_PROMPT_BYTES:
            return value
        # Trim by bytes, then decode-ignore to land on a codepoint boundary
        # without splitting a multi-byte sequence. Reserve room for the marker.
        budget = MAX_SYSTEM_PROMPT_BYTES - len(_TRUNCATION_MARKER.encode("utf-8"))
        head = encoded[:budget].decode("utf-8", errors="ignore")
        return head + _TRUNCATION_MARKER


class ToolDefinition(BaseModel):
    """Schema for a tool definition."""

    name: str = Field(description="The name of the tool")
    description: str = Field(description="The description of the tool")
    input_schema: InputSchema = Field(description="The parameters of the tool")


class InputSchema(BaseModel):
    """Schema for a tool's input parameters."""

    properties: dict[str, InputProperty] = Field(
        description="The properties of the tool"
    )
    required: list[str] = Field(description="The required properties of the tool")


class InputProperty(BaseModel):
    """A single property within a tool's input schema."""

    title: str = Field(description="The title of the property")
    type: str = Field(description="The type of the property")
