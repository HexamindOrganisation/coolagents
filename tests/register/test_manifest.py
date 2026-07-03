from hexgate.manifest import create_manifest
from hexgate.manifest.models import (
    AgentManifest,
    AgentFramework,
    InputProperty,
    InputSchema,
    ToolDefinition,
)
from hexgate.manifest.native import create_hexgate_manifest
from hexgate.manifest.openai import create_openai_manifest
from hexgate.manifest.google import create_google_manifest
from hexgate.manifest.langchain import create_langchain_manifest
from hexgate.manifest.pydantic_ai import create_pydantic_ai_manifest


def test_agent_manifest_schema():
    """Test the schema of the agent manifest."""
    manifest = AgentManifest(
        name="test-agent",
        description="A test agent",
        framework=AgentFramework.HEXGATE,
        tools=[],
    )
    assert manifest.name == "test-agent"
    assert manifest.description == "A test agent"
    assert manifest.framework == AgentFramework.HEXGATE
    assert manifest.tools == []


def test_openai_manifest_schema():
    """Test the schema of the OpenAI manifest."""
    from agents import Agent, function_tool

    @function_tool()
    def example_tool(example_input: str) -> str:
        """A test tool."""
        return f"Hello, {example_input}! This is a test tool."

    agent = Agent(
        name="test-agent",
        instructions="A test agent",
        tools=[example_tool],
    )

    expected_manifest = AgentManifest(
        name="test-agent",
        description="A test agent",
        framework=AgentFramework.OPENAI,
        model=None,
        system_prompt="A test agent",
        tools=[
            ToolDefinition(
                name="example_tool",
                description="A test tool.",
                input_schema=InputSchema(
                    properties={
                        "example_input": InputProperty(
                            title="Example Input",
                            type="string",
                        ),
                    },
                    required=["example_input"],
                ),
            )
        ],
    )
    manifest = create_openai_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest

    manifest = create_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest


def test_google_manifest_schema():
    """Test the schema of the Google ADK manifest."""
    from google.adk.agents import Agent

    def example_tool(example_input: str) -> str:
        """A test tool."""
        return f"Hello, {example_input}! This is a test tool."

    agent = Agent(
        name="test_agent",
        model="gemini-2.0-flash",
        description="A test agent",
        instruction="Greet the user.",
        tools=[example_tool],
    )

    expected_manifest = AgentManifest(
        name="test_agent",
        description="A test agent",
        framework=AgentFramework.GOOGLE,
        model="gemini-2.0-flash",
        system_prompt="Greet the user.",
        tools=[
            ToolDefinition(
                name="example_tool",
                description="A test tool.",
                input_schema=InputSchema(
                    properties={
                        "example_input": InputProperty(
                            title="example_input",
                            type="string",
                        ),
                    },
                    required=["example_input"],
                ),
            )
        ],
    )
    manifest = create_google_manifest(agent)
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest

    manifest = create_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest


def test_pydantic_ai_manifest_schema():
    """Test the schema of the Pydantic AI manifest."""
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    agent = Agent(TestModel(), name="test-agent", description="A test agent")

    @agent.tool_plain
    def example_tool(example_input: str) -> str:
        """A test tool."""
        return f"Hello, {example_input}! This is a test tool."

    expected_manifest = AgentManifest(
        name="test-agent",
        description="A test agent",
        framework=AgentFramework.PYDANTIC_AI,
        model="test",
        system_prompt=None,
        tools=[
            ToolDefinition(
                name="example_tool",
                description="A test tool.",
                input_schema=InputSchema(
                    properties={
                        "example_input": InputProperty(
                            title="example_input",
                            type="string",
                        ),
                    },
                    required=["example_input"],
                ),
            )
        ],
    )
    manifest = create_pydantic_ai_manifest(agent)
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest

    manifest = create_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest


def test_langchain_manifest_schema():
    """Test the schema of the LangChain manifest."""
    from langchain_core.tools import tool
    from langgraph.graph import END, START, StateGraph

    @tool
    def example_tool(example_input: str) -> str:
        """A test tool."""
        return f"Hello, {example_input}! This is a test tool."

    builder = StateGraph(dict)
    builder.add_node("noop", lambda state: state)
    builder.add_edge(START, "noop")
    builder.add_edge("noop", END)
    graph = builder.compile(name="test-agent")

    expected_manifest = AgentManifest(
        name="test-agent",
        description="A test agent",
        framework=AgentFramework.LANGCHAIN,
        model=None,
        system_prompt=None,
        tools=[
            ToolDefinition(
                name="example_tool",
                description="A test tool.",
                input_schema=InputSchema(
                    properties={
                        "example_input": InputProperty(
                            title="Example Input",
                            type="string",
                        ),
                    },
                    required=["example_input"],
                ),
            )
        ],
    )
    manifest = create_langchain_manifest(
        graph,
        [example_tool],
        description="A test agent",
    )
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest

    manifest = create_manifest(graph, tools=[example_tool], description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest


def test_hexgate_manifest_schema():
    """Test the schema of the Hexgate manifest (HexgateAgent from create_agent)."""
    from langchain_core.tools import tool
    from langgraph.graph import END, START, StateGraph

    from hexgate.agents.factory import HexgateAgent

    @tool
    def example_tool(example_input: str) -> str:
        """A test tool."""
        return f"Hello, {example_input}! This is a test tool."

    builder = StateGraph(dict)
    builder.add_node("noop", lambda state: state)
    builder.add_edge(START, "noop")
    builder.add_edge("noop", END)
    graph = builder.compile(name="test-agent")

    agent = HexgateAgent(
        graph=graph,
        model="test-model",
        tools=[example_tool],
        system_prompt=None,
        name="test-agent",
    )

    expected_manifest = AgentManifest(
        name="test-agent",
        description="A test agent",
        framework=AgentFramework.HEXGATE,
        model="test-model",
        system_prompt=None,
        tools=[
            ToolDefinition(
                name="example_tool",
                description="A test tool.",
                input_schema=InputSchema(
                    properties={
                        "example_input": InputProperty(
                            title="Example Input",
                            type="string",
                        ),
                    },
                    required=["example_input"],
                ),
            )
        ],
    )
    manifest = create_hexgate_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest

    manifest = create_manifest(agent, description="A test agent")
    assert isinstance(manifest, AgentManifest)
    assert manifest == expected_manifest


def test_hexgate_manifest_system_message_prompt():
    """SystemMessage system prompts are flattened to their text content."""
    from langchain_core.messages import SystemMessage
    from langgraph.graph import END, START, StateGraph

    from hexgate.agents.factory import HexgateAgent

    builder = StateGraph(dict)
    builder.add_node("noop", lambda state: state)
    builder.add_edge(START, "noop")
    builder.add_edge("noop", END)
    graph = builder.compile(name="sm-agent")

    agent = HexgateAgent(
        graph=graph,
        model="test-model",
        tools=[],
        system_prompt=SystemMessage(content="hi"),
        name="sm-agent",
    )

    manifest = create_hexgate_manifest(agent)
    assert manifest.system_prompt == "hi"
    assert manifest.model == "test-model"


def test_openai_manifest_callable_instructions():
    """Callable ``instructions`` is dropped (no static text to snapshot)."""
    from agents import Agent

    agent = Agent(
        name="callable-agent",
        instructions=lambda *_args, **_kwargs: "ignored",
        tools=[],
    )

    manifest = create_openai_manifest(agent)
    assert manifest.system_prompt is None


def test_langchain_manifest_explicit_model_and_prompt():
    """LangChain kwargs flow through ``create_manifest`` to the manifest."""
    from langgraph.graph import END, START, StateGraph

    builder = StateGraph(dict)
    builder.add_node("noop", lambda state: state)
    builder.add_edge(START, "noop")
    builder.add_edge("noop", END)
    graph = builder.compile(name="lc-agent")

    manifest = create_manifest(
        graph,
        tools=[],
        model="gpt-4o-mini",
        system_prompt="be helpful",
    )
    assert manifest.model == "gpt-4o-mini"
    assert manifest.system_prompt == "be helpful"


def test_pydantic_ai_manifest_static_prompts():
    """Static ``system_prompt`` + ``instructions`` strings are concatenated."""
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    agent = Agent(
        TestModel(),
        name="prompty-agent",
        system_prompt="part one",
        instructions="part two",
    )

    manifest = create_pydantic_ai_manifest(agent)
    assert manifest.system_prompt == "part one\n\npart two"
    assert manifest.model == "test"
