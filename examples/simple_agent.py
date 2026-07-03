"""A minimal OpenAI Agents SDK agent for testing `hexgate register`."""

from agents import Agent, function_tool


@function_tool
def add(a: int, b: int) -> int:
    """Add two integers and return their sum."""
    return a + b

@function_tool
def subtract(a: int, b: int) -> int:
    """Subtract two integers and return their difference."""
    return a - b

@function_tool
def multiply(a: int, b: int, c: int) -> int:
    """Multiply three integers and return their product."""
    return a * b * c

@function_tool
def divide(a: int, b: int) -> int:
    """Divide two integers and return their quotient."""
    return a / b

agent = Agent(
    name="calculator agent",
    model="gpt-4o-mini",
    instructions="You are a helpful assistant that can add numbers.",
    tools=[add, subtract, multiply],
)
