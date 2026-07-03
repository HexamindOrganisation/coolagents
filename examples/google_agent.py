"""A minimal Google ADK agent for testing `hexgate register`.

Mirrors the agent constructed inside ``examples/google_demo.py`` but exposes
it at module scope (no runner / session wiring) so the CLI can resolve it as
``examples.google_agent:agent``:

    hexgate register --agent examples.google_agent:agent
"""

import time
from datetime import datetime

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm

from hexgate.cli.register import register_agent


def get_weather(city: str) -> str:
    """Get the current weather for a given city."""
    time.sleep(1)
    return f"{city}: sunny, 23°C (feels like 23°C), humidity 50%, wind 10 m/s"


def get_current_time() -> str:
    """Return the current local time as an ISO-8601 string."""
    return datetime.now().isoformat()

def main():
    load_dotenv()
    agent = Agent(
        name="google_runner_example_agent",
        model=LiteLlm(model="openai/gpt-4o"),
        instruction=(
            "You are a concise assistant. Use the get_current_time and "
            "get_weather tools whenever the user asks about time or date."
        ),
        tools=[get_current_time, get_weather],
    )
    register_agent(agent)

if __name__ == "__main__":
    main()