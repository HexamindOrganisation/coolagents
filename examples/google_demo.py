"""A minimal Google ADK agent with one tool that returns the current time."""

import asyncio
from datetime import datetime
import time

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.genai import types

from hexgate.runtime import HexgateContext
from hexgate.adapters.google import HexgateRunner


def get_weather(city: str) -> str:
    """Get the current weather for a given city."""
    time.sleep(1)
    return f"{city}: sunny, 23°C (feels like 23°C), humidity 50%, wind 10 m/s"


def get_current_time() -> str:
    """Return the current local time as an ISO-8601 string."""
    return datetime.now().isoformat()


async def main():
    agent = Agent(
        name="google_runner_example_agent",
        model=LiteLlm(model="openai/gpt-4o"),
        instruction=(
            "You are a concise assistant. Use the get_current_time and "
            "get_weather tools whenever the user asks about time or date."
        ),
        tools=[get_current_time, get_weather],
    )

    hexgate_context = HexgateContext(
        user_id="google_user_1",
        session_id="google_session_1",
        user_roles=["user"],
    )

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="google_runner_example",
        user_id=hexgate_context.user_id,
        session_id=hexgate_context.session_id,
    )

    runner = HexgateRunner(
        agent=agent,
        app_name="google_runner_example",
        session_service=session_service,
    )

    user_msg = types.Content(
        role="user", parts=[types.Part(text="what is the weather in New Delhi?")]
    )

    async for event in runner.run_async(
        new_message=user_msg, hexgate_context=hexgate_context
    ):
        if event.is_final_response():
            print(event.content.parts[0].text)


if __name__ == "__main__":
    load_dotenv()
    asyncio.run(main())
