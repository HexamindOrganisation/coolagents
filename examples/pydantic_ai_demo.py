import asyncio
from dotenv import load_dotenv
from pydantic_ai import Agent

from hexgate.runtime import HexgateContext
from hexgate.adapters.pydantic_ai import wrap_pydantic_agent


async def main():
    load_dotenv()

    agent = Agent("openai:gpt-4o-mini")

    @agent.tool_plain
    def get_weather(city: str) -> str:
        """Return a weather report for a city."""
        return f"The weather in {city} is 21°C and sunny."

    @agent.tool_plain
    def delete_user(user_id: str) -> str:
        """Delete a user account. Destructive."""
        return f"User {user_id} deleted."

    agent = wrap_pydantic_agent(agent=agent)

    result = await agent.run(
        "What is the weather in Tokyo?",
        hexgate_context=HexgateContext(
            user_id="pydantic_ai_user_1",
            user_roles=["member"],
            session_id="pydantic_ai_session_1",
        ),
    )
    print(result.output)


if __name__ == "__main__":
    asyncio.run(main())
