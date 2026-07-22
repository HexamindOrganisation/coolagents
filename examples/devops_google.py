import asyncio

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.genai import types

from hexgate.adapters.google import HexgateRunner
from hexgate.runtime import User

INSTRUCTION = (
    "You are a DevOps assistant for a Kubernetes platform. Help engineers read "
    "service logs, restart services, and scale deployments. Pull the service "
    "name, replica count, and environment (dev/staging/prod) from the request "
    "and act directly — the policy layer gates sensitive actions."
)

_APP_NAME = "devops_demo"


def read_logs(service: str, env: str) -> str:
    """Return recent log lines for `service` in `env` (dev/staging/prod)."""
    return f"(stub) {service}@{env}: 200 OK, 200 OK, WARN upstream slow"


def restart_service(service: str, env: str) -> str:
    """Restart `service` in `env`."""
    return f"(stub) restarted {service}@{env}"


def scale_deployment(service: str, replicas: int, env: str) -> str:
    """Scale `service` to `replicas` pods in `env`."""
    return f"(stub) scaled {service}@{env} to {replicas} replicas"


async def main() -> None:
    load_dotenv()

    agent = Agent(
        name="devops_agent",
        model=LiteLlm(model="openai/gpt-4o"),
        instruction=INSTRUCTION,
        tools=[read_logs, restart_service, scale_deployment],
    )

    user = User(user_id="engineer_1", session_id="session_1", role="operator")

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name=_APP_NAME,
        user_id=user.user_id,
        session_id=user.session_id,
    )

    runner = HexgateRunner(
        agent=agent,
        app_name=_APP_NAME,
        session_service=session_service,
    )

    message = types.Content(
        role="user",
        parts=[types.Part(text="Scale the checkout service to 5 replicas in staging.")],
    )

    async for event in runner.run_async(new_message=message, user=user):
        if event.is_final_response():
            print(event.content.parts[0].text)


if __name__ == "__main__":
    asyncio.run(main())
