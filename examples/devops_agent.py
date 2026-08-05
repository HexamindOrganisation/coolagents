import asyncio

from agents import Agent, function_tool
from dotenv import load_dotenv

from hexgate.adapters.openai import HexgateRunner
from hexgate.runtime import User

INSTRUCTION = (
    "You are a DevOps assistant for a Kubernetes platform. Help engineers read "
    "service logs, restart services, and scale deployments. Pull the service "
    "name, replica count, and environment (dev/staging/prod) from the request "
    "and act directly — the policy layer gates sensitive actions."
)


@function_tool
def read_logs(service: str, env: str) -> str:
    """Return recent log lines for `service` in `env` (dev/staging/prod)."""
    return f"(stub) {service}@{env}: 200 OK, 200 OK, WARN upstream slow"


@function_tool
def restart_service(service: str, env: str) -> str:
    """Restart `service` in `env`."""
    return f"(stub) restarted {service}@{env}"


@function_tool
def scale_deployment(service: str, replicas: int, env: str) -> str:
    """Scale `service` to `replicas` pods in `env`."""
    return f"(stub) scaled {service}@{env} to {replicas} replicas"


agent = Agent(
    name="devops_agent",
    instructions=INSTRUCTION,
    tools=[read_logs, restart_service, scale_deployment],
    model="gpt-4o-mini",
)


async def main() -> None:
    load_dotenv()

    runner = HexgateRunner()
    result = await runner.run(
        agent,
        "Check the logs of the web service in prod, then restart it.",
        user=User(user_id="olivia", session_id="session_1", role="operator"),
    )
    print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
