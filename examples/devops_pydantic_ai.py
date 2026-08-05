import asyncio

from dotenv import load_dotenv
from pydantic_ai import Agent

from hexgate.adapters.pydantic_ai import wrap_pydantic_agent
from hexgate.runtime import HexgateContext

INSTRUCTION = (
    "You are a DevOps assistant for a Kubernetes platform. Help engineers read "
    "service logs, restart services, and scale deployments. Pull the service "
    "name, replica count, and environment (dev/staging/prod) from the request "
    "and act directly — the policy layer gates sensitive actions."
)


async def main() -> None:
    load_dotenv()

    agent = Agent("openai:gpt-4o-mini", name="devops_agent", instructions=INSTRUCTION)

    @agent.tool_plain
    def read_logs(service: str, env: str) -> str:
        """Return recent log lines for `service` in `env` (dev/staging/prod)."""
        return f"(stub) {service}@{env}: 200 OK, 200 OK, WARN upstream slow"

    @agent.tool_plain
    def restart_service(service: str, env: str) -> str:
        """Restart `service` in `env`."""
        return f"(stub) restarted {service}@{env}"

    @agent.tool_plain
    def scale_deployment(service: str, replicas: int, env: str) -> str:
        """Scale `service` to `replicas` pods in `env`."""
        return f"(stub) scaled {service}@{env} to {replicas} replicas"

    agent = wrap_pydantic_agent(agent=agent)

    result = await agent.run(
        "Scale the checkout service to 5 replicas in staging.",
        user=HexgateContext(
            user_id="engineer_1", session_id="session_1", user_roles=["operator"]
        ),
    )
    print(result.output)


if __name__ == "__main__":
    asyncio.run(main())
