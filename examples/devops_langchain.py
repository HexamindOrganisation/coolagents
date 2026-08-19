import asyncio

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from hexgate.adapters.langchain import wrap_langchain_agent
from hexgate.runtime import HexgateContext

INSTRUCTION = (
    "You are a DevOps assistant for a Kubernetes platform. Help engineers read "
    "service logs, restart services, and scale deployments. Pull the service "
    "name, replica count, and environment (dev/staging/prod) from the request "
    "and act directly — the policy layer gates sensitive actions."
)


@tool
def read_logs(service: str, env: str) -> str:
    """Return recent log lines for `service` in `env` (dev/staging/prod)."""
    return f"(stub) {service}@{env}: 200 OK, 200 OK, WARN upstream slow"


@tool
def restart_service(service: str, env: str) -> str:
    """Restart `service` in `env`."""
    return f"(stub) restarted {service}@{env}"


@tool
def scale_deployment(service: str, replicas: int, env: str) -> str:
    """Scale `service` to `replicas` pods in `env`."""
    return f"(stub) scaled {service}@{env} to {replicas} replicas"


TOOLS = [read_logs, restart_service, scale_deployment]


async def main() -> None:
    load_dotenv()

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    graph = create_react_agent(llm, TOOLS, name="devops_agent", prompt=INSTRUCTION)

    agent = wrap_langchain_agent(agent=graph, tools=TOOLS)

    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Scale the checkout service to 5 replicas in staging.",
                }
            ]
        },
        hexgate_context=HexgateContext(
            user_id="engineer_1", session_id="session_1", user_roles=["operator"]
        ),
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
