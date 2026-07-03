"""DevOps / infra assistant demo — same agent, role flips the decision.

Built on the Google ADK (``google.adk.agents.Agent``) and run through
Hexgate's :class:`~hexgate.adapters.google.HexgateRunner`, which
enforces the role-aware policy bundle on every tool call. The policy
itself lives on the platform (resolved by agent name, pulled fresh on
each run) — register ``devops_agent`` and author its roles there.

Run it:

    uv run python examples/devops_agent.py

The ``main()`` below sends the SAME prompt as different roles and prints
each outcome. The agent's reasoning never changes — only the policy
pulled for the caller's ``User.role`` does:

    "Scale checkout to 50 replicas in prod."
        operator  → DENY (env constraint `env in ["dev","staging"]`
                          fails — the engine names it verbatim)
        admin     → ALLOW (env bounds lifted; 50 ≤ 200, prod included)

    "Scale checkout to 500 replicas in staging."
        admin     → DENY (replica cap exceeded) — gating on the VALUE
                          of an argument, not just the tool name

    "Delete the prod database."
        operator  → DENY (delete_resource is off-limits)
        admin     → ALLOW (destructive ops are an admin's call)

    "Show me the checkout logs in prod."
        viewer / operator / admin → ALLOW

Roles (escalating ladder: viewer < operator < admin)
----------------------------------------------------
- ``viewer``   — read logs only. No actions.
- ``operator`` — restart + scale freely in dev/staging (cap 10 replicas);
                 blocked in prod, no destructive ops.
- ``admin``    — inherits operator and lifts the env bounds (scale up to
                 200 replicas, prod included); the only role allowed to
                 run destructive delete_resource ops.
- ``default``  — fail-closed fallback; nothing is allowed.

The role-aware policy bundle lives on the platform (resolved by agent
name); ``examples/devops_policy.yaml`` is the source to paste into the
policy editor.

Tool layout
-----------
- ``read_logs``         — read a service's logs (the only thing viewer sees)
- ``restart_service``   — restart a service (operator+ in dev/staging)
- ``scale_deployment``  — scale; gated on the replica count AND the env
- ``delete_resource``   — destructive; admin only (denied for the rest)
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.genai import types

from hexgate.adapters.google import HexgateRunner
from hexgate.runtime import User


# ---------------------------------------------------------------------------
# Tools — stubs in place of real implementations. Replace the bodies once the
# policy + roles round-trip looks right on the platform.
# ---------------------------------------------------------------------------


def read_logs(service: str, env: str) -> str:
    """Return the most recent log lines for `service` in environment `env`.

    `env` is one of "dev", "staging", "prod".
    """
    return (
        f"(stub) {service}@{env} last 3 lines:\n"
        f"  12:01:04 INFO  request id=ab12 status=200 latency=42ms\n"
        f"  12:01:05 WARN  upstream payments slow (peer=2)\n"
        f"  12:01:06 INFO  request id=ab13 status=200 latency=51ms"
    )


def restart_service(service: str, env: str) -> str:
    """Restart `service` in environment `env` (one of dev/staging/prod)."""
    return f"(stub) restarted {service}@{env} → rollout OPS-2210 complete"


def scale_deployment(service: str, replicas: int, env: str) -> str:
    """Scale `service` to `replicas` pods in environment `env`.

    `replicas` is an integer; `env` is one of dev/staging/prod. The policy
    gates this on BOTH the replica count (a per-role cap) and the env, so
    the same call can pass for one role and fail for another.
    """
    return f"(stub) scaled {service}@{env} to {replicas} replicas → OPS-2211"


def delete_resource(name: str, env: str) -> str:
    """Permanently delete resource `name` in environment `env`.

    Destructive and irreversible — the policy allows it only for the
    highest-privilege role and denies it outright for everyone else.
    """
    return f"(stub) deleted {name}@{env} → OPS-2212"


# ---------------------------------------------------------------------------
# The agent. One definition; the role lives on the User passed at run time.
# ---------------------------------------------------------------------------


agent = Agent(
    name="devops_agent",
    model=LiteLlm(model="openai/gpt-4o"),
    instruction=(
        "You are a DevOps assistant operating a Kubernetes platform. Help "
        "authorized engineers read service logs, restart services, scale "
        "deployments, and delete resources. Map the user's request to the "
        "right tool, pulling the service/resource name, the replica count, "
        "and the environment (one of dev/staging/prod) straight from their "
        "message. You normally do not need to ask the user to confirm "
        "before invoking a tool — act directly on the details given rather "
        "than echoing them back for approval. The policy layer is what "
        "gates sensitive actions, so trust it to stop anything you're not "
        "allowed to do. Always respond in the same language as the user's "
        "message."
    ),
    tools=[
        read_logs,
        restart_service,
        scale_deployment,
        delete_resource,
    ],
)


# ---------------------------------------------------------------------------
# Demo: same prompt, the role changes the outcome. Each role gets a fresh
# session so the runs stay isolated.
#   uv run python examples/devops_agent.py
# ---------------------------------------------------------------------------


_APP_NAME = "devops_agent_demo"


async def _run_as(role: str, prompt: str) -> None:
    user = User(
        user_id=f"engineer_{role}",
        session_id=f"session_{role}",
        role=role,
    )

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

    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    print(f"\n=== role={role} :: {prompt!r} ===")
    async for event in runner.run_async(new_message=message, user=user):
        if event.is_final_response():
            print(event.content.parts[0].text)


async def main() -> None:
    load_dotenv()

    # Same scale prompt, two roles — env bounds flip the decision.
    await _run_as("operator", "Passe le service checkout à 50 réplicas en prod.")
    await _run_as("admin", "Passe le service checkout à 50 réplicas en prod.")

    # Even with env bounds lifted, the replica-count cap still bites.
    await _run_as("admin", "Passe le service checkout à 500 réplicas en staging.")

    # Destructive op: denied outright vs. allowed for the admin.
    await _run_as("operator", "Supprime la base de données de prod.")
    await _run_as("admin", "Supprime la base de données de prod.")

    # Read path is open to everyone with a role.
    await _run_as("viewer", "Montre-moi les logs du service checkout en prod.")


if __name__ == "__main__":
    asyncio.run(main())
