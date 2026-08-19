"""Provision one disposable demo world's serve token.

Run once per container before (or alongside) the API process. Shares the
container's SQLite file and on-disk keystore with the API, so the minted
``HEXGATE_API_KEY`` verifies against the same signing key the API serves with.

Everything here is idempotent — ``init_db`` + ``ensure_default_seed`` +
``ensure_keypair`` are no-ops on a warm DB, so it's safe to run before
uvicorn (which re-runs them in its lifespan).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# The API runs as `hexgate_api.main:app` with the api dir on sys.path, so
# callers must add platform/api to sys.path before calling in here.

# The gates demo's policy — the single source the dashboard shows/edits and the
# hexkit `docs_agent` binds to. Seeded here (demo-only) rather than in the
# platform's product SEED_AGENTS, so a plain platform boot stays clean.
_GDOCS_POLICY = Path(__file__).resolve().parent / "gates-demo" / "policy.yaml"
_GDOCS_AGENT_NAME = "docs_agent"


async def _seed_gdocs_agent() -> None:
    """Idempotently seed the ``docs_agent`` policy into the default project.

    Opens its OWN session so a seed failure (e.g. a commit-time DB error) can't
    poison the token-mint session — the mint is what the demo actually depends
    on. Mirrors ``ensure_seeded_agents`` for one agent: create the row with
    ``policy_yaml`` from :data:`_GDOCS_POLICY`. No bundle needed — the API's
    ``backfill_bundles`` compiles one at startup if ``opa`` is present, and the
    SDK bind path falls back to the pydantic engine from ``policy_yaml`` if not.
    """
    # NOTE: stdout is the token channel (see __main__) — log to stderr only.
    if not _GDOCS_POLICY.is_file():
        print(
            f"[provision] {_GDOCS_POLICY} missing — skipping docs_agent seed",
            file=sys.stderr,
        )
        return

    from hexgate_api.constants import DEFAULT_PROJECT_ID
    from hexgate_api.core.db import async_session_factory
    from hexgate_api.core.ids import new_id
    from hexgate_api.features.agents.service import get_agent
    from hexgate_api.models import Agent

    async with async_session_factory() as session:
        if await get_agent(session, DEFAULT_PROJECT_ID, _GDOCS_AGENT_NAME) is not None:
            return  # already seeded (warm DB)

        session.add(
            Agent(
                id=new_id(Agent),
                project_id=DEFAULT_PROJECT_ID,
                name=_GDOCS_AGENT_NAME,
                agent_yaml=(
                    "name: docs_agent\nmodel: gpt-4o-mini\n"
                    "system_prompt: system.md\npolicy: policy.yaml\n"
                ),
                policy_yaml=_GDOCS_POLICY.read_text(),
                system_md=(
                    "A Google-Docs assistant whose MCP tools (mcp-gdocs-*) are gated "
                    "by role — analyst < editor < admin. Runs inside hexkit.\n"
                ),
            )
        )
        await session.commit()
    print(
        f"[provision] seeded {_GDOCS_AGENT_NAME} policy for the dashboard",
        file=sys.stderr,
    )


async def _mint() -> str:
    from hexgate_api.constants import DEFAULT_PROJECT_ID
    from hexgate_api.core.db import async_session_factory, init_db
    from hexgate_api.core.keystore import keystore  # same singleton the API uses
    from hexgate_api.features.tokens.service import mint_api_key
    from hexgate_api.seeds.defaults import ensure_default_seed

    await init_db()
    keystore.ensure_keypair()
    async with async_session_factory() as session:
        await ensure_default_seed(session)
        _, full_token = await mint_api_key(
            session,
            DEFAULT_PROJECT_ID,
            name="demo-serve",
            # Same scopes the dashboard's mint UI issues by default — these are
            # what the per-user attenuation flow (`user_attenuation`) needs.
            scopes=["mint_user_token", "read_audit"],
            env="live",
            signing_key_bytes=keystore._private_key_bytes(),
        )

    # Best-effort, in its OWN session (see _seed_gdocs_agent): the gates demo's
    # docs_agent is enrichment for the dashboard/hexkit half. A seed error must
    # NOT take down the token mint above (the core BYOK notebook path).
    try:
        await _seed_gdocs_agent()
    except Exception as exc:  # noqa: BLE001
        print(f"[provision] docs_agent seed skipped: {exc}", file=sys.stderr)
    return full_token


def provision_serve_token() -> str:
    """Return a fresh ``fty_live_...`` HEXGATE_API_KEY scoped to the seeded project."""
    return asyncio.run(_mint())


if __name__ == "__main__":
    # Print the token so a shell caller can capture it: HEXGATE_API_KEY=$(python provision.py)
    sys.stdout.write(provision_serve_token())
