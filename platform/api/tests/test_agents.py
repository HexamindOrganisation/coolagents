"""Tests for the inline-roles policy shape on the platform API.

After phase 4c-A the per-agent storage collapsed to three string columns —
``agent_yaml``, ``policy_yaml``, ``system_md``. Role bundles live inline
under a top-level ``roles:`` key in ``policy_yaml`` rather than in a
separate ``roles_json`` column. These tests cover the new shape:

  * seeded support_bot's policy.yaml carries inline roles
  * GET / list / PUT round-trip the three string fields cleanly
  * /validate accepts a single policy_yaml document (flat or inline-roles)
    and surfaces YAML / schema / constraint errors with role attribution
"""

from __future__ import annotations

import shutil

import pytest
import pytest_asyncio
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api import main
from hexgate_api.main import app
from hexgate_api.services import (
    DEFAULT_PROJECT_ID,
    DEFAULT_USER_ID,
    ensure_default_project,
)


@pytest_asyncio.fixture
async def session_factory():
    """A fresh in-memory async engine + session factory.

    StaticPool keeps every Session bound to the same connection — otherwise
    each :memory: handle gets its own private DB and the tables vanish.
    Returns the factory so tests + the client fixture can both build
    sessions against the same in-memory DB.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as bootstrap:
        await ensure_default_project(bootstrap)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def client(session_factory, tmp_path) -> TestClient:
    """TestClient that routes ``get_session`` through the shared test factory."""
    from hexgate_api.core.keystore import FileKeyStore

    async def override_session():
        async with session_factory() as session:
            yield session

    # Endpoints depend on core.db.get_session; override that shared object.
    from hexgate_api.core.db import get_session

    app.dependency_overrides[get_session] = override_session
    # PUT /agents now compiles + signs the policy bundle, so the endpoint
    # needs an initialised keystore. The fixture doesn't run the app
    # lifespan, so wire up a throwaway temp-dir keystore here and restore
    # the original afterward.
    original_keystore = main.keystore
    main.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    main.keystore.ensure_keypair()
    try:
        # Bake the dev-user header into every request so M3 Phase 2's
        # require_org_member dependency lets these tests through. The
        # default seed user is a member of support-bot's org.
        yield TestClient(app, headers={"X-Dev-User": DEFAULT_USER_ID})
    finally:
        app.dependency_overrides.clear()
        main.keystore = original_keystore


# ---------------------------------------------------------------------------
# Seed shape
# ---------------------------------------------------------------------------


def test_support_bot_policy_carries_inline_roles(client: TestClient) -> None:
    """The seed plants four inline roles inside support_bot's policy.yaml."""
    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot")
    assert resp.status_code == 200
    body = resp.json()
    # Wire format is three string fields — no roles map at the top level.
    assert set(body.keys()) >= {"agent_yaml", "policy_yaml", "system_md"}
    assert "roles" not in body
    # Roles live inline in policy.yaml.
    parsed = yaml.safe_load(body["policy_yaml"])
    assert isinstance(parsed.get("roles"), dict)
    assert set(parsed["roles"].keys()) == {
        "read_only",
        "default",
        "support",
        "billing",
    }
    # The mixin marker survives the round-trip.
    assert parsed["roles"]["read_only"].get("is_mixin") is True


def test_default_agent_policy_stays_flat(client: TestClient) -> None:
    """Legacy seed agents keep the single-policy shape — no ``roles:`` key."""
    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default")
    assert resp.status_code == 200
    parsed = yaml.safe_load(resp.json()["policy_yaml"])
    assert "roles" not in parsed
    assert "tools" in parsed


# ---------------------------------------------------------------------------
# PUT / GET round-trip
# ---------------------------------------------------------------------------


def test_put_agent_updates_policy_yaml(client: TestClient) -> None:
    """PUT updates policy_yaml; subsequent GET reflects the change."""
    new_policy = (
        "version: 1\n"
        "roles:\n"
        "  default:\n"
        "    tools:\n"
        "      refund_order: { mode: allow }\n"
    )
    resp = client.put(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot",
        json={"policy_yaml": new_policy},
    )
    assert resp.status_code == 200
    assert resp.json()["policy_yaml"] == new_policy

    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot")
    assert resp.json()["policy_yaml"] == new_policy


def test_put_agent_partial_update_preserves_other_fields(
    client: TestClient,
) -> None:
    """An update touching one field leaves the others alone."""
    before = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot").json()

    resp = client.put(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot",
        json={"system_md": "Updated prompt."},
    )
    assert resp.status_code == 200
    after = resp.json()
    assert after["system_md"] == "Updated prompt."
    assert after["policy_yaml"] == before["policy_yaml"]
    assert after["agent_yaml"] == before["agent_yaml"]


def test_list_agents_returns_three_string_fields(client: TestClient) -> None:
    """The /agents collection endpoint returns the same three-field shape."""
    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents")
    assert resp.status_code == 200
    for agent in resp.json():
        assert "agent_yaml" in agent
        assert "policy_yaml" in agent
        assert "system_md" in agent
        assert "roles" not in agent


# ---------------------------------------------------------------------------
# /agents/{name}/validate — single-document linter
# ---------------------------------------------------------------------------


def test_validate_inline_roles_clean(client: TestClient) -> None:
    """A well-formed inline-roles document → ok=True, no errors."""
    resp = client.post(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot/validate",
        json={
            "policy_yaml": (
                "version: 1\n"
                "roles:\n"
                "  default:\n"
                "    tools:\n"
                "      refund_order:\n"
                "        mode: allow\n"
                "        constraints:\n"
                "          - args.amount <= 50\n"
            )
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "errors": []}


def test_validate_flat_single_policy_clean(client: TestClient) -> None:
    """A legacy single-policy document also validates."""
    resp = client.post(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default/validate",
        json={
            "policy_yaml": (
                "version: 1\n"
                "default_policy: { mode: deny }\n"
                "tools:\n"
                "  web_search: { mode: allow }\n"
            )
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "errors": []}


def test_validate_reports_yaml_parse_error_with_line(client: TestClient) -> None:
    """A YAML lex error surfaces with the offending line; ``role`` is None."""
    resp = client.post(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot/validate",
        json={"policy_yaml": "tools: [bad: unclosed\n"},
    )
    body = resp.json()
    assert body["ok"] is False
    [err] = body["errors"]
    assert err["role"] is None
    assert err["line"] is not None and err["line"] >= 1
    assert "YAML parse" in err["message"]


def test_validate_reports_constraint_grammar_error_inside_role(
    client: TestClient,
) -> None:
    """An unsupported constraint operator is attributed to its role."""
    resp = client.post(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot/validate",
        json={
            "policy_yaml": (
                "version: 1\n"
                "roles:\n"
                "  billing:\n"
                "    tools:\n"
                "      refund_order:\n"
                "        mode: allow\n"
                "        constraints:\n"
                "          - args.amount ~~ 50\n"
            )
        },
    )
    body = resp.json()
    assert body["ok"] is False
    [err] = body["errors"]
    assert err["role"] == "billing"
    assert "no recognised operator" in err["message"]


def test_validate_accumulates_errors_across_roles(client: TestClient) -> None:
    """Multiple bad roles → multiple diagnostics, one per failure."""
    resp = client.post(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/support_bot/validate",
        json={
            "policy_yaml": (
                "version: 1\n"
                "roles:\n"
                "  good:\n"
                "    tools:\n"
                "      refund_order: { mode: allow }\n"
                "  bad1:\n"
                "    tools:\n"
                "      refund_order:\n"
                "        mode: allow\n"
                "        constraints:\n"
                "          - args.amount %%% 50\n"
                "  bad2:\n"
                "    tools:\n"
                "      refund_order:\n"
                "        mode: allow\n"
                "        constraints:\n"
                "          - args.amount @@@ 50\n"
            )
        },
    )
    body = resp.json()
    assert body["ok"] is False
    roles_with_errors = {e["role"] for e in body["errors"]}
    assert roles_with_errors == {"bad1", "bad2"}


# ---------------------------------------------------------------------------
# GET /agents/manifest — dashboard read path rehydrated from the JSON snapshot
# stored on the latest AgentVersion.manifest (not from joined Tool rows).
# ---------------------------------------------------------------------------


def _sample_manifest(
    name: str,
    *,
    description: str | None = None,
    model: str | None = None,
    system_prompt: str | None = None,
) -> dict:
    """Minimal AgentManifest payload for register_manifest in tests."""
    return {
        "name": name,
        "description": description,
        "framework": "hexgate",
        "model": model,
        "system_prompt": system_prompt,
        "tools": [
            {
                "name": "echo",
                "description": "Repeat back the input.",
                "input_schema": {
                    "properties": {"msg": {"title": "Message", "type": "string"}},
                    "required": ["msg"],
                },
            }
        ],
    }


def test_manifest_endpoint_returns_envelope_for_unregistered_agents(
    client: TestClient,
) -> None:
    """Seeded agents have YAML but no AgentVersion → manifest is null."""
    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/manifest")
    assert resp.status_code == 200
    rows = resp.json()
    by_name = {row["name"]: row for row in rows}
    assert {"default", "support_bot"} <= set(by_name)
    for row in by_name.values():
        assert row["manifest"] is None
        assert row["version"] is None
        assert row["content_hash"] is None


async def test_manifest_endpoint_returns_registered_manifest_with_tools(
    client: TestClient, session_factory
) -> None:
    """After register_manifest, the endpoint surfaces the full manifest."""
    from hexgate_api.schemas import AgentManifest
    from hexgate_api.services import register_manifest

    async with session_factory() as session:
        manifest = AgentManifest.model_validate(
            _sample_manifest("support_bot", description="customer support")
        )
        # ``sign=`` is required from Phase 7 step 1 onward — wire the
        # test keystore through so first-time agents get a real signed
        # bundle (when opa's available) and the starter policy_yaml.
        await register_manifest(
            session, DEFAULT_PROJECT_ID, manifest, sign=main.keystore.sign
        )

    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/manifest")
    row = next(r for r in resp.json() if r["name"] == "support_bot")
    assert row["version"] == 1
    assert row["content_hash"]
    assert row["manifest"]["description"] == "customer support"
    assert [t["name"] for t in row["manifest"]["tools"]] == ["echo"]
    assert row["manifest"]["tools"][0]["input_schema"]["required"] == ["msg"]


async def test_manifest_endpoint_returns_latest_version(
    client: TestClient, session_factory
) -> None:
    """When multiple versions exist, only the highest one is returned."""
    from hexgate_api.schemas import AgentManifest
    from hexgate_api.services import register_manifest

    async with session_factory() as session:
        v1 = AgentManifest.model_validate(_sample_manifest("support_bot"))
        v2 = AgentManifest.model_validate(
            {**_sample_manifest("support_bot"), "description": "v2"}
        )
        # ``sign=`` required from Phase 7 step 1 onward.
        await register_manifest(
            session, DEFAULT_PROJECT_ID, v1, sign=main.keystore.sign
        )
        await register_manifest(
            session, DEFAULT_PROJECT_ID, v2, sign=main.keystore.sign
        )

    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/manifest")
    row = next(r for r in resp.json() if r["name"] == "support_bot")
    assert row["version"] == 2
    assert row["manifest"]["description"] == "v2"


async def test_manifest_endpoint_round_trips_model_and_system_prompt(
    client: TestClient, session_factory
) -> None:
    """The new manifest fields survive register → read."""
    from hexgate_api.schemas import AgentManifest
    from hexgate_api.services import register_manifest

    async with session_factory() as session:
        manifest = AgentManifest.model_validate(
            _sample_manifest(
                "support_bot",
                model="gpt-4o-mini",
                system_prompt="be helpful",
            )
        )
        # ``sign=`` is required from Phase 7 step 1 onward — wire the
        # test keystore through so first-time agents get a real signed
        # bundle (when opa's available) and the starter policy_yaml.
        await register_manifest(
            session, DEFAULT_PROJECT_ID, manifest, sign=main.keystore.sign
        )

    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/manifest")
    row = next(r for r in resp.json() if r["name"] == "support_bot")
    assert row["manifest"]["model"] == "gpt-4o-mini"
    assert row["manifest"]["system_prompt"] == "be helpful"


def test_manifest_endpoint_unregistered_agents_have_no_leakage(
    client: TestClient,
) -> None:
    """Agents without a registered version expose a null manifest body —
    and crucially the sensitive fields (``model`` / ``system_prompt``)
    stay *inside* ``manifest``, never promoted to the envelope. The
    envelope itself carries lightweight metadata (``version``,
    ``content_hash``, ``updated_at``) for the picker; those are not
    leakage.
    """
    resp = client.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/manifest")
    for row in resp.json():
        if row.get("manifest") is None:
            assert row["manifest"] is None
            # The bytes that would leak — model + system prompt — must never
            # appear at the envelope level. They only live inside `manifest`.
            assert "model" not in row
            assert "system_prompt" not in row


def test_register_endpoint_accepts_legacy_shape_without_new_fields(
    client: TestClient,
) -> None:
    """A manifest from an older SDK (no model / system_prompt keys) still 201s.

    Backwards-compat guarantee: when the dashboard ships ahead of every
    deployed SDK, older `hexgate register` calls must keep working against
    the new platform. The new fields are Optional with `None` defaults, so
    Pydantic validation should accept payloads that omit them entirely.
    """
    payload = {
        "manifest": {
            "name": "legacy_agent",
            "description": "registered by an old SDK",
            "framework": "hexgate",
            "tools": [],
        }
    }
    resp = client.post(
        "/v1/agents",
        json=payload,
        headers={"Authorization": "Bearer fake-but-unauthenticated"},
    )
    # The legacy-shape body validates; the request itself fails auth (401)
    # rather than schema validation (422). 422 here would mean we broke
    # backwards compatibility.
    assert resp.status_code != 422, resp.text


# ---------------------------------------------------------------------------
# Phase 6: bearer-only ``GET /v1/agents/{name}`` + ``GET /v1/me/key``
#
# Both routes derive project_id from the bearer token; no project_id in
# the URL. Counterparts of the legacy ``GET /v1/projects/{p}/agents/{n}``
# dual-auth route and the CLI's startup introspection call.
# ---------------------------------------------------------------------------


def _mint_token_for_test(session_factory) -> str:
    """Helper: mint a real biscuit-backed token for the seed project.

    Returns the full ``fty_<env>_<project>_<biscuit>`` envelope so the
    test can drop it into an ``Authorization: Bearer …`` header.
    """
    import asyncio

    from hexgate_api.domains.tokens.service import mint_dev_token

    async def _mint():
        async with session_factory() as session:
            _row, full = await mint_dev_token(
                session,
                DEFAULT_PROJECT_ID,
                name="phase6-test",
                scopes=["read"],
                env="live",
                signing_key_bytes=main.keystore._private_key_bytes(),
            )
            await session.commit()
            return full

    return asyncio.get_event_loop().run_until_complete(_mint())


def test_bearer_get_agent_resolves_project_from_token(
    client: TestClient, session_factory
) -> None:
    """``GET /v1/agents/default`` with a valid bearer → 200 + AgentRead.

    The seed project has a ``default`` agent (created by
    ``ensure_default_project``); the bearer is freshly minted against
    that same project, so the lookup must succeed.
    """
    token = _mint_token_for_test(session_factory)
    r = client.get(
        "/v1/agents/default",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["name"] == "default"
    # Project resolution is implicit — confirm by asserting the response
    # carries the agent's policy_yaml (a non-trivial column the legacy
    # path would surface identically).
    assert "policy_yaml" in body and len(body["policy_yaml"]) > 0


def test_bearer_get_agent_rejects_missing_authorization(
    client: TestClient,
) -> None:
    """No ``Authorization`` header → 401, not a 404 or 422.

    The route's auth gate must fire before the path lookup; otherwise
    an unauthenticated caller could probe agent names by status code
    (404 = doesn't exist, 200 = leaks existence).
    """
    r = client.get("/v1/agents/anything")
    assert r.status_code == 401


def test_bearer_get_agent_returns_304_on_matching_etag(
    client: TestClient, session_factory
) -> None:
    """Conditional GET with the bundle's ETag → 304 Not Modified.

    Mirrors the legacy route's behaviour so the SDK's per-run
    refresh logic keeps working when the bundle hasn't changed. We
    PUT first so a signed bundle exists in the test DB — the fixture
    skips the lifespan's ``backfill_bundles`` step so the seed agent
    starts unsigned.
    """
    # Touch the agent so the platform compiles + signs the bundle. Use
    # the cookie-authed PUT path with the X-Dev-User test seam (already
    # enabled by conftest).
    put = client.put(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default",
        headers={"X-Dev-User": DEFAULT_USER_ID},
        json={"policy_yaml": _trivial_policy_yaml()},
    )
    assert put.status_code == 200, put.text

    token = _mint_token_for_test(session_factory)
    first = client.get(
        "/v1/agents/default",
        headers={"Authorization": f"Bearer {token}"},
    )
    etag = first.headers.get("etag")
    assert etag is not None, first.headers

    second = client.get(
        "/v1/agents/default",
        headers={
            "Authorization": f"Bearer {token}",
            "If-None-Match": etag,
        },
    )
    assert second.status_code == 304


def _trivial_policy_yaml() -> str:
    """A policy that compiles cleanly — enough to trigger bundle signing."""
    return (
        "version: 1\n"
        "name: default\n"
        "rules:\n"
        "  - effect: allow\n"
        "    when:\n"
        "      tool: any\n"
    )


def test_me_key_introspects_token_metadata(client: TestClient, session_factory) -> None:
    """``GET /v1/me/key`` describes the bearer without round-tripping it.

    Returns project_id + env + name + scopes. Doesn't echo the token
    value or any secret material — the bearer authenticates the
    request, the response is metadata only.
    """
    token = _mint_token_for_test(session_factory)
    r = client.get(
        "/v1/me/key",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["project_id"] == DEFAULT_PROJECT_ID
    assert body["env"] == "live"
    assert body["name"] == "phase6-test"
    assert body["scopes"] == ["read"]
    # Defensive: the full envelope must never leak in the body.
    assert token not in r.text


def test_me_key_rejects_missing_bearer(client: TestClient) -> None:
    """No ``Authorization`` header → 401."""
    r = client.get("/v1/me/key")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# Phase 7 step 1: register-time default policy + signed bundle
#
# A brand-new agent registered via POST /v1/agents lands with:
#   - a starter role-aware policy_yaml (4 roles inc. mixin)
#   - a signed WASM bundle (when opa is on PATH)
# Re-registers of an existing agent leave the operator's policy_yaml
# alone — only the AgentVersion snapshot history grows.
# ---------------------------------------------------------------------------


_OPA_AVAILABLE = shutil.which("opa") is not None
_needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


def _register_payload(name: str, tools: list[str]) -> dict:
    """Helper: build the JSON body POST /v1/agents expects."""
    return {
        "manifest": {
            "name": name,
            "description": f"test agent {name}",
            "framework": "langchain",
            "tools": [
                {
                    "name": t,
                    "description": None,
                    "input_schema": {"properties": {}, "required": []},
                }
                for t in tools
            ],
        }
    }


def _load_agent_row(session_factory, project_id: str, name: str):
    """Read an Agent row back out of the test DB via the same session
    factory the route handlers used. Reaches around the API on purpose
    — we want to see what actually got written, not what got returned."""
    import asyncio

    from hexgate_api.models import Agent
    from sqlmodel import select

    async def _fetch():
        async with session_factory() as session:
            return (
                await session.exec(
                    select(Agent).where(
                        Agent.project_id == project_id,
                        Agent.name == name,
                    )
                )
            ).first()

    return asyncio.get_event_loop().run_until_complete(_fetch())


def test_register_first_time_generates_starter_policy_yaml(
    client: TestClient, session_factory
) -> None:
    """First POST /v1/agents for a fresh name populates policy_yaml with
    the four-role starter — not the legacy ``""`` placeholder.

    Doesn't require opa: signing is best-effort, the policy_yaml is
    populated unconditionally.
    """
    token = _mint_token_for_test(session_factory)
    r = client.post(
        "/v1/agents",
        json=_register_payload("phase7_fresh", ["web_search", "write_file", "bash"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text

    agent = _load_agent_row(session_factory, DEFAULT_PROJECT_ID, "phase7_fresh")
    assert agent is not None
    # Must not be the legacy empty default.
    assert agent.policy_yaml != ""
    # Round-trips through the SDK's loader — same code path the
    # SDK runs at every chat turn.
    from hexgate.security import load_policy_set_from_dict

    policy_set = load_policy_set_from_dict(yaml.safe_load(agent.policy_yaml))
    assert sorted(policy_set.roles) == ["admin", "default", "member"]
    # Each bucket landed in the right role:
    assert policy_set.policy_for("admin").tools["web_search"].mode == "allow"
    assert policy_set.policy_for("admin").tools["write_file"].mode == "allow"
    assert (
        policy_set.policy_for("member").tools["write_file"].mode == "approval_required"
    )
    assert policy_set.policy_for("admin").tools["bash"].mode == "approval_required"


@_needs_opa
def test_register_first_time_compiles_signed_bundle(
    client: TestClient, session_factory
) -> None:
    """When opa is available, the new agent ships a signed WASM bundle
    so ``hexgate serve`` runs against the real enforcement engine from
    the first request (not the pydantic fallback)."""
    token = _mint_token_for_test(session_factory)
    r = client.post(
        "/v1/agents",
        json=_register_payload("phase7_signed", ["read_file", "write_file"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201

    agent = _load_agent_row(session_factory, DEFAULT_PROJECT_ID, "phase7_signed")
    assert agent is not None
    # All three bundle columns populated together.
    assert agent.compiled_wasm is not None
    assert agent.bundle_manifest is not None
    assert agent.bundle_signature is not None


def test_register_preserves_operator_edited_policy_on_subsequent_register(
    client: TestClient, session_factory
) -> None:
    """Once the operator edits ``policy_yaml`` (via the dashboard's PUT
    route), re-registering the same agent must NOT clobber those
    edits — only the manifest snapshot grows. Policy belongs to the
    operator after first registration.
    """
    token = _mint_token_for_test(session_factory)
    # First register — establishes the agent + auto-generated policy.
    r1 = client.post(
        "/v1/agents",
        json=_register_payload("phase7_edited", ["read_file"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 201

    # Operator edits the policy via the cookie-auth PUT route.
    edited = "version: 1\nroles:\n  default:\n    default_policy:\n      mode: deny\n"
    put = client.put(
        f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/phase7_edited",
        headers={"X-Dev-User": DEFAULT_USER_ID},
        json={"policy_yaml": edited},
    )
    assert put.status_code == 200, put.text

    # Re-register with the same manifest content → 200 (no-op) or 201
    # with new version. Either way, agent.policy_yaml stays as the
    # operator's edited version.
    r2 = client.post(
        "/v1/agents",
        json=_register_payload("phase7_edited", ["read_file"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code in (200, 201)

    agent = _load_agent_row(session_factory, DEFAULT_PROJECT_ID, "phase7_edited")
    assert agent is not None
    assert agent.policy_yaml == edited


def test_register_with_different_tools_leaves_existing_policy_alone(
    client: TestClient, session_factory
) -> None:
    """An operator who registers an agent, edits the policy, then adds
    a new tool to the manifest and re-registers should NOT see the
    policy regenerated. The new tool will be unmentioned in the
    policy — that's correct, the operator decides how to handle it.
    """
    token = _mint_token_for_test(session_factory)

    # First register with one tool.
    r1 = client.post(
        "/v1/agents",
        json=_register_payload("phase7_toolchurn", ["read_file"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 201
    agent_after_first = _load_agent_row(
        session_factory, DEFAULT_PROJECT_ID, "phase7_toolchurn"
    )
    starter = agent_after_first.policy_yaml
    assert "read_file" in starter

    # Re-register with a manifest that ADDS a new tool. Triggers a
    # new AgentVersion (different content_hash) but must not touch
    # the Agent.policy_yaml.
    r2 = client.post(
        "/v1/agents",
        json=_register_payload("phase7_toolchurn", ["read_file", "write_file"]),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 201  # New version → 201, not 200

    agent_after_second = _load_agent_row(
        session_factory, DEFAULT_PROJECT_ID, "phase7_toolchurn"
    )
    # Policy unchanged — the new tool name doesn't appear because the
    # auto-generation only fires on first create.
    assert agent_after_second.policy_yaml == starter
    assert "write_file" not in agent_after_second.policy_yaml


# ---------------------------------------------------------------------------
# require_project — the SDK bearer-auth gate
#
# Pre-fix, the gate only ran ``find_token_by_secret`` (a plain
# secret-string lookup) — a forged biscuit whose payload happened to
# match a stored secret would pass. The fix routes through
# ``_validate_sdk_token`` first, which adds the signature gate
# ws_require_project already had.
# ---------------------------------------------------------------------------


def test_require_project_rejects_token_with_bad_signature(
    client: TestClient, session_factory
) -> None:
    """A bearer whose envelope decodes but signature doesn't chain to
    the platform's root key → 401, even when the surrounding token
    string is byte-identical to a stored secret.

    Synthesised by minting a valid token, then tampering the last few
    chars of the biscuit b64 payload before sending it. The DB still
    has the original (untampered) secret, so the revocation lookup
    would silently accept the tampered string under the pre-fix
    behaviour. The signature gate now catches it first.
    """
    token = _mint_token_for_test(session_factory)
    # Flip the trailing 4 chars of the biscuit_b64 payload. The
    # envelope is ``fty_<env>_<project>_<biscuit>`` — keep the prefix
    # intact so parse_envelope succeeds, mutate the signed payload so
    # verify_token fails.
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    assert tampered != token  # sanity

    r = client.post(
        "/v1/agents",
        json={
            "manifest": {
                "name": "tampered_test",
                "description": None,
                "framework": "langchain",
                "tools": [],
            }
        },
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert r.status_code == 401, r.text
    assert (
        "signature" in r.json()["detail"].lower()
        or "malformed" in r.json()["detail"].lower()
    )


def test_require_project_accepts_valid_signed_token(
    client: TestClient, session_factory
) -> None:
    """Happy-path sanity check — a freshly-minted token still works
    after the signature gate is added. Guards against the regression
    where adding _validate_sdk_token would over-reject."""
    token = _mint_token_for_test(session_factory)
    r = client.post(
        "/v1/agents",
        json={
            "manifest": {
                "name": "sig_gate_happy_path",
                "description": None,
                "framework": "langchain",
                "tools": [],
            }
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 201, r.text
