"""Tests for the policy-module store + resolve/check API (docs/adr/R-POL-001).

Covers module CRUD, role bindings, and resolve/check composition over the SDK:
a floor boundary caps refunds for every role, a capability grants them, and a
role selects which capabilities apply. Link failures surface as a 422 on resolve
and as a link-error lint on check (diagnostics-as-data). Fixtures mirror
test_projects.py.
"""

from __future__ import annotations

import shutil

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.core import keystore as keystore_mod
from hexgate_api.main import app
from hexgate_api.seeds.defaults import ensure_default_project

BOUNDARY = (
    "default_policy: { mode: allow }\n"
    "tools:\n"
    '  refund_order: { mode: allow, constraints: ["args.amount <= 1000"] }\n'
    "  delete_database: { mode: deny }\n"
)
READ_ONLY = "tools:\n  view_orders: { mode: allow }\n"
PAYMENTS = "tools:\n  refund_order: { mode: allow }\n"


@pytest_asyncio.fixture
async def session_factory():
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
    from hexgate_api.core.db import get_session
    from hexgate_api.core.keystore import FileKeyStore

    async def override_session():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    original_keystore = keystore_mod.keystore
    keystore_mod.keystore = FileKeyStore(base_dir=tmp_path / "keystore")
    keystore_mod.keystore.ensure_keypair()
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        keystore_mod.keystore = original_keystore


def _project(client: TestClient) -> str:
    """Sign up (=> org owner), create a project, return its id."""
    client.post(
        "/v1/auth/register",
        json={"email": "pol@example.com", "password": "correcthorsebattery"},
    )
    client.post(
        "/v1/auth/cookie/login",
        data={"username": "pol@example.com", "password": "correcthorsebattery"},
    )
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "modular"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _put_module(client, pid, tier, path, content) -> None:
    r = client.put(
        f"/v1/projects/{pid}/policy-modules/{tier}/{path}", json={"content": content}
    )
    assert r.status_code == 200, r.text


def _seed_bundle(client, pid) -> None:
    _put_module(client, pid, "boundary", "org_core", BOUNDARY)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)
    _put_module(client, pid, "capability", "payments", PAYMENTS)
    r = client.put(
        f"/v1/projects/{pid}/policy-roles",
        json={
            "roles": {"default": ["read_only"], "billing": ["read_only", "payments"]}
        },
    )
    assert r.status_code == 200, r.text


def test_module_crud_roundtrip(client: TestClient) -> None:
    pid = _project(client)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)
    rows = client.get(f"/v1/projects/{pid}/policy-modules").json()
    assert [(m["tier"], m["path"]) for m in rows] == [("capability", "read_only")]
    assert rows[0]["content_hash"]

    # delete
    assert (
        client.delete(
            f"/v1/projects/{pid}/policy-modules/capability/read_only"
        ).status_code
        == 204
    )
    assert client.get(f"/v1/projects/{pid}/policy-modules").json() == []


def test_nested_path_module(client: TestClient) -> None:
    pid = _project(client)
    _put_module(client, pid, "capability", "team_a/payments", PAYMENTS)
    rows = client.get(f"/v1/projects/{pid}/policy-modules").json()
    assert rows[0]["path"] == "team_a/payments"


def test_resolve_composes_per_role(client: TestClient) -> None:
    pid = _project(client)
    _seed_bundle(client, pid)

    body = client.get(f"/v1/projects/{pid}/policy/resolve").json()
    assert set(body["roles"]) == {"default", "billing"}
    billing = body["roles"]["billing"]["tools"]
    # boundary cap AND the payments grant both land on refund_order.
    assert billing["refund_order"]["mode"] == "allow"
    assert any("amount <= 1000" in c for c in billing["refund_order"]["constraints"])
    assert billing["delete_database"]["mode"] == "deny"  # boundary deny, every role
    # default imports read_only only -> no refund_order grant.
    assert "refund_order" not in body["roles"]["default"]["tools"]


def test_resolve_single_role(client: TestClient) -> None:
    pid = _project(client)
    _seed_bundle(client, pid)
    body = client.get(f"/v1/projects/{pid}/policy/resolve?role=billing").json()
    assert set(body["roles"]) == {"billing"}


def test_check_clean_bundle_is_ok(client: TestClient) -> None:
    pid = _project(client)
    _seed_bundle(client, pid)
    body = client.get(f"/v1/projects/{pid}/policy/check").json()
    assert body["ok"] is True
    assert all(lint["severity"] != "error" for lint in body["lints"])


def test_capability_deny_is_link_error_on_check_and_422_on_resolve(
    client: TestClient,
) -> None:
    pid = _project(client)
    _put_module(client, pid, "capability", "bad", "tools:\n  x: { mode: deny }\n")
    client.put(f"/v1/projects/{pid}/policy-roles", json={"roles": {"default": ["bad"]}})

    check = client.get(f"/v1/projects/{pid}/policy/check").json()
    assert check["ok"] is False
    assert any(lint["code"] == "link-error" for lint in check["lints"])

    assert client.get(f"/v1/projects/{pid}/policy/resolve").status_code == 422


def test_invalid_content_and_tier_are_422(client: TestClient) -> None:
    pid = _project(client)
    # not a policy document
    r = client.put(
        f"/v1/projects/{pid}/policy-modules/capability/x", json={"content": "[1, 2, 3]"}
    )
    assert r.status_code == 422
    # unknown tier
    r = client.put(
        f"/v1/projects/{pid}/policy-modules/bogus/x", json={"content": READ_ONLY}
    )
    assert r.status_code == 422


def test_set_roles_is_idempotent_on_reused_role_name(client: TestClient) -> None:
    """Re-setting roles with a role name that already exists must not 500.
    Wholesale-replace has to emit the DELETEs before the INSERTs or the
    (project_id, role) unique constraint trips on the reused name."""
    pid = _project(client)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)
    r1 = client.put(
        f"/v1/projects/{pid}/policy-roles", json={"roles": {"default": ["read_only"]}}
    )
    assert r1.status_code == 200, r1.text
    r2 = client.put(f"/v1/projects/{pid}/policy-roles", json={"roles": {"default": []}})
    assert r2.status_code == 200, r2.text
    assert client.get(f"/v1/projects/{pid}/policy-roles").json()["roles"] == {
        "default": []
    }


def test_upsert_module_replaces_existing(client: TestClient) -> None:
    pid = _project(client)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)
    first = client.get(f"/v1/projects/{pid}/policy-modules").json()[0]["content_hash"]
    _put_module(
        client, pid, "capability", "read_only", "tools:\n  x: { mode: allow }\n"
    )
    rows = client.get(f"/v1/projects/{pid}/policy-modules").json()
    assert len(rows) == 1  # replaced, not duplicated
    assert rows[0]["content_hash"] != first


def test_no_role_bindings_resolves_all_compose(client: TestClient) -> None:
    # A project with capabilities but no role bindings resolves as one default
    # importing everything (docs/adr/R-POL-001), not fail-closed — so it never
    # looks denied-but-healthy. No test set roles first, on purpose.
    pid = _project(client)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)

    body = client.get(f"/v1/projects/{pid}/policy/resolve").json()
    assert "view_orders" in body["roles"]["default"]["tools"]

    check = client.get(f"/v1/projects/{pid}/policy/check").json()
    assert check["ok"] is True
    # the capability is imported by the synthesized default, so it isn't "unused"
    assert not any(lint["code"] == "unused-capability" for lint in check["lints"])


def test_content_hash_matches_sdk_loader_and_is_format_stable() -> None:
    import yaml as _yaml

    from hexgate.security.module_loader import _canonical_hash

    from hexgate_api.features.policy_modules.service import _content_hash

    a = _content_hash("tools:\n  x: { mode: allow }\n")
    b = _content_hash("tools: {x: {mode: allow}}\n")  # same payload, other formatting
    assert a == b  # hash is over the parsed payload, not the raw text
    # byte-identical to what the SDK's file loader would compute for the module
    assert a == _canonical_hash(_yaml.safe_load("tools:\n  x: { mode: allow }\n"))


# --- 3a-2: compile agent bundles from resolved modules (docs/adr/R-POL-002) ---

needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa not on PATH")


def _dummy_sign(data: bytes) -> bytes:
    return b"sig"


async def _fresh_project_with_agent(
    session, *, policy_yaml="version: 1\n", bundle=None
):
    """A project under the default org with one agent, isolated from the seeded
    default project (which carries seeded agents)."""
    import uuid

    from hexgate_api.constants import DEFAULT_ORG_ID
    from hexgate_api.core.ids import new_id
    from hexgate_api.models import Agent, Project

    proj = Project(
        id=str(uuid.uuid4()), org_id=DEFAULT_ORG_ID, name=f"mod-{uuid.uuid4().hex[:8]}"
    )
    session.add(proj)
    agent = Agent(
        id=new_id(Agent),
        project_id=proj.id,
        name="a1",
        agent_yaml="",
        policy_yaml=policy_yaml,
        system_md="",
    )
    if bundle is not None:
        agent.compiled_wasm, agent.bundle_manifest, agent.bundle_signature = bundle
    session.add(agent)
    await session.commit()
    await session.refresh(proj)
    await session.refresh(agent)
    return proj, agent


async def test_is_modular_flips_on_first_role_binding(session_factory):
    from hexgate_api.features.policy_modules import service as pm

    async with session_factory() as s:
        proj, _ = await _fresh_project_with_agent(s)
        assert await pm.is_modular(s, proj.id) is False
        await pm.set_roles(s, project_id=proj.id, roles={"default": []})
        assert await pm.is_modular(s, proj.id) is True


async def test_resolved_policy_yaml_is_inline_roles_shape(session_factory):
    import yaml

    from hexgate_api.features.policy_modules import service as pm

    async with session_factory() as s:
        proj, _ = await _fresh_project_with_agent(s)
        await pm.upsert_module(
            s,
            project_id=proj.id,
            tier="capability",
            path="read_only",
            content=READ_ONLY,
        )
        await pm.set_roles(
            s,
            project_id=proj.id,
            roles={"default": ["read_only"], "billing": ["read_only"]},
        )
        text = await pm.resolved_policy_yaml(s, proj.id)

    doc = yaml.safe_load(text)
    assert set(doc["roles"]) == {"default", "billing"}
    assert "view_orders" in doc["roles"]["billing"]["tools"]


async def test_bundle_for_agent_routes_by_mode(session_factory, monkeypatch):
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.features.policy_modules import service as pm

    captured: list[str] = []

    def fake_compile(policy_yaml, sign):
        captured.append(policy_yaml)
        return (b"w", "m", b"s")

    monkeypatch.setattr(asvc, "compile_bundle", fake_compile)

    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(s, policy_yaml="version: 1\n")
        # classic: no role bindings -> compile from the agent's own policy_yaml
        await asvc.bundle_for_agent(s, agent, _dummy_sign)
        assert captured[-1] == "version: 1\n"

        # make modular -> compile from the resolved role-keyed policy instead
        await pm.upsert_module(
            s,
            project_id=proj.id,
            tier="capability",
            path="read_only",
            content=READ_ONLY,
        )
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["read_only"]})
        await asvc.bundle_for_agent(s, agent, _dummy_sign)
        assert "roles:" in captured[-1]
        assert "view_orders" in captured[-1]


async def test_recompile_project_fans_out_to_every_agent(session_factory, monkeypatch):
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.core.ids import new_id
    from hexgate_api.features.policy_modules import service as pm
    from hexgate_api.models import Agent

    monkeypatch.setattr(
        asvc, "compile_bundle", lambda py, sign: (b"WASM", "MANI", b"SIG")
    )

    async with session_factory() as s:
        proj, a1 = await _fresh_project_with_agent(s)
        a2 = Agent(
            id=new_id(Agent),
            project_id=proj.id,
            name="a2",
            agent_yaml="",
            policy_yaml="version: 1\n",
            system_md="",
        )
        s.add(a2)
        await s.commit()
        await pm.upsert_module(
            s,
            project_id=proj.id,
            tier="capability",
            path="read_only",
            content=READ_ONLY,
        )
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["read_only"]})

        n = await asvc.recompile_project(s, proj.id, _dummy_sign)
        assert n == 2
        for a in (a1, a2):
            await s.refresh(a)
            assert a.compiled_wasm == b"WASM"


async def test_recompile_project_noop_leaves_bundles_when_unresolvable(session_factory):
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.features.policy_modules import service as pm

    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(
            s, bundle=(b"OLD", "OLDMANI", b"OLDSIG")
        )
        # role imports a capability that doesn't exist -> project won't resolve
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["nonexistent"]})

        n = await asvc.recompile_project(s, proj.id, _dummy_sign)
        assert n == 0
        await s.refresh(agent)
        assert agent.compiled_wasm == b"OLD"  # last-good bundle untouched


def _capture_compile(monkeypatch, ret=(b"w", "m", b"s")):
    import hexgate_api.features.agents.service as asvc

    captured: list[str] = []

    def fake(policy_yaml, sign):
        captured.append(policy_yaml)
        return ret

    monkeypatch.setattr(asvc, "compile_bundle", fake)
    return captured


async def test_classic_project_recompiles_from_policy_yaml(
    session_factory, monkeypatch
):
    import hexgate_api.features.agents.service as asvc

    captured = _capture_compile(monkeypatch)
    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(
            s, policy_yaml="version: 1\n# classic\n"
        )
        # classic: recompile_project rebuilds each agent from its own policy_yaml
        assert await asvc.recompile_project(s, proj.id, _dummy_sign) == 1
        assert captured[-1] == "version: 1\n# classic\n"


async def test_update_agent_does_not_blank_a_modular_bundle_when_unresolvable(
    session_factory,
):
    # R-POL-002 fail-safe: editing an agent while the project's modules don't
    # resolve must leave the last-good bundle enforced, not wipe it.
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.features.policy_modules import service as pm

    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(
            s, bundle=(b"LIVE", "MANI", b"SIG")
        )
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["nonexistent"]})

        updated = await asvc.update_agent(
            s, proj.id, agent.name, system_md="edited", sign=_dummy_sign
        )
        assert updated is not None
        assert updated.compiled_wasm == b"LIVE"  # untouched despite the edit


async def test_modular_to_classic_transition_recompiles_from_policy_yaml(
    session_factory, monkeypatch
):
    # Dropping the last role binding returns the project to classic; agents must
    # recompile from policy_yaml, not keep enforcing the stale resolved bundle.
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.features.policy_modules import service as pm

    captured = _capture_compile(monkeypatch)
    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(
            s, policy_yaml="version: 1\n# classic\n"
        )
        await pm.upsert_module(
            s,
            project_id=proj.id,
            tier="capability",
            path="read_only",
            content=READ_ONLY,
        )
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["read_only"]})
        assert await asvc.recompile_project(s, proj.id, _dummy_sign) == 1
        assert "roles:" in captured[-1]  # modular: compiled from resolved YAML

        await pm.set_roles(s, project_id=proj.id, roles={})  # unbind -> classic
        assert await pm.is_modular(s, proj.id) is False
        assert await asvc.recompile_project(s, proj.id, _dummy_sign) == 1
        assert captured[-1] == "version: 1\n# classic\n"  # back to policy_yaml


@needs_opa
async def test_modular_bundle_matches_compile_of_resolved_yaml(session_factory, client):
    import hexgate_api.features.agents.service as asvc
    from hexgate_api.features.agents.compiler import compile_bundle
    from hexgate_api.features.policy_modules import service as pm

    sign = keystore_mod.keystore.sign
    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(s)
        await pm.upsert_module(
            s,
            project_id=proj.id,
            tier="capability",
            path="read_only",
            content=READ_ONLY,
        )
        await pm.set_roles(s, project_id=proj.id, roles={"default": ["read_only"]})

        got = await asvc.bundle_for_agent(s, agent, sign)
        expected = compile_bundle(await pm.resolved_policy_yaml(s, proj.id), sign)

    assert got is not None and expected is not None
    assert got[0] == expected[0]  # identical wasm bytes -> same enforced policy


async def test_classic_recompile_nulls_bundle_when_policy_fails_to_compile(
    session_factory, monkeypatch
):
    # A classic agent whose own policy_yaml no longer compiles must DROP its
    # stale bundle (fall back to pydantic), never keep serving a wrong one — the
    # Agent.compiled_wasm invariant, and the worst case after a modular->classic
    # unbind. (The other recompile tests stub compile to always succeed.)
    import hexgate_api.features.agents.service as asvc

    monkeypatch.setattr(asvc, "compile_bundle", lambda py, sign: None)
    async with session_factory() as s:
        proj, agent = await _fresh_project_with_agent(s, bundle=(b"STALE", "M", b"S"))
        # no role bindings -> classic branch
        n = await asvc.recompile_project(s, proj.id, _dummy_sign)
        assert n == 1
        await s.refresh(agent)
        assert agent.compiled_wasm is None
        assert agent.bundle_manifest is None
        assert agent.bundle_signature is None


def test_identical_role_put_skips_recompile(client: TestClient, monkeypatch) -> None:
    # An idempotent PUT /policy-roles (re-saving the same bindings) must not pay
    # a resolve + opa compile; a real change still recompiles.
    import hexgate_api.features.agents.service as asvc

    calls = {"n": 0}
    real = asvc.recompile_project

    async def spy(session, project_id, sign):
        calls["n"] += 1
        return await real(session, project_id, sign)

    monkeypatch.setattr(asvc, "recompile_project", spy)

    pid = _project(client)
    _put_module(client, pid, "capability", "read_only", READ_ONLY)
    body = {"roles": {"default": ["read_only"]}}
    assert client.put(f"/v1/projects/{pid}/policy-roles", json=body).status_code == 200
    after_change = calls["n"]
    assert after_change >= 1  # a real change recompiled
    # identical re-save -> no recompile
    assert client.put(f"/v1/projects/{pid}/policy-roles", json=body).status_code == 200
    assert calls["n"] == after_change
