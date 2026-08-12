"""Tests for the policy-module store + resolve/check API (docs/adr/R-POL-001).

Covers module CRUD, role bindings, and resolve/check composition over the SDK:
a floor boundary caps refunds for every role, a capability grants them, and a
role selects which capabilities apply. Link failures surface as a 422 on resolve
and as a link-error lint on check (diagnostics-as-data). Fixtures mirror
test_projects.py.
"""

from __future__ import annotations

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
