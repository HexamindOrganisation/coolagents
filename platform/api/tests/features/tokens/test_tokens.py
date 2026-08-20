"""Tests for the API-key CRUD routes (`/v1/projects/{id}/tokens`).

Covers mint / list / revoke through the actual HTTP router — the existing
suite only ever calls `mint_api_key()` directly as a helper to get a token
for *other* features' tests, so the router itself (and `list_api_keys`)
had no coverage of its own. Fixtures mirror `test_projects.py`.
"""

from __future__ import annotations

from biscuit_auth import AuthorizerBuilder, Rule
from fastapi.testclient import TestClient
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import DEFAULT_PROJECT_ID
from hexgate_api.core import keystore as keystore_mod
from hexgate_api.core.biscuits import parse_envelope, verify_token
from hexgate_api.core.keystore import FileKeyStore
from hexgate_api.features.tokens.service import mint_api_key
from hexgate_api.main import app
from hexgate_api.seeds.defaults import ensure_default_project


# ---------------------------------------------------------------------------
# Fixtures — mirror test_projects.py
# ---------------------------------------------------------------------------


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


def _signup_and_login(client: TestClient, email: str, password: str) -> None:
    """Register + log in; cookie persists on the client for the next call."""
    r = client.post(
        "/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert r.status_code == 201, r.text
    r = client.post(
        "/v1/auth/cookie/login",
        data={"username": email, "password": password},
    )
    assert r.status_code == 204, r.text


def _signup_with_project(client: TestClient, email: str) -> str:
    """Sign up, log in, create a project in the user's default org.

    Returns the project id — every tokens endpoint is project-scoped.
    """
    _signup_and_login(client, email, "correcthorsebattery")
    org_id = client.get("/v1/orgs").json()[0]["id"]
    r = client.post(f"/v1/orgs/{org_id}/projects", json={"name": "tokens-project"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# POST /v1/projects/{id}/tokens
# ---------------------------------------------------------------------------


def test_mint_token_happy_path(client: TestClient) -> None:
    pid = _signup_with_project(client, "minter@example.com")

    r = client.post(f"/v1/projects/{pid}/tokens", json={"name": "ci-deploy"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "ci-deploy"
    assert body["id"]
    assert body["full"].startswith("fty_test_")  # env defaults to "test"
    assert body["masked"] != body["full"]  # never echoes the secret unmasked
    assert body["scopes"] == ["mint_user_token", "read_audit"]  # schema default


def test_mint_token_when_caller_is_not_an_org_member_then_status_is_403(
    client: TestClient,
) -> None:
    pid = _signup_with_project(client, "ownerG@example.com")
    client.cookies.clear()
    _signup_and_login(client, "strangerG@example.com", "correcthorsebattery")

    r = client.post(f"/v1/projects/{pid}/tokens", json={"name": "sneaky"})
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# GET /v1/projects/{id}/tokens
# ---------------------------------------------------------------------------


def test_list_tokens_happy_path(client: TestClient) -> None:
    pid = _signup_with_project(client, "lister2@example.com")
    client.post(f"/v1/projects/{pid}/tokens", json={"name": "key-a"})
    client.post(f"/v1/projects/{pid}/tokens", json={"name": "key-b"})

    r = client.get(f"/v1/projects/{pid}/tokens")
    assert r.status_code == 200
    items = r.json()
    names = {item["name"] for item in items}
    assert names == {"key-a", "key-b"}
    for item in items:
        assert "full" not in item  # the list view never returns the raw secret
        assert item["masked"]


def test_list_tokens_when_caller_is_not_an_org_member_then_status_is_403(
    client: TestClient,
) -> None:
    pid = _signup_with_project(client, "ownerH@example.com")
    client.cookies.clear()
    _signup_and_login(client, "strangerH@example.com", "correcthorsebattery")

    r = client.get(f"/v1/projects/{pid}/tokens")
    assert r.status_code == 403


# ---------------------------------------------------------------------------
# DELETE /v1/projects/{id}/tokens/{token_id}
# ---------------------------------------------------------------------------


def test_revoke_token_happy_path(client: TestClient) -> None:
    pid = _signup_with_project(client, "revoker@example.com")
    token_id = client.post(
        f"/v1/projects/{pid}/tokens", json={"name": "throwaway"}
    ).json()["id"]

    r = client.delete(f"/v1/projects/{pid}/tokens/{token_id}")
    assert r.status_code == 204

    r = client.get(f"/v1/projects/{pid}/tokens")
    assert r.json() == []


def test_revoke_token_when_token_already_deleted_then_status_is_404(
    client: TestClient,
) -> None:
    pid = _signup_with_project(client, "doublerevoke@example.com")
    token_id = client.post(f"/v1/projects/{pid}/tokens", json={"name": "once"}).json()[
        "id"
    ]
    client.delete(f"/v1/projects/{pid}/tokens/{token_id}")

    r = client.delete(f"/v1/projects/{pid}/tokens/{token_id}")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# mint_api_key() — service-level invariants
# ---------------------------------------------------------------------------


async def test_mint_api_key_happy_path(session_factory, tmp_path) -> None:
    """The token_id fact signed into the biscuit is the row's primary key.

    The OTLP Collector looks a token up in its cache by that fact, so a fact
    that doesn't match the row id points at nothing.
    """
    ks = FileKeyStore(base_dir=tmp_path / "keystore")
    ks.ensure_keypair()

    async with session_factory() as session:
        row, full_token = await mint_api_key(
            session,
            project_id=DEFAULT_PROJECT_ID,
            name="collector-key",
            scopes=["read_audit"],
            env="live",
            signing_key_bytes=ks._private_key_bytes(),
        )

    _, _, biscuit_b64 = parse_envelope(full_token)
    biscuit = verify_token(biscuit_b64, ks.public_key_bytes())

    minted = (
        AuthorizerBuilder().build(biscuit).query(Rule("found($id) <- token_id($id)"))
    )
    assert [f.terms[0] for f in minted] == [row.id]
