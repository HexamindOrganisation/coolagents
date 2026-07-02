"""Tests for platform-side bundle compilation + signing (M2 phase 7a).

The control plane compiles policy.yaml → WASM and signs the manifest at
save time. These tests cover the compile helper directly, the save path
through ``update_agent``, and the wire format the SDK will consume.

Compilation shells out to ``opa``; tests that need it are skipped when
opa isn't on PATH.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

from hexgate_api.constants import DEFAULT_PROJECT_ID, DEFAULT_USER_ID
from hexgate.security import generate_keypair, sign_bytes, verify_bytes
from hexgate_api.models import Agent  # noqa: F401 — ensures the table is registered
from hexgate_api.domains.agents.service import (
    backfill_bundles,
    compile_bundle,
    update_agent,
)
from hexgate_api.bootstrap.seed import ensure_default_project


_OPA_AVAILABLE = shutil.which("opa") is not None
needs_opa = pytest.mark.skipif(not _OPA_AVAILABLE, reason="opa not on PATH")


_DEMO_POLICY = """\
version: 1
roles:
  default:
    tools:
      web_search: { mode: allow }
  billing:
    tools:
      refund_order:
        mode: allow
        constraints:
          - args.amount <= 500
"""

_BAD_POLICY = """\
version: 1
roles:
  default:
    tools:
      t:
        mode: allow
        constraints:
          - args.x ~~ 1
"""


@pytest.fixture
def signer() -> tuple:
    """A throwaway keypair + a sign callable shaped like keystore.sign."""
    private_raw, public_raw = generate_keypair()
    return (lambda data: sign_bytes(data, private_raw)), public_raw


@pytest_asyncio.fixture
async def session(tmp_path):
    """A fresh temp-file async SQLite session with the schema + seeded agents."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        await ensure_default_project(s)
        yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# compile_bundle
# ---------------------------------------------------------------------------


@needs_opa
def test_compile_bundle_produces_signed_artifact(signer) -> None:
    sign, public_raw = signer
    out = compile_bundle(_DEMO_POLICY, sign)
    assert out is not None
    wasm, manifest_text, signature = out
    assert wasm.startswith(b"\x00asm")
    # Signature verifies over the EXACT manifest bytes.
    verify_bytes(manifest_text.encode("utf-8"), signature, public_raw)


@needs_opa
def test_compile_bundle_manifest_hash_matches_wasm(signer) -> None:
    sign, _ = signer
    wasm, manifest_text, _ = compile_bundle(_DEMO_POLICY, sign)
    manifest = json.loads(manifest_text)
    assert manifest["wasm_hash"] == hashlib.sha256(wasm).hexdigest()


def test_compile_bundle_returns_none_for_bad_policy(signer) -> None:
    """A malformed constraint degrades to None — no bundle, no crash."""
    sign, _ = signer
    assert compile_bundle(_BAD_POLICY, sign) is None


def test_compile_bundle_returns_none_when_opa_missing(
    signer, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If opa isn't available, compile_bundle returns None (graceful degrade)."""
    from hexgate.security.rego_wasm import OpaNotFoundError

    def boom(*_a, **_k):
        raise OpaNotFoundError("opa not found (simulated)")

    # build_signed_bundle imports compile_to_wasm from rego_wasm directly,
    # so patch it there (not the hexgate.security package re-export).
    monkeypatch.setattr("hexgate.security.rego_wasm.compile_to_wasm", boom)
    sign, _ = signer
    assert compile_bundle(_DEMO_POLICY, sign) is None


# ---------------------------------------------------------------------------
# update_agent save path
# ---------------------------------------------------------------------------


@needs_opa
async def test_update_agent_stores_signed_bundle(session, signer) -> None:
    sign, public_raw = signer
    agent = await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_DEMO_POLICY,
        sign=sign,
    )
    assert agent is not None
    assert agent.compiled_wasm and agent.compiled_wasm.startswith(b"\x00asm")
    assert agent.bundle_manifest is not None
    assert agent.bundle_signature is not None
    verify_bytes(
        agent.bundle_manifest.encode("utf-8"), agent.bundle_signature, public_raw
    )


@needs_opa
async def test_update_agent_clears_stale_bundle_on_bad_policy(session, signer) -> None:
    """A good save then a broken save drops the now-wrong bundle."""
    sign, _ = signer
    await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_DEMO_POLICY,
        sign=sign,
    )
    agent = await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_BAD_POLICY,
        sign=sign,
    )
    assert agent.compiled_wasm is None
    assert agent.bundle_manifest is None
    assert agent.bundle_signature is None


async def test_update_agent_without_sign_stores_no_bundle(session) -> None:
    """No signer → no bundle (pure yaml save, e.g. tests / opa-less envs)."""
    agent = await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_DEMO_POLICY,
    )
    assert agent.compiled_wasm is None


# ---------------------------------------------------------------------------
# backfill_bundles — seeded agents get bundles at startup
# ---------------------------------------------------------------------------


@needs_opa
async def test_backfill_signs_seeded_agents(session, signer) -> None:
    """Seeded agents start bundle-less; backfill compiles + signs them so
    they're served via WASM on the first request, not just after an edit."""
    from sqlmodel import select

    sign, public_raw = signer

    # Seeds are inserted without a bundle.
    rows = (await session.exec(select(Agent))).all()
    assert all(a.compiled_wasm is None for a in rows)

    n = await backfill_bundles(session, sign)
    assert n >= 1

    # Every agent now carries a verifiable bundle.
    rows = (await session.exec(select(Agent))).all()
    for a in rows:
        assert a.compiled_wasm is not None
        verify_bytes(a.bundle_manifest.encode("utf-8"), a.bundle_signature, public_raw)


@needs_opa
async def test_backfill_is_idempotent(session, signer) -> None:
    """A second backfill touches nothing — already-bundled agents are skipped."""
    sign, _ = signer
    first = await backfill_bundles(session, sign)
    assert first >= 1
    assert (await backfill_bundles(session, sign)) == 0


# ---------------------------------------------------------------------------
# Wire format (_agent_read serializer)
# ---------------------------------------------------------------------------


@needs_opa
async def test_agent_read_serializes_bundle_as_base64(session, signer) -> None:
    from hexgate_api.domains.agents.router import _agent_read

    sign, public_raw = signer
    agent = await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_DEMO_POLICY,
        sign=sign,
    )
    view = _agent_read(agent)
    assert view.bundle_wasm_b64 is not None
    assert view.bundle_signature_b64 is not None
    assert view.bundle_manifest is not None
    # Round-trip the wire format and verify the signature end to end.
    wasm = base64.b64decode(view.bundle_wasm_b64)
    sig = base64.b64decode(view.bundle_signature_b64)
    assert wasm.startswith(b"\x00asm")
    verify_bytes(view.bundle_manifest.encode("utf-8"), sig, public_raw)
    # And the manifest's wasm_hash still ties to the served wasm.
    assert (
        json.loads(view.bundle_manifest)["wasm_hash"]
        == hashlib.sha256(wasm).hexdigest()
    )


async def test_agent_read_nulls_when_unsigned(session) -> None:
    agent = await update_agent(
        session,
        DEFAULT_PROJECT_ID,
        "default",
        policy_yaml=_DEMO_POLICY,
    )
    from hexgate_api.domains.agents.router import _agent_read

    view = _agent_read(agent)
    assert view.bundle_wasm_b64 is None
    assert view.bundle_manifest is None
    assert view.bundle_signature_b64 is None


# ---------------------------------------------------------------------------
# Cross-seam parity: platform-compiled bundle, consumed by the SDK, agrees
# with the pydantic engine on the same policy. This is the load-bearing
# check that 7a (producer) and 7b (consumer) line up across the wire.
# ---------------------------------------------------------------------------


_PARITY_CASES = [
    ("default", "web_search", {}, True),
    ("billing", "refund_order", {"amount": 200}, True),
    ("billing", "refund_order", {"amount": 700}, False),
    ("default", "refund_order", {"amount": 1}, False),  # no rule → deny
]


@needs_opa
@pytest.mark.parametrize(("role", "tool", "args", "expect_allow"), _PARITY_CASES)
def test_platform_bundle_matches_pydantic(role, tool, args, expect_allow, signer):
    """The platform's signed bundle, loaded via the SDK's from_parts +
    verified, decides exactly what the pydantic engine decides on the same
    policy_yaml."""
    from hexgate.security import (
        ApprovalRequiredError,
        PolicyBundle,
        PolicyDeniedError,
        authorize_tool_call,
        load_policy_set_from_dict,
    )

    sign, public_raw = signer

    # Producer side: the platform compiles + signs.
    out = compile_bundle(_DEMO_POLICY, sign)
    assert out is not None
    wasm, manifest_text, signature = out

    # Consumer side: the SDK rebuilds from the served parts + verifies.
    bundle = PolicyBundle.from_parts(
        wasm_bytes=wasm,
        manifest_bytes=manifest_text.encode("utf-8"),
        signature=signature,
    )
    bundle.verify_signature(public_raw)
    bundle.verify_integrity()
    wasm_allow = bundle.policy().decide(role=role, tool=tool, args=args).allow

    # Pydantic baseline on the same source.
    import yaml as _yaml

    ps = load_policy_set_from_dict(_yaml.safe_load(_DEMO_POLICY))
    policy = ps.policy_for(role)
    try:
        authorize_tool_call(policy, tool, args)
        py_allow = True
    except (PolicyDeniedError, ApprovalRequiredError):
        py_allow = False

    assert wasm_allow == expect_allow
    assert wasm_allow == py_allow, (
        f"platform-bundle wasm disagrees with pydantic for {role}/{tool}/{args}"
    )


# ---------------------------------------------------------------------------
# Phase 8a — ETag / If-None-Match on the agent fetch endpoint
# ---------------------------------------------------------------------------


@needs_opa
def test_get_agent_returns_etag_header_when_bundle_present() -> None:
    """The endpoint exposes the bundle's wasm_hash as a quoted ETag so
    the SDK can use it on subsequent conditional GETs."""
    from fastapi.testclient import TestClient
    from hexgate_api import main

    # M3 Phase 2: routes require the X-Dev-User header. The default seed user
    # is a member of support-bot's org, so baking it onto the client passes
    # the require_org_member gate.
    with TestClient(main.app, headers={"X-Dev-User": DEFAULT_USER_ID}) as c:
        r = c.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default")
        assert r.status_code == 200
        etag = r.headers.get("etag")
        assert etag and etag.startswith('"') and etag.endswith('"')
        # Server-side ETag matches the wasm sha256 the SDK can compute.
        body = r.json()
        served_wasm = base64.b64decode(body["bundle_wasm_b64"])
        assert etag == f'"{hashlib.sha256(served_wasm).hexdigest()}"'


@needs_opa
def test_if_none_match_returns_304_when_unchanged() -> None:
    """A conditional GET with the prior ETag returns 304 + empty body —
    the cheap path the per-run refresh leans on."""
    from fastapi.testclient import TestClient
    from hexgate_api import main

    # M3 Phase 2: routes require the X-Dev-User header. The default seed user
    # is a member of support-bot's org, so baking it onto the client passes
    # the require_org_member gate.
    with TestClient(main.app, headers={"X-Dev-User": DEFAULT_USER_ID}) as c:
        r1 = c.get(f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default")
        etag = r1.headers["etag"]

        r2 = c.get(
            f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default",
            headers={"If-None-Match": etag},
        )
        assert r2.status_code == 304
        assert r2.content == b""
        # ETag is echoed so the client can re-confirm the match.
        assert r2.headers.get("etag") == etag


@needs_opa
def test_if_none_match_stale_etag_returns_fresh_200() -> None:
    """A stale or wrong ETag → server resends the full body (200)."""
    from fastapi.testclient import TestClient
    from hexgate_api import main

    # M3 Phase 2: routes require the X-Dev-User header. The default seed user
    # is a member of support-bot's org, so baking it onto the client passes
    # the require_org_member gate.
    with TestClient(main.app, headers={"X-Dev-User": DEFAULT_USER_ID}) as c:
        r = c.get(
            f"/v1/projects/{DEFAULT_PROJECT_ID}/agents/default",
            headers={"If-None-Match": '"obviously-stale"'},
        )
        assert r.status_code == 200
        assert r.json().get("bundle_wasm_b64") is not None
