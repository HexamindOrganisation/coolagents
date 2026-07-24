"""Tests for the network-egress builder sugar and its constraint emitters.

Covers three things: the rendered constraint strings, that they decide correctly
on the pydantic engine, and that the *same* policy agrees on the compiled WASM
engine (skipped when `opa` is not on PATH).
"""

from __future__ import annotations

import shutil

import pytest

from hexgate import C, PolicyBuilder
from hexgate.security.network import (
    NET_HTTP_REQUEST,
    host_match_constraint,
    net_constraints,
)
from hexgate.security.policy_set import load_policy_set, load_policy_set_from_dict

_OPA = shutil.which("opa") is not None


# --- constraint emitters ------------------------------------------------------


def test_host_match_exact_only() -> None:
    assert (
        host_match_constraint(["a.com", "b.com"]) == 'args.host in ["a.com", "b.com"]'
    )


def test_host_match_subdomain_covers_apex_and_wildcard() -> None:
    clause = host_match_constraint(subdomains=["example.com"])
    assert clause == (
        'args.host == "example.com" or endswith(args.host, ".example.com")'
    )


def test_host_match_empty_is_none() -> None:
    assert host_match_constraint() is None


def test_net_constraints_full() -> None:
    assert net_constraints(
        hosts=["api.github.com"], schemes=["https"], ports=[443]
    ) == [
        'args.host in ["api.github.com"]',
        'args.scheme in ["https"]',
        "args.port in [443]",
    ]


# --- net_allow decides correctly (pydantic engine) ----------------------------


def _ps(builder: PolicyBuilder):
    return load_policy_set(builder.build())


def _decide(ps, host, scheme="https", port=443):
    return ps.evaluate(
        role="default",
        tool=NET_HTTP_REQUEST,
        args={"host": host, "scheme": scheme, "port": port},
    ).outcome.value


def test_net_allow_exact_host() -> None:
    ps = _ps(PolicyBuilder(default="deny").net_allow(hosts=["api.github.com"]))
    assert _decide(ps, "api.github.com") == "allow"
    assert _decide(ps, "evil.com") == "deny"


def test_net_allow_subdomain_matches_apex_and_children() -> None:
    ps = _ps(PolicyBuilder(default="deny").net_allow(subdomains=["github.com"]))
    assert _decide(ps, "github.com") == "allow"
    assert _decide(ps, "api.github.com") == "allow"
    assert _decide(ps, "notgithub.com") == "deny"  # leading-dot guard
    assert _decide(ps, "github.com.evil.com") == "deny"


def test_net_allow_scheme_and_port_gate() -> None:
    ps = _ps(
        PolicyBuilder(default="deny").net_allow(
            hosts=["api.github.com"], schemes=["https"], ports=[443]
        )
    )
    assert _decide(ps, "api.github.com", scheme="https", port=443) == "allow"
    assert _decide(ps, "api.github.com", scheme="http", port=443) == "deny"
    assert _decide(ps, "api.github.com", scheme="https", port=8080) == "deny"


def test_net_allow_extra_when_constraints() -> None:
    ps = _ps(
        PolicyBuilder(default="deny").net_allow(
            hosts=["api.github.com"], when=[C("args.method") == "GET"]
        )
    )
    assert (
        ps.evaluate(
            role="default",
            tool=NET_HTTP_REQUEST,
            args={"host": "api.github.com", "scheme": "https", "method": "GET"},
        ).outcome.value
        == "allow"
    )
    assert (
        ps.evaluate(
            role="default",
            tool=NET_HTTP_REQUEST,
            args={"host": "api.github.com", "scheme": "https", "method": "DELETE"},
        ).outcome.value
        == "deny"
    )


def test_net_approve_mode() -> None:
    ps = _ps(PolicyBuilder(default="deny").net_approve(hosts=["api.github.com"]))
    assert _decide(ps, "api.github.com") == "needs_approval"
    assert _decide(ps, "evil.com") == "deny"


def test_net_allow_without_host_restriction_raises() -> None:
    with pytest.raises(ValueError, match="host restriction"):
        PolicyBuilder(default="deny").net_allow()
    # scheme/port alone is still an error — it would authorize every host.
    with pytest.raises(ValueError, match="host restriction"):
        PolicyBuilder(default="deny").net_allow(ports=[443])


def test_net_approve_without_host_restriction_raises() -> None:
    with pytest.raises(ValueError, match="host restriction"):
        PolicyBuilder(default="deny").net_approve()


def test_net_allow_any_host_opt_in() -> None:
    ps = _ps(PolicyBuilder(default="deny").net_allow(any_host=True))
    assert _decide(ps, "anything.example.com", scheme="https") == "allow"
    assert (
        _decide(ps, "anything.example.com", scheme="http") == "deny"
    )  # still HTTPS-only


# --- pydantic <-> WASM parity -------------------------------------------------


@pytest.mark.skipif(not _OPA, reason="opa not on PATH")
def test_net_allow_pydantic_wasm_parity() -> None:
    from hexgate.security import WasmPolicy, compile_to_wasm
    from hexgate.security.rego import compile_to_rego

    policy = (
        PolicyBuilder(default="deny")
        .net_allow(hosts=["api.github.com"], subdomains=["githubusercontent.com"])
        .build()
    )
    payload = {"roles": {"default": policy.model_dump(exclude_defaults=True)}}
    ps = load_policy_set_from_dict(payload)
    wasm = WasmPolicy.from_bytes(compile_to_wasm(compile_to_rego(payload)).wasm)

    cases = [
        ("api.github.com", "https"),
        ("raw.githubusercontent.com", "https"),
        ("github.com", "https"),  # apex of the exact host — not allowlisted
        ("api.github.com", "http"),
        ("evil.com", "https"),
    ]
    for host, scheme in cases:
        args = {"host": host, "scheme": scheme, "port": 443}
        py = ps.evaluate(role="default", tool=NET_HTTP_REQUEST, args=args).outcome.value
        rego = wasm.decide(role="default", tool=NET_HTTP_REQUEST, args=args)
        wo = (
            "allow"
            if rego.allow
            else ("needs_approval" if rego.requires_approval else "deny")
        )
        assert py == wo, f"engines disagree on {host}/{scheme}: pydantic={py} wasm={wo}"
