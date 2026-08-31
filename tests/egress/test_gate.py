"""Tests for the egress enforcement seam (Gate).

Exercises the real ``PolicyEnforcer`` + ``PolicySet`` — no mocks — so the
tests also pin that network egress rides the existing policy engine, identity
binding, and decision-observer hook.
"""

from __future__ import annotations

from hexgate.egress.gate import Gate
from hexgate.egress.model import connect_to_args
from hexgate.runtime.context import HexgateContext
from hexgate.security.decision import Decision
from hexgate.security.enforcer import build_enforcer
from hexgate.security.policy_set import load_policy_set_from_dict


def _enforcer(mode: str, constraints: list[str] | None = None, observer=None):
    policy = load_policy_set_from_dict(
        {
            "roles": {
                "agent": {
                    "default_policy": {"mode": "deny"},
                    "tools": {
                        "net.http_request": {
                            "mode": mode,
                            "constraints": constraints or [],
                        }
                    },
                }
            }
        }
    )
    return build_enforcer(policy, agent_name="test-egress", decision_observer=observer)


def _agent() -> HexgateContext:
    return HexgateContext(user_id="u", user_roles=["agent"])


async def test_allows_matching_host() -> None:
    gate = Gate(_enforcer("allow", ['args.host == "ok.example.com"']), _agent())
    result = await gate.check(connect_to_args("ok.example.com", 443))
    assert result.allowed
    assert result.decision.outcome.value == "allow"


async def test_denies_other_host() -> None:
    gate = Gate(_enforcer("allow", ['args.host == "ok.example.com"']), _agent())
    result = await gate.check(connect_to_args("evil.example.com", 443))
    assert not result.allowed


async def test_ip_literal_is_denied_by_host_allowlist() -> None:
    gate = Gate(_enforcer("allow", ['args.host in ["ok.example.com"]']), _agent())
    result = await gate.check(connect_to_args("203.0.113.5", 443))
    assert not result.allowed


async def test_binds_identity_and_emits_to_observer() -> None:
    seen: list[Decision] = []
    gate = Gate(_enforcer("allow", observer=seen.append), _agent())
    await gate.check(connect_to_args("anything.example.com", 443))
    assert len(seen) == 1
    # sync_scope bound the run's user inside the handler task, so the enforcer
    # attributed the decision to role "agent" (not an empty set).
    assert seen[0].user_roles == ("agent",)
    assert seen[0].tool_name == "net.http_request"


async def test_approval_required_bool_true_allows() -> None:
    gate = Gate(_enforcer("approval_required"), _agent(), approval_handler=True)
    result = await gate.check(connect_to_args("any.example.com", 443))
    assert result.allowed
    # The recorded decision still reflects the original NEEDS_APPROVAL verdict.
    assert result.decision.outcome.value == "needs_approval"


async def test_approval_required_bool_false_denies() -> None:
    gate = Gate(_enforcer("approval_required"), _agent(), approval_handler=False)
    result = await gate.check(connect_to_args("any.example.com", 443))
    assert not result.allowed


async def test_approval_required_async_handler() -> None:
    async def approve(_decision: Decision) -> bool:
        return True

    gate = Gate(_enforcer("approval_required"), _agent(), approval_handler=approve)
    result = await gate.check(connect_to_args("any.example.com", 443))
    assert result.allowed


async def test_approval_handler_raising_fails_closed() -> None:
    def boom(_decision: Decision) -> bool:
        raise RuntimeError("handler blew up")

    gate = Gate(_enforcer("approval_required"), _agent(), approval_handler=boom)
    result = await gate.check(connect_to_args("any.example.com", 443))
    assert not result.allowed


async def test_approval_required_without_handler_denies() -> None:
    gate = Gate(_enforcer("approval_required"), _agent())
    result = await gate.check(connect_to_args("any.example.com", 443))
    assert not result.allowed


# ---------------------------------------------------------------------------
# run.* — egress sits above every run, and records nothing
# ---------------------------------------------------------------------------


async def test_egress_decision_records_no_run_facts() -> None:
    """``egress_guard`` is one per process — the proxy mutates the global
    HTTP_PROXY vars and refuses nesting, and ``Gate`` captures a single
    HexgateContext at construction. So an egress decision is not inside any run
    scope, and there is no correlation to put it in one: a tool's httpx call
    reaches the proxy as a TCP connection carrying no invocation identifier.

    Pinned as behaviour so a later attempt to attribute egress to a run starts
    from a red test rather than a silent semantic change.
    """
    from hexgate.runtime.run_facts import run_scope

    gate = Gate(_enforcer("allow"), _agent())

    with run_scope("a") as facts:
        result = await gate.check(connect_to_args("ok.example.com", 443))

    assert result.allowed
    assert (facts.tool_calls, facts.denials, facts.approvals, facts.errors) == (
        0,
        0,
        0,
        0,
    )


async def test_egress_run_constraint_reads_the_detached_zeros() -> None:
    """The other half of §0.3: because the decision happens outside a run, a
    counter cap on an egress policy reads zeros and therefore *permits*. That is
    the deliberate fail-open on an unattributable boundary — a fail-closed
    reading would brick every egress request the moment a run.* cap appeared in
    a shared default policy."""
    gate = Gate(_enforcer("allow", ["run.tool_calls < 1"]), _agent())

    result = await gate.check(connect_to_args("ok.example.com", 443))

    assert result.allowed
    assert result.decision.outcome.value == "allow"
