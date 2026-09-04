"""OTLP pipeline smoke test: one of every event type, then verify they landed.

Sends five events through the SDK's sender (configure -> emit -> flush) to the
stage HEXGATE_API_URL / HEXGATE_API_KEY point at:

    policy decision  allow / deny / needs_approval   -> policy_decision table
    LLM usage                                        -> llm_invocation table
    ban enforcement                                  -> ban_enforcement table

All five ride the same sender, tagged with a per-run session id so the
verification step can find exactly this run's rows.

Scope — what this does and does not prove. It starts at the sender, so it
covers the transport and storage path: OTLP exporter -> reverse proxy ->
Collector (auth, project key) -> Redpanda -> span-enricher -> ClickHouse ->
dashboard read endpoints. It runs no agent: the PolicyEnforcer, the adapter
hooks that produce usage and ban events, identity from the HexgateContext
scope, and policy evaluation are all upstream of where this starts and are
covered by the adapter integration tests (`pytest -m integration`), not here.
A PASS means "a correctly-formed span from this SDK version lands and is
queryable on this stage"; it does not mean "an agent on this stage is audited".

Verification needs a dashboard login (the read endpoints are org-member
only, an API key is not enough). Set HEXGATE_SMOKE_EMAIL and
HEXGATE_SMOKE_PASSWORD to the account you registered on that stage and the
script polls the API until every row shows up. Without them it prints the
ClickHouse queries to run on the box instead.

Usage (the post-deploy check in platform/DEPLOY.md §4; the Makefile target
maps STAGE to the stage's origin, or set HEXGATE_API_URL yourself):

    export HEXGATE_API_KEY=fty_live_...          # minted on THAT stage — a prod
                                                 # key 401s on staging's collector
    export HEXGATE_SMOKE_EMAIL=you@example.com HEXGATE_SMOKE_PASSWORD=...
    make platform-smoke STAGE=staging

Exit 0 means every event was accepted and (when credentials are set) found
in the platform. The OTLP exporter never raises on transport or auth
failures; it logs them at ERROR, so a "Failed to export" line is a failure
even though the script keeps going to the verification step, which then
reports what is missing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from uuid import uuid4

import httpx

from hexgate import audit
from hexgate.audit import AuditEvent
from hexgate.cloud.biscuit import parse_envelope
from hexgate.config.env import resolve_api_url, resolve_otlp_endpoint
from hexgate.security.bans import BanEnforcementEvent
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.tracing.usage import LlmUsageEvent

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

AGENT_NAME = "otlp_smoke"
POLL_TIMEOUT_S = 60
POLL_INTERVAL_S = 3


def build_events(session_id: str, user_id: str) -> dict[str, object]:
    """One event per pipeline path, keyed by a label used in the report."""

    def decision(
        outcome: DecisionOutcome, tool: str, granted: str | None
    ) -> AuditEvent:
        d = Decision(
            outcome=outcome,
            agent_name=AGENT_NAME,
            tool_name=tool,
            user_roles=("analyst",),
            deciding_role=granted,
            reason=f"otlp smoke test ({outcome.value})",
        )
        return AuditEvent(decision=d, user_id=user_id, session_id=session_id)

    return {
        "decision:allow": decision(DecisionOutcome.ALLOW, "search_docs", "analyst"),
        "decision:deny": decision(DecisionOutcome.DENY, "read_file", None),
        "decision:needs_approval": decision(
            DecisionOutcome.NEEDS_APPROVAL, "send_email", None
        ),
        "llm_usage": LlmUsageEvent(
            agent_name=AGENT_NAME,
            model="smoke-model",
            input_tokens=12,
            output_tokens=4,
            latency_ms=42,
            status="success",
            session_id=session_id,
            user_id=user_id,
        ),
        "ban_enforcement": BanEnforcementEvent(
            ban_type="agent",
            ban_id="ban_smoke",
            agent_name=AGENT_NAME,
            reason="otlp smoke test",
            user_id=user_id,
            session_id=session_id,
        ),
    }


def send(events: dict[str, object]) -> None:
    sender = audit.configure()
    if sender is None:
        raise SystemExit(
            "no audit sender: key not resolvable or HEXGATE_LOCAL_MODE is set"
        )
    for ev in events.values():
        sender.emit(ev)  # type: ignore[arg-type]  # every event class satisfies SpanEvent
    asyncio.run(audit.shutdown())  # flushes the batch; export errors log above


def login(client: httpx.Client, email: str, password: str) -> None:
    # FastAPI Users' cookie backend: OAuth2 password form, sets hexgate_session.
    r = client.post(
        "/v1/auth/cookie/login", data={"username": email, "password": password}
    )
    if r.status_code >= 400:
        raise SystemExit(f"dashboard login failed: {r.status_code} {r.text}")


def verify(
    client: httpx.Client,
    project_id: str,
    session_id: str,
    user_id: str,
    events: dict[str, object],
) -> bool:
    """Poll the dashboard read endpoints until every event is visible or time runs out."""
    want_decisions = {
        str(ev.event_id): ev.decision.outcome.value  # type: ignore[attr-defined]
        for label, ev in events.items()
        if label.startswith("decision:")
    }
    ban_event_id = str(events["ban_enforcement"].event_id)  # type: ignore[attr-defined]
    base = f"/v1/projects/{project_id}"

    deadline = time.monotonic() + POLL_TIMEOUT_S
    missing: dict[str, str] = {}
    while True:
        missing = {}

        rows = (
            client.get(
                f"{base}/audit/decisions",
                params={"agent": AGENT_NAME, "session_id": session_id, "limit": 50},
            )
            .raise_for_status()
            .json()["rows"]
        )
        seen = {r["event_id"]: r["outcome"] for r in rows}
        for eid, outcome in want_decisions.items():
            if eid not in seen:
                missing[f"decision:{outcome}"] = "row not found"
            elif seen[eid] != outcome:
                missing[f"decision:{outcome}"] = f"landed with outcome {seen[eid]!r}"

        bans = (
            client.get(f"{base}/audit/ban-enforcements", params={"limit": 100})
            .raise_for_status()
            .json()["rows"]
        )
        if not any(r["event_id"] == ban_event_id for r in bans):
            missing["ban_enforcement"] = "row not found"

        # No per-row read for usage; the summary filtered on this run's unique
        # user id is exactly one call when the event landed.
        totals = (
            client.get(
                f"{base}/llm/summary", params={"agent": AGENT_NAME, "user": user_id}
            )
            .raise_for_status()
            .json()["totals"]
        )
        if totals["calls"] < 1:
            missing["llm_usage"] = "no calls in summary"

        if not missing or time.monotonic() > deadline:
            break
        time.sleep(POLL_INTERVAL_S)

    for label in events:
        status = "MISSING  " + missing[label] if label in missing else "ok"
        print(f"  {label:<24} {status}")
    return not missing


def main() -> int:
    api_key = os.environ.get("HEXGATE_API_KEY")
    if not api_key:
        print("HEXGATE_API_KEY is not set", file=sys.stderr)
        return 1
    _, project_id, _ = parse_envelope(api_key)
    api_url = resolve_api_url()

    run = uuid4().hex[:8]
    session_id = f"s_smoke_{run}"
    user_id = f"u_smoke_{run}"
    events = build_events(session_id, user_id)

    print(
        f"exporting {len(events)} events to {resolve_otlp_endpoint()}  (session {session_id})"
    )
    send(events)
    print("flush complete (an ERROR line above means the collector rejected the batch)")

    email = os.environ.get("HEXGATE_SMOKE_EMAIL")
    password = os.environ.get("HEXGATE_SMOKE_PASSWORD")
    if not (email and password):
        print(
            "\nHEXGATE_SMOKE_EMAIL / HEXGATE_SMOKE_PASSWORD not set; verify on the box:\n"
            f"  clickhouse-client --query \"SELECT outcome, tool_name FROM hexgate_audit.policy_decision WHERE session_id = '{session_id}'\"\n"
            f"  clickhouse-client --query \"SELECT model, input_tokens FROM hexgate_audit.llm_invocation WHERE session_id = '{session_id}'\"\n"
            f"  clickhouse-client --query \"SELECT ban_type, ban_id FROM hexgate_audit.ban_enforcement WHERE session_id = '{session_id}'\"\n"
            "  (prefix each with: docker exec hexgate-<stage>-clickhouse-1)"
        )
        return 0

    print(f"\nverifying via {api_url} as {email} (up to {POLL_TIMEOUT_S}s)")
    with httpx.Client(base_url=api_url, timeout=15) as client:
        login(client, email, password)
        ok = verify(client, project_id, session_id, user_id, events)
    print("\nPASS: all events landed" if ok else "\nFAIL: some events did not land")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
