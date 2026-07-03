"""ITSM Change Request agent demo — RBAC + state-machine guard.

Built on deepagents (``create_deep_agent``) over LangChain tools, run
through Hexgate's :func:`~hexgate.adapters.langchain.wrap_langchain_agent`,
which enforces the role-aware policy bundle on every tool call. The policy
lives on the platform (resolved by agent name ``itsm_agent``); author its
roles there — ``examples/itsm_policy.yaml`` is the source to paste in.

Two questions are checked on every action (the security model):

  1. Does the actor's ROLE grant this operation?   → the policy (RBAC).
     Each lifecycle transition is its OWN tool, owned by exactly one role,
     so separation of duties is structural: a role simply has no access to
     a transition it does not own.
  2. Is the transition VALID from the current state, and does the actor
     OWN / is mentioned on this record?            → the tool body.
     The constraint engine only ever sees ``args`` — it cannot read the
     change's live state or its owner. So those checks live in the tool,
     keyed off the TRUSTED ``User`` identity (never a model-supplied arg),
     exactly as the healthcare demo re-derives the real email domain.

State machine (each arrow owned by one role):

    new ──(requester)──▶ Assess ──(change_manager)──▶ Authorize ──(cab_manager)──▶ Schedule

Run it:

    uv run python examples/itsm_agent.py

Identity = email. ``User.user_id`` is set to the caller's email so the
ownership checks compare against the ``requester_email`` /
``implementer_email`` columns directly. ``User.role`` comes from
Attachment A.

Roles
-----
- ``requester``      — create + edit drafts + submit. Write expires once the
                       change leaves ``new`` (state-bound write).
- ``implementer``    — read-only, scoped to changes they are mentioned on.
- ``change_manager`` — read all + edit assessment + authorize (Assess→Authorize).
- ``cab_manager``    — read all + schedule decision only (Authorize→Schedule).
- ``default``        — fail-closed fallback; nothing allowed.
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

try:  # `python examples/itsm_agent.py` puts examples/ on sys.path
    import itsm_db as db
except ModuleNotFoundError:  # `python -m examples.itsm_agent` puts the repo root on it
    from examples import itsm_db as db
from deepagents import create_deep_agent
from hexgate.adapters.langchain import wrap_langchain_agent
from hexgate.runtime import User, get_current_user

# Load .env at import — the module-level `agent` below is built eagerly so
# `hexgate register --agent examples.itsm_agent:agent` can resolve it, and
# deepagents resolves the model eagerly (ChatOpenAI needs OPENAI_API_KEY at
# construction time). `hexgate register` also loads .env via bootstrap; this
# makes the bare `python examples/itsm_agent.py` path work too.
load_dotenv()

# ---------------------------------------------------------------------------
# State machine: each transition tool maps to (required from_state, to_state).
# The REQUIRED ROLE for each is enforced by the policy (one tool per role);
# the FROM-STATE is enforced here in the tool body.
# ---------------------------------------------------------------------------

_TRANSITIONS = {
    "submit_for_assessment": ("new", "Assess"),
    "authorize_change": ("Assess", "Authorize"),
    "schedule_change": ("Authorize", "Schedule"),
}


def _actor() -> tuple[str, str | None]:
    """Trusted caller identity (email, role) from the active User scope."""
    user = get_current_user()
    if user is None:  # no scope → fail closed
        return ("anonymous", None)
    return (user.user_id, user.role)


def _fmt(change: dict) -> str:
    return (
        f"{change['number']} [{change['state']}] CI={change['ci']} "
        f"\"{change['short_description']}\" requester={change['requester_email']} "
        f"implementer={change['implementer_email']}"
    )


def _transition(tool_name: str, change_id: str) -> str:
    """Shared guard for the three lifecycle transitions.

    Role ownership is already enforced by the policy (this tool is only
    reachable by its owning role). Here we enforce the *state* half: the
    change must actually be in the expected ``from`` state, and — for the
    requester's submit — the actor must own the record.
    """
    actor_email, role = _actor()
    from_state, to_state = _TRANSITIONS[tool_name]
    change = db.get_change(change_id)
    if change is None:
        db.audit(action=tool_name, actor=actor_email, role=role, number=change_id,
                 decision="DENY", detail="not found")
        return f"DENIED: change {change_id} not found."

    if change["state"] != from_state:
        db.audit(action=tool_name, actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail=f"requires {from_state}")
        return (
            f"DENIED: {tool_name} requires state '{from_state}', but "
            f"{change_id} is in '{change['state']}'."
        )

    # Only the requester's own draft may be submitted.
    if tool_name == "submit_for_assessment" and change["requester_email"] != actor_email:
        db.audit(action=tool_name, actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail="not owner")
        return f"DENIED: {change_id} is not your change."

    updated = db.set_state(change_id, to_state)
    db.audit(action=tool_name, actor=actor_email, role=role, number=change_id,
             decision="ALLOW", before=from_state, after=to_state)
    return f"OK: {change_id} transitioned {from_state} → {to_state}.\n{_fmt(updated)}"


# ---------------------------------------------------------------------------
# Tools. RBAC (role → tool) is the policy's job; each body enforces the
# state-machine + ownership the policy cannot see.
# ---------------------------------------------------------------------------


@tool
async def create_change(ci: str, short_description: str) -> str:
    """Create a new change request on a CI (a server or application) by name.

    `ci` is a CMDB CI name such as 'srv-db-01' or 'CRM'. The new change is
    forced to state 'new' and owned by the calling user.
    """
    actor_email, role = _actor()
    try:
        created = db.create_change(
            short_description=short_description, ci_name=ci, requester_email=actor_email
        )
    except ValueError as exc:
        db.audit(action="create_change", actor=actor_email, role=role, number=None,
                 decision="DENY", detail=str(exc))
        return f"DENIED: {exc} (known CIs: srv-web-01/02, srv-db-01, srv-app-01, CRM, ERP, Billing)."
    db.audit(action="create_change", actor=actor_email, role=role,
             number=created["number"], decision="ALLOW", after="new", detail=f"CI={ci}")
    return f"OK: created {created['number']} in state 'new'.\n{_fmt(created)}"


@tool
async def update_change(change_id: str, description: str = "", ci: str = "") -> str:
    """Edit a DRAFT change. Pass `description` and/or `ci` (a CI name) to set.

    Allowed only while the change is in state 'new' and owned by the caller —
    write access expires once the change moves past 'new'.
    """
    actor_email, role = _actor()
    change = db.get_change(change_id)
    if change is None:
        return f"DENIED: change {change_id} not found."

    if change["state"] != "new":
        db.audit(action="update_change", actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail="not editable past 'new'")
        return f"DENIED: {change_id} is in '{change['state']}'; drafts are editable only while 'new'."
    if change["requester_email"] != actor_email:
        db.audit(action="update_change", actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail="not owner")
        return f"DENIED: {change_id} is not your draft."

    try:
        updated = db.update_change_fields(
            change_id,
            description=description or None,
            ci_name=ci or None,
        )
    except ValueError as exc:
        db.audit(action="update_change", actor=actor_email, role=role, number=change_id,
                 decision="DENY", detail=str(exc))
        return f"DENIED: {exc}."
    db.audit(action="update_change", actor=actor_email, role=role, number=change_id,
             decision="ALLOW", before="new", after="new")
    return f"OK: updated {change_id}.\n{_fmt(updated)}"


@tool
async def read_change(change_id: str) -> str:
    """Return a single change request by number (e.g. 'CHG0001')."""
    actor_email, role = _actor()
    change = db.get_change(change_id)
    # Implementers may read ONLY changes they are mentioned on. Return
    # 'not found' on a miss so the existence of unrelated changes never leaks.
    if change is None or (
        role == "implementer" and change["implementer_email"] != actor_email
    ):
        db.audit(action="read_change", actor=actor_email, role=role, number=change_id,
                 decision="DENY", detail="not found / out of scope")
        return f"Not found: {change_id}."
    db.audit(action="read_change", actor=actor_email, role=role, number=change_id,
             decision="ALLOW", before=change["state"])
    return _fmt(change)


@tool
async def list_my_changes() -> str:
    """List the change requests visible to the calling user."""
    actor_email, role = _actor()
    changes = db.all_changes()
    # Filter to the caller's scope BEFORE returning — no unrelated rows leak.
    if role == "requester":
        visible = [c for c in changes if c["requester_email"] == actor_email]
    elif role == "implementer":
        visible = [c for c in changes if c["implementer_email"] == actor_email]
    elif role in ("change_manager", "cab_manager"):
        visible = changes
    else:
        visible = []
    db.audit(action="list_my_changes", actor=actor_email, role=role, number=None,
             decision="ALLOW", detail=f"{len(visible)} visible")
    if not visible:
        return "No changes visible to you."
    return "\n".join(_fmt(c) for c in visible)


@tool
async def submit_for_assessment(change_id: str) -> str:
    """Submit your draft change for assessment (transition new → Assess)."""
    return _transition("submit_for_assessment", change_id)


@tool
async def update_assessment(change_id: str, short_description: str) -> str:
    """Update assessment details on a change under review (state must be 'Assess')."""
    actor_email, role = _actor()
    change = db.get_change(change_id)
    if change is None:
        return f"DENIED: change {change_id} not found."
    if change["state"] != "Assess":
        db.audit(action="update_assessment", actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail="requires Assess")
        return f"DENIED: assessment edits require state 'Assess'; {change_id} is in '{change['state']}'."
    updated = db.update_change_fields(change_id, description=short_description)
    db.audit(action="update_assessment", actor=actor_email, role=role, number=change_id,
             decision="ALLOW", before="Assess", after="Assess")
    return f"OK: updated assessment on {change_id}.\n{_fmt(updated)}"


@tool
async def authorize_change(change_id: str) -> str:
    """Authorize an assessed change (transition Assess → Authorize)."""
    return _transition("authorize_change", change_id)


@tool
async def schedule_change(change_id: str, cab_decision: str) -> str:
    """Record the CAB decision and schedule the change (transition Authorize → Schedule).

    `cab_decision` is the CAB's note (e.g. 'approved for Saturday window').
    Decision-only: no change fields are edited here.
    """
    actor_email, role = _actor()
    from_state, to_state = _TRANSITIONS["schedule_change"]
    change = db.get_change(change_id)
    if change is None:
        return f"DENIED: change {change_id} not found."
    if change["state"] != from_state:
        db.audit(action="schedule_change", actor=actor_email, role=role, number=change_id,
                 decision="DENY", before=change["state"], detail=f"requires {from_state}")
        return f"DENIED: scheduling requires state '{from_state}'; {change_id} is in '{change['state']}'."
    updated = db.set_state(change_id, to_state)
    db.audit(action="schedule_change", actor=actor_email, role=role, number=change_id,
             decision="ALLOW", before=from_state, after=to_state,
             detail=f"CAB: {cab_decision}")
    return f"OK: {change_id} scheduled (Authorize → Schedule). CAB decision: {cab_decision}.\n{_fmt(updated)}"


TOOLS = [
    create_change,
    update_change,
    read_change,
    list_my_changes,
    submit_for_assessment,
    update_assessment,
    authorize_change,
    schedule_change,
]

INSTRUCTIONS = (
    "You are an ITSM assistant operating a Change Request workflow. Help "
    "authorized staff create change requests, edit drafts, read changes, "
    "update assessment details, and move a change through its lifecycle "
    "(new → Assess → Authorize → Schedule). Map the user's request to the "
    "right tool, pulling the change number (CHGxxxx), the CI name "
    "(server or application), and field values straight from their message. "
    "Do not ask the user to confirm before invoking a tool — act directly on "
    "the details given. The policy layer and the workflow guard gate "
    "sensitive actions, so trust them to stop anything you're not allowed to "
    "do. Always respond in the same language as the user's message."
)


# ---------------------------------------------------------------------------
# Demo identities — from Attachment A (Users & Roles). user_id = email.
# ---------------------------------------------------------------------------

ALICE = ("demo.hexgate+alice.martin@hexamind.ai", "requester")       # owns CHG0001
BRUNO = ("demo.hexgate+bruno.petit@hexamind.ai", "requester")
CARLA = ("demo.hexgate+carla.robert@hexamind.ai", "implementer")     # mentioned on CHG0001
DAVID = ("demo.hexgate+david.richard@hexamind.ai", "implementer")    # not mentioned
EMMA = ("demo.hexgate+emma.dubois@hexamind.ai", "change_manager")
GABRIEL = ("demo.hexgate+gabriel.laurent@hexamind.ai", "cab_manager")


# Raw deepagent graph, built at import so `hexgate register` can resolve it as
# `examples.itsm_agent:agent`. It is wrapped with Hexgate policy enforcement in
# main() (wrapping needs HEXGATE_API_KEY and resolves the policy from the platform).
# Register with:
#   uv run hexgate register --agent examples.itsm_agent:agent \
#       --tools examples.itsm_agent:TOOLS --model gpt-4o-mini
agent = create_deep_agent(
    model=ChatOpenAI(model="gpt-4o-mini", temperature=0),
    tools=TOOLS,
    system_prompt=INSTRUCTIONS,
)
agent.name = "itsm_agent"  # policy + manifest resolve by this name on the platform


async def _run_as(enforced, identity: tuple[str, str | None], prompt: str) -> None:
    email, role = identity
    print(f"\n=== role={role} <{email}> :: {prompt!r} ===")
    result = await enforced.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
        user=User(user_id=email, role=role, session_id=f"session_{role}"),
    )
    print(result["messages"][-1].content)


async def main() -> None:
    db.init_db()
    enforced = wrap_langchain_agent(agent=agent, tools=TOOLS)

    # UC-01 — Requester creates a change on a CI.
    await _run_as(enforced, BRUNO, "Crée un changement sur le serveur srv-db-01 : montée de version.")
    # UC-02 — Requester edits their own draft while 'new'.
    await _run_as(enforced, BRUNO, "Mets à jour CHG0002 : description = 'Upgrade PostgreSQL 15 → 16'.")
    # UC-03 — Requester submits for assessment (new → Assess).
    await _run_as(enforced, BRUNO, "Soumets CHG0002 pour évaluation.")
    # UC-02 failure — once past 'new', the requester loses write access.
    await _run_as(enforced, BRUNO, "Mets à jour CHG0002 : description = 'oops, late edit'.")

    # UC-04 / UC-09 — Implementer reads only changes they are mentioned on.
    await _run_as(enforced, CARLA, "Montre-moi CHG0001.")   # mentioned → ALLOW
    await _run_as(enforced, DAVID, "Montre-moi CHG0001.")   # not mentioned → not found

    # UC-05 / UC-06 — Change Manager edits assessment then authorizes.
    await _run_as(enforced, EMMA, "Évalue CHG0002 : description = 'Risque moyen, fenêtre de nuit'.")
    await _run_as(enforced, EMMA, "Autorise CHG0002.")      # Assess → Authorize
    # UC-06 failure — scheduling belongs to the CAB Manager, not the Change Manager.
    await _run_as(enforced, EMMA, "Planifie CHG0002.")

    # UC-07 — CAB Manager records the decision and schedules.
    await _run_as(enforced, GABRIEL, "Accepte et planifie CHG0002 : approuvé pour samedi 02h.")

    # UC-08 — Out-of-state transition is rejected and logged.
    await _run_as(enforced, BRUNO, "Soumets CHG0002 pour évaluation.")  # already Scheduled → DENY


if __name__ == "__main__":
    asyncio.run(main())
