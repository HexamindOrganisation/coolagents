"""RH (HR) assistant demo — same agent, the role flips the decision.

Built on basic LangChain: ``@tool``-decorated functions over a
``langgraph.prebuilt.create_react_agent`` graph, run through Hexgate's
:func:`~hexgate.adapters.langchain.wrap_langchain_agent`, which enforces the
role-aware policy bundle on every tool call. The policy lives on the platform
(resolved by agent name ``hr_agent``); author its roles there —
``examples/hr_policy.yaml`` is the source to paste in.

Run it:

    uv run python examples/hr_agent.py

``main()`` sends the SAME sentence as different roles and prints each
outcome. The agent's reasoning never changes — only the policy pulled for the
caller's ``User.role`` does. The escalation ladder, least → most privileged:

    default < manager < gestionnaire_rh

Demo storyline (see examples/hr_policy.yaml for the matching policy):

    A. Field-level scoping — "titre + service de Sophie Martin"
         default / manager → ALLOW
       then "et son salaire ?"
         manager          → DENY  (salary not in the manager field allowlist)
         gestionnaire_rh  → ALLOW
       Same tool, same employee — the FIELD asked for + the ROLE decide.

    B. Sensitive write — "passe son salaire à 85 000 €"
         manager          → DENY
         gestionnaire_rh  → ALLOW

    C. Ultra-sensitive (medical) — "affiche ses arrêts maladie"
         manager          → DENY   (medical is out of scope)
         gestionnaire_rh  → ALLOW

    D. Mass export (anti-exfiltration) — "exporte toute la paie de janvier"
         gestionnaire_rh  → DENY  (args.count <= 1000)
       then a normal volume — "les 30 bulletins de l'équipe Commerciale"
         gestionnaire_rh  → ALLOW
       The ceiling lives OUTSIDE the LLM, so a prompt-injected agent can't
       siphon the whole payroll.

    E. Reserved action — "lance son départ"
         manager          → DENY
         gestionnaire_rh  → ALLOW

Tool layout
-----------
- ``search_directory``   — non-sensitive annuaire lookup (any role)
- ``get_employee_data``  — single read tool, FIELD-scoped per role
- ``get_medical_leave``  — health read, split out (own tool, gated separately)
- ``update_salary``      — write; gestionnaire_rh only
- ``view_compensation``  — aggregated payroll mass (gestionnaire_rh only)
- ``export_payroll``     — bulk export, volume-capped at 1000
- ``offboard_employee``  — trigger a departure (gestionnaire_rh only)
"""

from __future__ import annotations

import asyncio

from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from hexgate.adapters.langchain import wrap_langchain_agent
from hexgate.runtime import User

# Load .env at import — the module-level `agent` below is built eagerly so
# `hexgate register --agent examples.hr_agent:agent` can resolve it, and
# ChatOpenAI needs OPENAI_API_KEY at construction time.
load_dotenv()


# ---------------------------------------------------------------------------
# Tools — stubs in place of real implementations. Replace the bodies once the
# policy + roles round-trip looks right. The constraint engine only ever sees
# the call's `args`, so any check it can't express (row-level "son équipe"
# scope, name → id resolution) belongs in the body, keyed off the TRUSTED
# User identity rather than a model-supplied argument.
# ---------------------------------------------------------------------------


@tool
def search_directory(name: str) -> str:
    """Look up an employee in the internal directory by name.

    Returns non-sensitive annuaire fields only (title, department, manager,
    work email). Never returns salary, bank, or medical data.
    """
    return (
        f"(stub) annuaire — {name}: id=E1042, Responsable Marketing, "
        f"service Marketing, manager=Paul Durand, "
        f"work_email={name.split()[0].lower()}@acme.example"
    )


@tool
def get_employee_data(employee_id: str, field: str) -> str:
    """Return a single FIELD of an employee record.

    `field` is one of: title, department, manager, work_email, leave_balance,
    performance_rating, salary, contract, bank_account. Which fields a caller
    may read is decided by the policy from their role — pass the field the
    user asked for and let the policy gate it. Health data is NOT available
    here; use get_medical_leave for that.
    """
    sample = {
        "title": "Responsable Marketing",
        "department": "Marketing",
        "manager": "Paul Durand",
        "work_email": "sophie.martin@acme.example",
        "leave_balance": "18.5 jours",
        "performance_rating": "3,8 / 5 (cycle 2025)",
        "salary": "54 000 € brut/an",
        "contract": "CDI, temps plein, depuis 2021-03-01",
        "bank_account": "FR76 3000 4000 0512 3456 7890 143",
    }
    value = sample.get(field, f"<champ inconnu: {field}>")
    return f"(stub) employee {employee_id} — {field}: {value}"


@tool
def get_medical_leave(employee_id: str) -> str:
    """Return current medical / sick-leave information for an employee.

    Health data is the most sensitive category (RGPD). It lives in its own
    tool on purpose so it can be gated separately from the rest of the
    employee record.
    """
    return (
        f"(stub) employee {employee_id}: arrêt maladie en cours du "
        f"2026-06-02 au 2026-06-27 (motif non communiqué)."
    )


@tool
def update_salary(employee_id: str, new_amount: float) -> str:
    """Set an employee's gross annual salary to `new_amount` (in euros)."""
    return (
        f"(stub) salaire de l'employé {employee_id} mis à jour → "
        f"{new_amount:,.0f} € brut/an"
    )


@tool
def view_compensation(team: str) -> str:
    """Return the aggregated compensation grid / payroll mass for a team."""
    return (
        f"(stub) équipe {team}: masse salariale 1 245 000 €/an, "
        f"effectif 17, salaire médian 58 000 €, P90 92 000 €."
    )


@tool
def export_payroll(period: str, count: int) -> str:
    """Export `count` payslips for the given `period` (e.g. '2026-01').

    Pass `count` = the number of payslips the export would produce. The
    policy caps this per role so a runaway request can't dump the whole
    company's payroll.
    """
    return f"(stub) export de {count} bulletins de paie pour {period} → PAY-EXP-3391"


@tool
def offboard_employee(employee_id: str) -> str:
    """Trigger the offboarding (departure) procedure for an employee."""
    return (
        f"(stub) procédure de départ déclenchée pour l'employé "
        f"{employee_id} → OFFB-2207"
    )


TOOLS = [
    search_directory,
    get_employee_data,
    get_medical_leave,
    update_salary,
    view_compensation,
    export_payroll,
    offboard_employee,
]

INSTRUCTIONS = (
    "Tu es un assistant RH. Tu aides le personnel autorisé à consulter "
    "l'annuaire, lire les champs d'un dossier salarié, modifier une "
    "rémunération, exporter des bulletins de paie, consulter la compensation "
    "agrégée et déclencher un offboarding. Quand l'utilisateur demande un "
    "champ précis d'un dossier, appelle get_employee_data avec ce champ exact "
    "(title, department, manager, work_email, leave_balance, "
    "performance_rating, salary, contract, bank_account) ; pour les arrêts "
    "maladie, utilise get_medical_leave. Si l'utilisateur désigne un salarié "
    "par son nom, passe ce nom directement comme employee_id. Pour un export, "
    "estime le nombre de bulletins (count) à partir de la demande. Tu n'as pas "
    "besoin de demander confirmation avant d'appeler un outil — agis "
    "directement sur les détails fournis. La couche de politique gate les "
    "actions sensibles, fais-lui confiance pour bloquer ce qui n'est pas "
    "autorisé. Réponds toujours dans la langue du message de l'utilisateur."
)


# ---------------------------------------------------------------------------
# The agent. One definition; the role lives on the User passed at run time.
# Built at import so `hexgate register` can resolve it as
# `examples.hr_agent:agent`. It is wrapped with Hexgate policy enforcement in
# main() (wrapping needs HEXGATE_API_KEY and resolves the policy from the platform).
# Register with:
#   uv run hexgate register --agent examples.hr_agent:agent \
#       --tools examples.hr_agent:TOOLS --model gpt-4o-mini
# ---------------------------------------------------------------------------

agent = create_react_agent(
    model=ChatOpenAI(model="gpt-4o-mini", temperature=0),
    tools=TOOLS,
    prompt=INSTRUCTIONS,
)
agent.name = "hr_agent"  # policy + manifest resolve by this name on the platform


# ---------------------------------------------------------------------------
# Demo: same sentence, the role flips the decision.
#   uv run python examples/hr_agent.py
# ---------------------------------------------------------------------------


async def _run_as(enforced, role: str, prompt: str) -> None:
    print(f"\n=== role={role} :: {prompt!r} ===")
    result = await enforced.ainvoke(
        {"messages": [{"role": "user", "content": prompt}]},
        user=User(user_id=f"rh_{role}", role=role, session_id=f"session_{role}"),
    )
    print(result["messages"][-1].content)


async def main() -> None:
    enforced = wrap_langchain_agent(agent=agent, tools=TOOLS)

    # Démo A — scoping au niveau du champ : même outil, même salarié.
    await _run_as(enforced, "default", "Donne-moi le titre de poste et le service de Sophie Martin.")
    await _run_as(enforced, "manager", "Donne-moi le titre de poste et le service de Sophie Martin.")
    await _run_as(enforced, "manager", "Et quel est le salaire de Sophie Martin ?")
    await _run_as(enforced, "gestionnaire_rh", "Et quel est le salaire de Sophie Martin ?")

    # Démo B — écriture sensible.
    await _run_as(enforced, "manager", "Passe le salaire annuel de Sophie Martin à 85 000 €.")
    await _run_as(enforced, "gestionnaire_rh", "Passe le salaire annuel de Sophie Martin à 85 000 €.")

    # Démo C — donnée ultra-sensible (médical).
    await _run_as(enforced, "manager", "Affiche les arrêts maladie en cours de Sophie Martin.")
    await _run_as(enforced, "gestionnaire_rh", "Affiche les arrêts maladie en cours de Sophie Martin.")

    # Démo D — export de masse (anti-exfiltration), puis volume normal.
    await _run_as(enforced, "gestionnaire_rh", "Exporte les bulletins de paie de toute l'entreprise pour janvier 2026 (environ 5 000 salariés).")
    await _run_as(enforced, "gestionnaire_rh", "Exporte les 30 bulletins de l'équipe Commerciale pour janvier 2026.")

    # Démo E — action réservée.
    await _run_as(enforced, "manager", "Lance la procédure de départ de Sophie Martin.")
    await _run_as(enforced, "gestionnaire_rh", "Lance la procédure de départ de Sophie Martin.")


if __name__ == "__main__":
    asyncio.run(main())
