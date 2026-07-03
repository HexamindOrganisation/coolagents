"""HIPAA clinical assistant demo — same agent, role flips the decision.

Built on the OpenAI Agents SDK (``agents.Agent`` + ``@function_tool``) and
run through Hexgate's :class:`~hexgate.adapters.openai.HexgateRunner`, which
enforces the role-aware policy bundle on every tool call.

Run it:

    uv run python examples/healthcare_agent.py

The ``main()`` below sends the SAME prompt as three different roles and
prints each outcome. The agent's reasoning never changes — only the policy
pulled for the caller's ``User.role`` does:

    "Prescribe oxycodone 5mg for patient 88."
        nurse      → DENY (prescribe is denied for nurses)
        physician  → ALLOW (prescribing is a physician's call)

    "Email patient 88's record to alice@gmail.com."
        physician  → DENY (recipient_domain not in the allowlist)

    "Pull up the full record for patient 88."
        nurse / physician → ALLOW
        billing_staff     → DENY (clinical data is walled off from billing)

Tool layout
-----------
- ``get_patient_record``  — clinical read
- ``view_lab_results``    — clinical read
- ``order_lab_test``      — clinical write (nurses + physicians)
- ``prescribe``           — physician only (denied for everyone else)
- ``share_record``        — PHI egress; gated on recipient_domain allowlist
- ``get_billing_summary`` — billing read (the only thing billing_staff sees)
"""

from __future__ import annotations

import asyncio

from agents import Agent, function_tool
from dotenv import load_dotenv

from hexgate.adapters.openai import HexgateRunner
from hexgate.runtime import User


# ---------------------------------------------------------------------------
# Tools — stubs in place of real implementations. Replace the bodies once the
# policy + roles round-trip looks right.
# ---------------------------------------------------------------------------


@function_tool
def get_patient_record(patient_id: str) -> str:
    """Return the full clinical record (demographics, problem list, meds) for patient_id."""
    return (
        f"(stub) patient {patient_id}: Jane Doe, 47F, problem list: T2DM, HTN; "
        f"active meds: metformin 1000mg BID, lisinopril 10mg QD."
    )


@function_tool
def view_lab_results(patient_id: str) -> str:
    """Return the most recent lab panel for patient_id."""
    return (
        f"(stub) patient {patient_id} labs: A1c 7.8%, eGFR 88, "
        f"LDL 132 mg/dL (drawn 2026-05-30)."
    )


@function_tool
def order_lab_test(patient_id: str, test: str) -> str:
    """Order lab `test` (e.g. 'CBC', 'CMP', 'lipid panel') for patient_id."""
    return f"(stub) ordered {test} for patient {patient_id} → LAB-7781"


@function_tool
def prescribe(patient_id: str, drug: str, dose: str) -> str:
    """Prescribe a medication for patient_id."""
    return f"(stub) prescribed {drug} {dose} for patient {patient_id} → RX-4410"


@function_tool
def share_record(patient_id: str, recipient_email: str, recipient_domain: str) -> str:
    """Share patient_id's record with an external recipient.

    Pass the recipient's email and, separately, just the domain portion
    (the part after the @) as recipient_domain — the policy gates PHI
    egress on a domain allowlist, so a record can't leave for a personal
    inbox.

    Defense in depth: the enforcer only ever sees what the model puts in
    ``recipient_domain``, so a forged split (recipient_email on
    gmail.com, recipient_domain spoofed to an allowlisted hospital)
    would otherwise pass the gate and exfiltrate PHI. Re-derive the true
    domain from the address and refuse on any mismatch, so the gated
    value can't be decoupled from where the record actually goes.
    """
    actual_domain = recipient_email.rsplit("@", 1)[-1].strip().lower()
    if "@" not in recipient_email or actual_domain != recipient_domain.strip().lower():
        return (
            f"(stub) REFUSED: recipient_domain {recipient_domain!r} does not "
            f"match the address {recipient_email!r} — PHI not shared."
        )
    return f"(stub) shared patient {patient_id} record with {recipient_email}"


@function_tool
def get_billing_summary(patient_id: str) -> str:
    """Return the billing/claims summary (charges, payer, balance) for patient_id."""
    return (
        f"(stub) patient {patient_id} billing: payer=Aetna PPO, "
        f"outstanding balance $240.00, last claim CLM-5521 (paid)."
    )


# ---------------------------------------------------------------------------
# The agent. One definition; the role lives on the User passed at run time.
# ---------------------------------------------------------------------------


agent = Agent(
    name="healthcare_agent",
    instructions=(
        "You are a clinical assistant in a hospital EHR. Help authorized "
        "staff look up patient records, review labs, order tests, prescribe "
        "medications, and share records. When sharing a record, pass the "
        "recipient's email domain separately. You normally do not need to "
        "ask the user to confirm before invoking a tool — act directly on "
        "the details given in their message rather than echoing them back "
        "for approval. The policy layer is what gates sensitive actions, "
        "so trust it to stop anything you're not allowed to do. Always "
        "respond in the same language as the user's message."
    ),
    tools=[
        get_patient_record,
        view_lab_results,
        order_lab_test,
        prescribe,
        share_record,
        get_billing_summary,
    ],
    model="gpt-4o-mini",
)


# ---------------------------------------------------------------------------
# Demo: same prompt, three roles. Watch the decision flip with the role.
#   uv run python examples/healthcare_agent.py
# ---------------------------------------------------------------------------


async def _run_as(role: str, prompt: str) -> None:
    runner = HexgateRunner()
    result = await runner.run(
        agent=agent,
        input=prompt,
        user=User(
            user_id=f"clinician_{role}",
            session_id=f"session_{role}",
            role=role,
        ),
    )
    print(f"\n=== role={role} :: {prompt!r} ===")
    print(result)


async def main() -> None:
    load_dotenv()

    await _run_as("nurse", "Prescris de l'oxycodone 5mg pour le patient 88.")
    await _run_as("physician", "Prescris de l'oxycodone 5mg pour le patient 88.")
    await _run_as("physician", "Envoie le dossier du patient 88 à alice@gmail.com par e-mail.")
    # Same read prompt, two roles, back to back — watch the decision flip.
    await _run_as("physician", "Affiche le dossier complet du patient 88.")
    await _run_as("billing_staff", "Affiche le dossier complet du patient 88.")


if __name__ == "__main__":
    asyncio.run(main())
