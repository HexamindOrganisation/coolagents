"""Hexgate agent-gate demo (marimo) — gate whole agents by policy, in code.

A code-only tour of agent-level enforcement, the sibling to the egress gate. No
platform, no API key, no model call. Hexgate normally gates the *tool call* the
model proposes; this gate sits one level up and asks two questions from the same
policy engine:

  * admission — may this caller, in this role, *run this agent at all*?
  * reach     — which *other* agents may it call as a tool or hand off to?

Both lower to synthetic tool keys (`agent.run`, `agent.tool:<name>`,
`agent.handoff:<name>`), so the same engine decides them through the same path as
any tool. Admission is enforced at run entry today; the handoff interception in
the framework adapters is the next slice, but the policy already decides it.

Run with `uv run --with marimo marimo edit deploy/agent_gate_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import marimo as mo
    import yaml

    from hexgate import HexgateContext
    from hexgate.security import (
        AGENT_RUN_TOOL,
        AgentNotAdmittedError,
        agent_target_key,
        resolve_agent_gate,
    )
    from hexgate.security.enforcer import build_enforcer
    from hexgate.security.policy_set import load_policy_set_from_dict

    return (
        AGENT_RUN_TOOL,
        AgentNotAdmittedError,
        HexgateContext,
        agent_target_key,
        build_enforcer,
        load_policy_set_from_dict,
        mo,
        resolve_agent_gate,
        yaml,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🚪 Hexgate — gating whole agents

        The tool gate answers "may the model run *this tool* with *these args*?".
        The **agent gate** sits one level up and answers two more, from the same
        policy engine:

        - **admission** — may this caller, in this role, *start this agent at all*?
          Checked at run entry, before the model sees anything.
        - **reach** — which *other* agents may it call as a tool, or hand the whole
          conversation off to?

        Both lower to synthetic tool keys (`agent.run`, `agent.tool:<name>`,
        `agent.handoff:<name>`), so there is no second decision path: the same
        engine, constraints, and audit apply. This demo is **code-only** — no
        platform, no API key, no model call.
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""## 1 · The policy""")
    return


@app.cell
def _(load_policy_set_from_dict, yaml):
    # A refund agent that can consult a billing-bot. support may run it and call
    # billing-bot as a tool, but must never hand the customer conversation off.
    # billing may hand off, with a human's approval and only one hop deep.
    # contractor cannot start the agent at all. Any undefined role falls to
    # `default`, which denies admission — closed-world for free.
    POLICY_YAML = """
version: 1
roles:
  default:
    default_policy: { mode: deny }
    admission: { mode: deny }

  support:
    default_policy: { mode: deny }
    admission: { mode: allow }
    agents:
      billing-bot:
        via: [tool]                  # consult as a tool; never hand off
        mode: allow

  billing:
    default_policy: { mode: deny }
    admission: { mode: allow }
    agents:
      billing-bot:
        via: [tool, handoff]         # may also hand off...
        mode: approval_required      # ...with a human's approval
        constraints: ["args.depth <= 1"]   # ...and only one hop deep

  contractor:
    default_policy: { mode: deny }
    admission: { mode: deny }        # cannot start the agent at all
"""
    ps = load_policy_set_from_dict(yaml.safe_load(POLICY_YAML))
    return POLICY_YAML, ps


@app.cell
def _(POLICY_YAML, mo):
    mo.md(
        f"""
        Written once, in ordinary policy YAML. `admission` is ingress (may I run
        this agent), `agents` is egress (which agents may I reach, and how).

        ```yaml{POLICY_YAML}```
        """
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 2 · Admission — decided at run entry

        This is the exact check `HexgateAgent` runs at the top of every run, before
        the model. A refused caller never starts the agent; the run raises
        `AgentNotAdmittedError` instead. No model call is involved, so we drive the
        gate directly here.
        """
    )
    return


@app.cell
def _(
    AgentNotAdmittedError,
    HexgateContext,
    build_enforcer,
    mo,
    ps,
    resolve_agent_gate,
):
    def admit(role):
        # A fresh enforcer + gate, exactly as enforce_policy builds them.
        gate = resolve_agent_gate(build_enforcer(ps, agent_name="refund_agent"))
        roles = [role] if role is not None else []
        with HexgateContext(user_id="demo", user_roles=roles).sync_scope():
            try:
                gate.check_admission()
                return "allow", ""
            except AgentNotAdmittedError as exc:
                return exc.decision.outcome.value, exc.decision.reason

    _label = {
        "allow": "✅ admitted",
        "deny": "❌ refused",
        "needs_approval": "🔶 approval",
    }
    _cases = [
        "support",  # admitted
        "billing",  # admitted
        "contractor",  # refused (admission: deny)
        "intern",  # undefined role -> falls to default -> refused
        None,  # no role at all -> default -> refused
    ]
    _rows = ["| caller role | may run `refund_agent`? |", "|---|---|"]
    for _role in _cases:
        _outcome, _ = admit(_role)
        _shown = _role if _role is not None else "_(none)_"
        _rows.append(f"| `{_shown}` | {_label.get(_outcome, _outcome)} |")
    mo.md("\n".join(_rows))
    return (admit,)


@app.cell
def _(mo):
    mo.md(
        """
        ## 3 · Reach — which agents may this agent call or hand off to

        The same engine decides agent-to-agent reach. `agent.tool:<name>` is
        calling a sub-agent as a tool (the orchestrator keeps control);
        `agent.handoff:<name>` is transferring the whole conversation. A policy can
        allow one and gate the other.

        > Admission (section 2) is enforced at run entry today. The handoff
        > *interception* inside the framework adapters is the next slice; the policy
        > below already decides it through the same path.
        """
    )
    return


@app.cell
def _(agent_target_key, mo, ps):
    def _reach(role, via, target, **args):
        return ps.evaluate(
            role=role, tool=agent_target_key(via, target), args=args
        ).outcome.value

    _label = {"allow": "✅ allow", "deny": "❌ deny", "needs_approval": "🔶 approval"}
    # (role, via, args, note)
    _cases = [
        ("support", "tool", {}, "consult billing-bot as a tool"),
        ("support", "handoff", {}, "hand the customer to billing-bot"),
        ("billing", "tool", {"depth": 0}, "consult billing-bot as a tool"),
        ("billing", "handoff", {"depth": 0}, "hand off (1 hop)"),
        ("billing", "handoff", {"depth": 2}, "hand off (2 hops — over the cap)"),
    ]
    _rows = ["| role | reach `billing-bot` via | decision | |", "|---|---|---|---|"]
    for _role, _via, _args, _note in _cases:
        _outcome = _reach(_role, _via, "billing-bot", **_args)
        _rows.append(
            f"| `{_role}` | `{_via}` | {_label.get(_outcome, _outcome)} | {_note} |"
        )
    mo.md("\n".join(_rows))
    return


@app.cell
def _(mo):
    mo.md("""## 4 · Your turn""")
    return


@app.cell
def _(mo):
    role_form = (
        mo.md("**Caller role** {role}")
        .batch(
            role=mo.ui.dropdown(
                options=["support", "billing", "contractor", "intern"],
                value="support",
            )
        )
        .form(submit_button_label="▶ Check admission")
    )
    role_form
    return (role_form,)


@app.cell
def _(admit, mo, role_form):
    if role_form.value is None:
        _out = mo.callout(
            mo.md("Pick a role and click **▶ Check admission**."), kind="info"
        )
    else:
        _role = role_form.value["role"]
        _outcome, _reason = admit(_role)
        if _outcome == "allow":
            _out = mo.callout(
                mo.md(f"`{_role}` is **admitted** — the agent run starts."),
                kind="success",
            )
        else:
            _detail = f"\n\nreason: {_reason}" if _reason else ""
            _out = mo.callout(
                mo.md(
                    f"`{_role}` is **refused** (`{_outcome}`) — the run never "
                    f"starts, `AgentNotAdmittedError` is raised.{_detail}"
                ),
                kind="danger",
            )
    _out
    return


if __name__ == "__main__":
    app.run()
