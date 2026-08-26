"""Hexgate support-bot demo (marimo) — one modular policy, tools *and* agents.

A read-top-to-bottom tour of a small customer-support system where the WHOLE
policy — tool permissions *and* agent-to-agent reach — is composed from the same
shared modules by the linker, then enforced. Fully local (no platform, no API
key, no model call):

  many module .yaml files  →  resolve_for_project()  →  one PolicySet per role

The system has two agents: a front-line `support_bot` and a refunds specialist
`billing_bot`. A role's policy governs both what tools it may call (support caps
out before refunds; billing refunds up to the boundary's $1000 ceiling) *and*
whether `support_bot` may hand the conversation off to `billing_bot`. Agent
reach is closed-world: no role may reach `billing_bot` until a capability grants
it — the same module pipeline as tools (new in the agent-reach work).

Run with `uv run --with marimo marimo edit deploy/support_bot_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import os
    import shutil
    import tempfile
    from pathlib import Path
    from textwrap import dedent

    # Force offline: the gate's enforcer wires an audit sender that otherwise
    # falls back to HEXGATE_API_KEY. This is a policy tour — keep it local.
    os.environ["HEXGATE_LOCAL_MODE"] = "1"

    import marimo as mo

    from hexgate import HexgateContext
    from hexgate.security import (
        ReachNotAllowedError,
        agent_target_key,
        load_local_modules,
        resolve_for_project,
        resolve_reach_gate,
    )
    from hexgate.security.enforcer import build_enforcer

    return (
        HexgateContext,
        Path,
        ReachNotAllowedError,
        agent_target_key,
        build_enforcer,
        dedent,
        load_local_modules,
        mo,
        resolve_for_project,
        resolve_reach_gate,
        shutil,
        tempfile,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🎧 Hexgate — one modular policy, tools *and* agents

        A customer-support system with two agents: front-line `support_bot` and
        refunds specialist `billing_bot`. Everything a role may do is composed
        from the **same shared modules**:

        - **Tool permissions** — may this role call this tool with these args?
        - **Agent reach** — may `support_bot` hand the conversation off to
          `billing_bot`?

        Both are authored as modules (security's **boundary** + teams'
        **capabilities**), bound to roles, and folded by the linker into one
        `PolicySet` per role. Agent-level policy is modular too — it rides the
        exact same pipeline as tools. All local: no platform, no API key, no
        model call.
        """
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 1 · The modules

        One **boundary** (security-owned) sets the org's allowed surface and its
        caps — including the ceiling on agent reach: `support_bot` may *hand off*
        to `billing_bot` (never call it as a tool). **Capabilities** (team-owned)
        grant subsets. A **role** names the capabilities it imports.
        """
    )
    return


@app.cell
def _(dedent):
    # Edit these and the whole notebook re-resolves. The boundary is a ceiling
    # (default deny): it enumerates the allowed surface, so a tool — or a reach
    # target — it doesn't list is ineligible no matter what a capability grants.
    BOUNDARIES = {
        "org_core": dedent(
            """
            default_policy: { mode: deny }
            tools:
              view_orders:     { mode: allow }
              send_email:      { mode: allow }
              escalate:        { mode: allow }
              refund_order:    { mode: allow, constraints: ["args.amount <= 1000"] }  # hard cap
              delete_database: { mode: deny }                                          # absolute
            agents:
              # reach ceiling: hand-off to billing_bot is permitted; agent-as-tool
              # is not (billing_bot must own the conversation for a refund).
              billing_bot: { via: [handoff], mode: allow }
            """
        ),
    }
    CAPABILITIES = {
        "read_only": dedent(
            """
            tools:
              view_orders: { mode: allow }
            """
        ),
        "support_leaf": dedent(
            """
            tools:
              send_email: { mode: allow }
              escalate:   { mode: approval_required }
            """
        ),
        "payments": dedent(
            """
            tools:
              refund_order: { mode: allow, constraints: ['args.currency in ["USD", "EUR"]'] }
            """
        ),
        "billing_reach": dedent(
            """
            # grants the agent-level reach: this role's support_bot may hand off
            # to billing_bot. No grant -> closed-world deny.
            agents:
              billing_bot: { via: [handoff], mode: allow }
            """
        ),
    }
    # Role -> the capabilities it imports (the boundary applies to every role).
    ROLES = {
        "default": ["read_only"],
        "support": ["read_only", "support_leaf"],
        "billing": ["read_only", "payments", "billing_reach"],
    }
    return BOUNDARIES, CAPABILITIES, ROLES


@app.cell
def _(BOUNDARIES, CAPABILITIES, Path, load_local_modules, shutil, tempfile):
    # Write the modules to a policies/ tree and load them through the real
    # local-files loader — the same path as `hexgate policy resolve --dir`. A
    # stable dir (recreated each run) so re-running on an edit doesn't leak.
    def _write_modules(boundaries, capabilities):
        root = Path(tempfile.gettempdir()) / "hexgate-support-demo"
        shutil.rmtree(root, ignore_errors=True)
        for kind, mods in (
            ("boundaries", boundaries),
            ("capabilities", capabilities),
        ):
            d = root / "policies" / kind
            d.mkdir(parents=True, exist_ok=True)
            for name, body in mods.items():
                (d / f"{name}.yaml").write_text(body, encoding="utf-8")
        return load_local_modules(root)

    boundaries, library = _write_modules(BOUNDARIES, CAPABILITIES)
    return boundaries, library


@app.cell
def _(ROLES, boundaries, library, resolve_for_project):
    # One resolve. The role-keyed PolicySet carries tools AND agent reach — the
    # fold lowers the `agents` blocks to `agent.handoff:<target>` keys and
    # composes them exactly like tool keys.
    policy_set = resolve_for_project(boundaries, library, ROLES).policy_set
    return (policy_set,)


@app.cell
def _(ROLES, mo, policy_set):
    _LABEL = {"allow": "✅", "deny": "❌", "needs_approval": "🔶 approval"}
    _CALLS = [
        ("view_orders", {}),
        ("send_email", {}),
        ("escalate", {}),
        ("refund_order", {"amount": 800, "currency": "USD"}),
        ("refund_order", {"amount": 2000, "currency": "USD"}),
    ]

    def _cell(role, tool, args):
        o = policy_set.evaluate(role=role, tool=tool, args=args).outcome.value
        return _LABEL.get(o, o)

    _cols = [f"`{t}`" + (f"<br>`{a}`" if a else "") for t, a in _CALLS]
    _header = "| role | " + " | ".join(_cols) + " |"
    _sep = "|" + "---|" * (len(_CALLS) + 1)
    _rows = [
        "| `" + r + "` | " + " | ".join(_cell(r, t, a) for t, a in _CALLS) + " |"
        for r in ROLES
    ]
    mo.md(
        "**Resolved tool policy, per role**\n\n" + "\n".join([_header, _sep, *_rows])
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 2 · Agent reach — composed from the same modules

        Reach is **closed-world**: no role may reach `billing_bot` until a
        capability grants it. Only `billing` imports `billing_reach`, so only
        `billing` may hand `support_bot`'s conversation off — `support` and
        `default` are denied, and nobody may reach it *as a tool* (the boundary
        ceilinged `handoff` only). This runs the real `ReachGate` — the seam the
        framework calls at a hand-off — over the modularly-composed policy.
        """
    )
    return


@app.cell
def _(
    HexgateContext,
    ReachNotAllowedError,
    build_enforcer,
    policy_set,
    resolve_reach_gate,
):
    def reach(role, via="handoff", target="billing_bot"):
        """Run the real ReachGate for `role`: may support_bot reach `target`?

        Returns (outcome, reason). The source agent's policy governs reach, so
        the gate is built from support_bot's enforcer and decides the target's
        lowered key. No-op-safe: closed-world denies an ungranted role."""
        gate = resolve_reach_gate(build_enforcer(policy_set, agent_name="support_bot"))
        roles = [role] if role is not None else []
        with HexgateContext(user_id="demo", user_roles=roles).sync_scope():
            try:
                gate.check_reach(target, via=via)
                return "allow", ""
            except ReachNotAllowedError as exc:
                return exc.decision.outcome.value, exc.decision.reason

    return (reach,)


@app.cell
def _(mo, reach):
    _LABEL = {"allow": "✅ allowed", "deny": "❌ refused", "needs_approval": "🔶 approval"}
    _rows = [
        "| caller role | `support_bot` → `billing_bot` (handoff) | (as tool) |",
        "|---|---|---|",
    ]
    for _role in ["default", "support", "billing"]:
        _h, _ = reach(_role, via="handoff")
        _t, _ = reach(_role, via="tool")
        _rows.append(f"| `{_role}` | {_LABEL.get(_h, _h)} | {_LABEL.get(_t, _t)} |")
    mo.md(
        "**Reach, live from the gate**\n\n"
        + "\n".join(_rows)
        + "\n\n> `billing` was granted `handoff` by the `billing_reach` "
        "capability; `support`/`default` hit the closed-world deny; and "
        "*as-tool* reach is refused for everyone (the boundary ceilinged "
        "`handoff` only)."
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 3 · Capping hand-off depth

        The boundary can also **cap how deep a hand-off chain goes** with a
        constraint on `args.depth` — the framework's hand-off seam supplies the
        current depth. Here we author the cap and pass the depth explicitly to
        show it: one hop is allowed, a second is refused.
        """
    )
    return


@app.cell
def _(
    Path,
    agent_target_key,
    dedent,
    load_local_modules,
    mo,
    resolve_for_project,
    shutil,
    tempfile,
):
    def _resolve_depth_capped():
        root = Path(tempfile.gettempdir()) / "hexgate-support-depth"
        shutil.rmtree(root, ignore_errors=True)
        (root / "policies" / "boundaries").mkdir(parents=True, exist_ok=True)
        cap = root / "policies" / "capabilities"
        cap.mkdir(parents=True, exist_ok=True)
        (root / "policies" / "boundaries" / "org.yaml").write_text(
            dedent(
                """
                default_policy: { mode: deny }
                agents:
                  billing_bot: { via: [handoff], mode: allow, constraints: ["args.depth <= 1"] }
                """
            )
        )
        (cap / "billing_reach.yaml").write_text(
            "agents:\n  billing_bot: { via: [handoff], mode: allow }\n"
        )
        b, lib = load_local_modules(root)
        return resolve_for_project(b, lib, {"default": ["billing_reach"]}).policy_set

    _ps = _resolve_depth_capped()
    _key = agent_target_key("handoff", "billing_bot")
    _hop1 = _ps.evaluate(role="default", tool=_key, args={"depth": 1}).outcome.value
    _hop2 = _ps.evaluate(role="default", tool=_key, args={"depth": 2}).outcome.value
    mo.md(
        "boundary reach cap `args.depth <= 1`:\n\n"
        f"- hand-off at depth 1 → **{_hop1}**\n"
        f"- hand-off at depth 2 → **{_hop2}** (over the cap)"
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 4 · One pipeline

        Nothing above is bolted on: the tool table (§1) and the reach table (§2)
        came from the **same** `resolve_for_project` call over the same modules.
        Agent-level policy — reach here, and admission the same way — lowers to
        `agent.*` decision keys the linker folds like any tool, so a boundary
        can cap it and a capability can grant it, bound to roles.
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""## 5 · Your turn""")
    return


@app.cell
def _(mo):
    play = (
        mo.md("""**caller role** {role} &nbsp;&nbsp; **reach via** {via}""")
        .batch(
            role=mo.ui.dropdown(
                options=["default", "support", "billing"], value="support"
            ),
            via=mo.ui.dropdown(options=["handoff", "tool"], value="handoff"),
        )
        .form(submit_button_label="▶ Check reach")
    )
    play
    return (play,)


@app.cell
def _(mo, play, policy_set, reach):
    if play.value is None:
        _out = mo.callout(mo.md("Pick a role + via, then **▶ Check reach**."), kind="info")
    else:
        _role = play.value["role"]
        _via = play.value["via"]
        _outcome, _reason = reach(_role, via=_via)
        _refund = policy_set.evaluate(
            role=_role, tool="refund_order", args={"amount": 800, "currency": "USD"}
        ).outcome.value
        if _outcome == "allow":
            _reach_md = mo.callout(
                mo.md(
                    f"**Reach ✅** — as `{_role}`, `support_bot` may `{_via}` to "
                    f"`billing_bot`."
                ),
                kind="success",
            )
        else:
            _detail = f"\n\nreason: {_reason}" if _reason else ""
            _reach_md = mo.callout(
                mo.md(
                    f"**Reach ❌** — as `{_role}`, `support_bot` may not `{_via}` "
                    f"to `billing_bot` (`{_outcome}`).{_detail}"
                ),
                kind="danger",
            )
        _out = mo.vstack(
            [
                _reach_md,
                mo.md(
                    f"For reference, `refund_order($800, USD)` as `{_role}` → "
                    f"**{_refund}** (same modular policy, tool side)."
                ),
            ]
        )
    _out
    return


@app.cell
def _(mo):
    mo.md(
        """
        ---
        The same linker + rules power the CLI — point it at a policies/ tree of
        your own:

        ```
        hexgate policy resolve --dir <your policies/ dir>
        ```

        Reach and admission are enforced at run entry / hand-off by the
        `ReachGate` / `AgentGate` seams a live agent runs, over the policy the
        linker composed from these modules.
        """
    )
    return


if __name__ == "__main__":
    app.run()
