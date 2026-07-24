"""Hexgate stacked-policy demo (marimo) — many module files, one signed decision.

A read-top-to-bottom tour of the policy **modules + linker** (SDK-side, fully
local — no platform, no API key):

  many module .yaml files  →  link()  →  one effective policy  →  (rego → wasm)

You'll see the two tiers compose — **guardrails** (caps + hard denies) over
**capabilities** (grants) — under the rule *fences intersect, grants union,
denies win*. Edit a decision's args and watch allow / deny / approval resolve
live. If `opa` is on PATH, each decision is also checked against the compiled
WASM engine so you can watch the two engines agree.

The same rules power `hexgate policy resolve --dir deploy/demo_policies`.

Run with `marimo edit deploy/policy_modules_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import json
    import shutil
    import tempfile
    from pathlib import Path
    from textwrap import dedent

    import marimo as mo

    from hexgate.security import (
        AgentPolicy,
        BaseToolPolicy,
        DecisionOutcome,
        LinkError,
        ModuleContent,
        compile_to_rego,
        compile_to_wasm,
        link,
        link_policy_set,
        load_local_modules,
        verdict_from_rego,
    )
    from hexgate.security.wasm_engine import WasmPolicy

    OPA = shutil.which("opa") is not None
    return (
        AgentPolicy,
        BaseToolPolicy,
        DecisionOutcome,
        LinkError,
        ModuleContent,
        OPA,
        Path,
        WasmPolicy,
        compile_to_rego,
        compile_to_wasm,
        dedent,
        json,
        link,
        link_policy_set,
        load_local_modules,
        mo,
        tempfile,
        verdict_from_rego,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🛡️ Hexgate — stacked policy

        Instead of one policy file per agent, an agent's policy is a **stack of
        modules** composed into one effective policy:

        - **Guardrails** (security-owned) — caps + hard denies. A guardrail
          `allow` is a *ceiling*, not a grant.
        - **Capabilities** (team-owned) — additive grants only.

        Composition rule: **fences intersect · grants union · denies win.**
        Everything below is local SDK code — no platform, no key.
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""## 1 · The module bundle""")
    return


@app.cell
def _(dedent):
    # Three modules — the same files that live in deploy/demo_policies/. Edit
    # them here and the whole notebook re-resolves.
    GUARDRAILS = {
        "org_core": dedent(
            """
            # floor: only subtracts what it names; unlisted tools pass through.
            default_policy: { mode: allow }
            tools:
              delete_database: { mode: deny }                                 # absolute
              refund_order: { mode: allow, constraints: ["args.amount <= 1000"] }  # cap
            """
        ),
    }
    CAPABILITIES = {
        "payments": dedent(
            """
            tools:
              refund_order: { mode: allow, constraints: ['args.currency in ["USD", "EUR"]'] }
              lookup_order: { mode: allow }
            """
        ),
        "support_leaf": dedent(
            """
            tools:
              send_email: { mode: allow }
              escalate: { mode: approval_required }
            """
        ),
    }
    return CAPABILITIES, GUARDRAILS


@app.cell
def _(CAPABILITIES, GUARDRAILS, Path, load_local_modules, tempfile):
    # Write the modules to a temp policies/ tree and load them through the real
    # local-files loader — exactly what `hexgate policy resolve --dir` does.
    _root = Path(tempfile.mkdtemp(prefix="hexgate-demo-"))
    for _kind, _mods in (("guardrails", GUARDRAILS), ("capabilities", CAPABILITIES)):
        _dir = _root / "policies" / _kind
        _dir.mkdir(parents=True, exist_ok=True)
        for _name, _body in _mods.items():
            (_dir / f"{_name}.yaml").write_text(_body, encoding="utf-8")

    guardrails, capabilities = load_local_modules(_root)
    return capabilities, guardrails


@app.cell
def _(capabilities, guardrails, mo):
    def _row(m):
        tools = ", ".join(sorted(m.policy.tools)) or "—"
        return {
            "module": m.name,
            "tier": m.kind,
            "tools": tools,
            "hash": m.content_hash[:12],
        }

    mo.ui.table(
        [_row(m) for m in (*guardrails, *capabilities)],
        selection=None,
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 2 · Link → one effective policy

        The **linker** folds the stack into a single `AgentPolicy`. That's the
        only thing that compiles — Rego/WASM never see the stack, so the
        pydantic-vs-WASM parity gate is untouched.
        """
    )
    return


@app.cell
def _(capabilities, guardrails, link_policy_set):
    result = link_policy_set(guardrails, capabilities)
    effective = result.effective["default"]
    return effective, result


@app.cell
def _(effective, mo):
    def _fmt(tp):
        line = f"**{tp.mode}**"
        if tp.constraints:
            line += "  ·  " + "  ∧  ".join(f"`{c}`" for c in tp.constraints)
        return line

    _rows = "\n".join(
        f"| `{name}` | {_fmt(tp)} |" for name, tp in sorted(effective.tools.items())
    )
    mo.md(
        "**Effective policy** (default_policy: `deny` — fail-closed)\n\n"
        "| tool | resolved rule |\n| --- | --- |\n" + _rows
    )
    return


@app.cell
def _(mo, result):
    # Provenance: which layers fed each rule, and which grants got shadowed by a
    # ceiling. This is what powers the analyzer + editor's file-attributed errors.
    _contrib = "\n".join(
        f"| `{tool}` | {', '.join(sorted({p.module for p in provs}))} |"
        for tool, provs in sorted(result.trace.contributors.items())
    )
    _shadow = (
        "\n\n**Shadowed (ineligible under a ceiling):** "
        + ", ".join(f"`{t}` ← {p.module}" for t, p in result.trace.shadowed.items())
        if result.trace.shadowed
        else "\n\n**Shadowed:** none (floor guardrail — nothing gated out)."
    )
    mo.md(
        "**Provenance** — every rule traces to its source layers\n\n"
        "| tool | contributing layers |\n| --- | --- |\n" + _contrib + _shadow
    )
    return


@app.cell
def _(OPA, WasmPolicy, compile_to_rego, compile_to_wasm, effective):
    # Build the WASM engine once (if opa is available) so decisions can be
    # cross-checked against the compiled production bundle.
    wasm_engine = None
    if OPA:
        _rego = compile_to_rego(effective.model_dump(mode="json"))
        wasm_engine = WasmPolicy.from_bytes(compile_to_wasm(_rego).wasm)
    return (wasm_engine,)


@app.cell
def _(result, verdict_from_rego, wasm_engine):
    def decide(tool, args):
        """Return (pydantic_outcome, wasm_outcome) for a tool call."""
        py = result.policy_set.evaluate(role="default", tool=tool, args=args).outcome.value
        if wasm_engine is None:
            return py, None
        wo = verdict_from_rego(
            wasm_engine.decide(role="default", tool=tool, args=args),
            tool_name=tool,
            role="default",
        ).outcome.value
        return py, wo

    return (decide,)


@app.cell
def _(mo):
    mo.md(
        """
        ## 3 · Try a decision

        Pick a tool and edit the args, then **▶ Check**. `refund_order` shows the
        interesting cases: over the $1000 cap → deny (guardrail), wrong currency →
        deny (no grant), `delete_database` → always deny, unlisted tool → deny.
        """
    )
    return


@app.cell
def _(effective, mo):
    _tools = sorted(effective.tools) + ["unlisted_tool"]
    try_it = (
        mo.md(
            """
            **tool** {tool}

            **args** (JSON)

            {args}
            """
        )
        .batch(
            tool=mo.ui.dropdown(_tools, value="refund_order"),
            args=mo.ui.text_area(value='{"amount": 800, "currency": "USD"}', full_width=True),
        )
        .form(submit_button_label="▶ Check decision")
    )
    try_it
    return (try_it,)


@app.cell
def _(OPA, decide, json, mo, try_it):
    def _box(engine, outcome):
        label, kind = {
            "allow": ("✅ allow", "success"),
            "deny": ("❌ deny", "danger"),
            "needs_approval": ("🔶 needs approval", "warn"),
        }.get(outcome, (f"— {outcome}", "neutral"))
        return mo.callout(mo.md(f"**{engine}**\n\n### {label}"), kind=kind)

    if try_it.value is None:
        _out = mo.callout(mo.md("Pick a tool + args, then **▶ Check decision**."), kind="info")
    else:
        _v = try_it.value
        try:
            _args = json.loads(_v["args"] or "{}")
            _py, _wo = decide(_v["tool"], _args)
            _boxes = [_box("pydantic · dev", _py)]
            if OPA:
                _boxes.append(_box("wasm · prod bundle", _wo))
            _footer = (
                ("### ✅ engines agree" if _py == _wo else "### ❌ engines DISAGREE")
                if OPA
                else "_(install `opa` to also check the WASM bundle)_"
            )
            _out = mo.vstack(
                [
                    mo.md(f"`{_v['tool']}({_args})`"),
                    mo.hstack(_boxes, widths="equal"),
                    mo.md(_footer),
                ]
            )
        except json.JSONDecodeError as _exc:
            _out = mo.callout(mo.md(f"Invalid JSON in args: {_exc}"), kind="warn")
    _out
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 4 · The combining rules

        Small self-contained bundles showing each rule. `M(...)` builds a module
        in-code so the rule is visible in one place.
        """
    )
    return


@app.cell
def _(AgentPolicy, BaseToolPolicy, ModuleContent):
    def M(name, kind, tools, default="allow"):
        return ModuleContent(
            name=name,
            kind=kind,
            policy=AgentPolicy(
                default_policy=BaseToolPolicy(mode=default), tools=tools
            ),
            source=f"{name}.yaml",
            content_hash=name,
        )

    def A(constraints=None):
        return BaseToolPolicy(mode="allow", constraints=constraints or [])

    def D(constraints=None):
        return BaseToolPolicy(mode="deny", constraints=constraints or [])

    return A, D, M


@app.cell
def _(A, D, M, evaluate_outcomes, link, mo):
    # grants UNION — allowed if EITHER capability's condition holds
    _usd = M("usd", "capability", {"refund": A(['args.currency == "USD"'])})
    _eur = M("eur", "capability", {"refund": A(['args.currency == "EUR"'])})
    _union, _ = link([], [_usd, _eur])

    # fences INTERSECT — two guardrail caps → the stricter wins
    _g1 = M("cap1000", "guardrail", {"refund": A(["args.amount <= 1000"])})
    _g2 = M("cap500", "guardrail", {"refund": A(["args.amount <= 500"])})
    _intersect, _ = link([_g1, _g2], [M("c", "capability", {"refund": A()})])

    # deny WINS — guardrail deny beats a capability grant
    _dw, _ = link(
        [M("g", "guardrail", {"wire": D()})], [M("c", "capability", {"wire": A()})]
    )

    mo.vstack(
        [
            mo.md("**grants union** — `refund` allowed for USD **or** EUR"),
            evaluate_outcomes(
                _union,
                [("refund", {"currency": "USD"}), ("refund", {"currency": "GBP"})],
            ),
            mo.md("**fences intersect** — caps 1000 ∧ 500 → stricter 500 wins"),
            evaluate_outcomes(
                _intersect, [("refund", {"amount": 400}), ("refund", {"amount": 700})]
            ),
            mo.md("**deny wins** — guardrail deny beats the grant"),
            evaluate_outcomes(_dw, [("wire", {})]),
        ]
    )
    return


@app.cell
def _(mo):
    def evaluate_outcomes(policy, cases):
        from hexgate.security import evaluate_tool_call

        emoji = {"allow": "✅", "deny": "❌", "needs_approval": "🔶"}
        parts = []
        for tool, args in cases:
            o = evaluate_tool_call(policy, tool, args).outcome.value
            parts.append(f"`{tool}({args})` → {emoji.get(o, '')} **{o}**")
        return mo.md("&nbsp;&nbsp;·&nbsp;&nbsp;".join(parts))

    return (evaluate_outcomes,)


@app.cell
def _(A, D, LinkError, M, link, mo):
    # Capabilities may only grant — a capability that tries to deny is a hard
    # LinkError, so a team can never silently punch a hole in a guardrail.
    try:
        link([], [M("rogue", "capability", {"refund": D()})])
        _msg = "no error (unexpected)"
    except LinkError as exc:
        _msg = str(exc)
    mo.callout(
        mo.md(f"**capabilities can't deny**\n\n```\n{_msg}\n```"), kind="danger"
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 5 · Ceiling vs floor

        A guardrail's `default_policy` sets its posture. Same capabilities below,
        two guardrails:

        - **floor** (`default_policy: allow`) — only subtracts named tools;
          `lookup_order` / `send_email` pass through.
        - **ceiling** (`default_policy: deny`) — a tool it doesn't list is
          *ineligible*, so those same grants are shadowed → deny.
        """
    )
    return


@app.cell
def _(A, D, M, link, mo):
    from hexgate.security import evaluate_tool_call

    _caps = [
        M("payments", "capability", {"refund": A(["args.amount <= 1000"]), "lookup_order": A()}),
        M("leaf", "capability", {"send_email": A()}),
    ]
    _floor = M("g", "guardrail", {"refund": A(), "delete": D()}, default="allow")
    _ceiling = M("g", "guardrail", {"refund": A(), "delete": D()}, default="deny")

    _eff_floor, _ = link([_floor], _caps)
    _eff_ceiling, _ = link([_ceiling], _caps)

    def _o(policy, tool):
        return evaluate_tool_call(policy, tool, {"amount": 500}).outcome.value

    _tools = ["refund", "lookup_order", "send_email", "delete"]
    _rows = "\n".join(
        f"| `{t}` | {_o(_eff_floor, t)} | {_o(_eff_ceiling, t)} |" for t in _tools
    )
    mo.md(
        "| tool | floor guardrail | ceiling guardrail |\n"
        "| --- | --- | --- |\n" + _rows
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ---
        **Try it yourself:** edit the module YAML in cell 1 and the whole notebook
        re-resolves. Or run the same thing from the CLI:

        ```
        hexgate policy resolve --dir deploy/demo_policies
        ```
        """
    )
    return


if __name__ == "__main__":
    app.run()
