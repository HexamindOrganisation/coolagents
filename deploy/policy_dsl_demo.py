"""Hexgate policy DSL demo (marimo) — write conditions, see both engines agree.

A read-top-to-bottom tour of the constraint grammar (count/every/any, cross-field,
string functions, and/or/not, consts, role/tool facts). Every decision is run
through BOTH engines — the pydantic engine (dev / fallback) and the compiled WASM
engine (the signed production bundle) — so you can watch them agree, including on
the fail-closed edge cases.

Needs `opa` on PATH for the WASM column (`brew install opa`); without it the demo
still runs pydantic-only and says so.

Run with `marimo edit deploy/policy_dsl_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import json
    import shutil

    import marimo as mo
    import yaml

    from hexgate.security import (
        WasmPolicy,
        compile_to_wasm,
        load_policy_set_from_dict,
    )
    from hexgate.security.rego import compile_to_rego

    OPA = shutil.which("opa") is not None
    return (
        OPA,
        WasmPolicy,
        compile_to_rego,
        compile_to_wasm,
        json,
        load_policy_set_from_dict,
        mo,
        yaml,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🛡️ Hexgate — writing conditions

        A tour of the constraint grammar. Every decision below is evaluated by
        **both** engines and shown side by side:

        - **pydantic** — the in-process engine used in local dev,
        - **WASM** — the compiled, signed policy bundle that runs in production.

        They must always **agree**. That equivalence is the whole point — a policy
        you test locally behaves identically once shipped.
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""## 1 · The policy""")
    return


@app.cell
def _(OPA, WasmPolicy, compile_to_rego, compile_to_wasm, load_policy_set_from_dict, yaml):
    # A support agent: email customers, issue refunds, read files, deploy — each
    # tool gated by conditions on its arguments. Edit freely and re-run.
    POLICY = """
    version: 1

    consts:
      max_recipients: 5
      prod_env: "production"

    roles:
      base:                                    # shared constants, inherited
        is_mixin: true
        consts:
          max_recipients: 5
          prod_env: "production"

      default:
        inherits: [base]
        tools:
          send_email:
            mode: allow
            constraints:
              - count(args.to) <= consts.max_recipients          # count() + const
              - every(args.to, endswith(., "@acme.com"))         # quantifier over a list
          refund:
            mode: allow
            constraints:
              - args.amount <= args.limit                        # cross-field
              - matches(args.ticket, "^INC-[0-9]+$")             # regex
          read_file:
            mode: allow
            constraints:
              - startswith(args.path, "/srv/") and not contains(args.path, "..")
          deploy:
            mode: approval_required
            constraints:
              - args.env != consts.prod_env or role == "admin"   # or + role fact

      admin:
        inherits: [base]
        tools:
          deploy: { mode: allow, constraints: ['role == "admin"'] }
    """

    payload = yaml.safe_load(POLICY)
    ps = load_policy_set_from_dict(payload)                 # pydantic engine
    wasm = (
        WasmPolicy.from_bytes(compile_to_wasm(compile_to_rego(payload)).wasm)
        if OPA
        else None
    )
    return POLICY, ps, wasm


@app.cell
def _(POLICY, mo):
    mo.md(f"```yaml{POLICY}```")
    return


@app.cell
def _(mo):
    mo.md(
        """
        ### …or write it in code

        The same rules, built with `PolicyBuilder` + `C` (typed, validated at the
        call site) — and the YAML they render to. Two ways to author, one grammar.
        """
    )
    return


@app.cell
def _(mo, yaml):
    import inspect

    from hexgate import C, PolicyBuilder

    def _demo_policy():
        return (
            PolicyBuilder(default="deny")
            .allow(
                "refund",
                when=[
                    C("args.amount") <= C("args.limit"),        # cross-field, typed
                    'matches(args.ticket, "^INC-[0-9]+$")',     # functions: grammar string
                ],
            )
            .allow(
                "send_email",
                when=[
                    C("args.to").count() <= 5,
                    'every(args.to, endswith(., "@acme.com"))',
                ],
            )
            .approve("deploy", when=['args.env != "production" or role == "admin"'])
            .build()
        )

    _src = inspect.getsource(_demo_policy)
    _yaml = yaml.dump(_demo_policy().model_dump(exclude_defaults=True), sort_keys=False)
    mo.hstack(
        [
            mo.vstack([mo.md("**Written in Python**"), mo.md(f"```python\n{_src}```")]),
            mo.vstack([mo.md("**Renders to YAML**"), mo.md(f"```yaml\n{_yaml}```")]),
        ],
        widths="equal",
    )
    return


@app.cell
def _(ps, wasm):
    # One decision, both engines. Returns (pydantic, wasm) outcome strings.
    def decide(role, tool, args):
        py = ps.evaluate(role=role, tool=tool, args=args).outcome.value
        if wasm is None:
            return py, "n/a (no opa)"
        d = wasm.decide(role=role, tool=tool, args=args)
        wo = "allow" if d.allow else ("needs_approval" if d.requires_approval else "deny")
        return py, wo

    return (decide,)


@app.cell
def _(mo):
    mo.md(
        """
        ## 2 · Real tool calls, both engines

        Each row is a `(role, tool, args)` decision. The **agree** column is what
        matters.
        """
    )
    return


@app.cell
def _(decide, mo):
    _cases = [
        ("default", "send_email", {"to": ["a@acme.com", "b@acme.com"]}),
        ("default", "send_email", {"to": ["x@gmail.com"]}),                 # not @acme
        ("default", "send_email", {"to": ["a@acme.com"] * 6}),              # > max
        ("default", "refund", {"amount": 50, "limit": 100, "ticket": "INC-42"}),
        ("default", "refund", {"amount": 200, "limit": 100, "ticket": "INC-42"}),  # >limit
        ("default", "refund", {"amount": 50, "limit": 100, "ticket": "nope"}),     # bad id
        ("default", "read_file", {"path": "/srv/app.log"}),
        ("default", "read_file", {"path": "/srv/../etc/passwd"}),           # contains ..
        ("default", "read_file", {"path": "/etc/passwd"}),                  # not /srv/
        ("default", "deploy", {"env": "staging"}),                          # approval
        ("default", "deploy", {"env": "production"}),                       # deny
        ("admin", "deploy", {"env": "production"}),                         # admin -> allow
    ]

    _rows = ["| role | tool | args | pydantic | wasm | agree |", "|---|---|---|---|---|---|"]
    for _role, _tool, _args in _cases:
        _py, _wo = decide(_role, _tool, _args)
        _agree = "✅" if _py == _wo else "❌"
        _rows.append(f"| {_role} | `{_tool}` | `{_args}` | **{_py}** | **{_wo}** | {_agree} |")
    mo.md("\n".join(_rows))
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 3 · Fail-closed & type safety

        Missing arguments, wrong-typed arguments, empty collections — the safe
        defaults, agreed by both engines.
        """
    )
    return


@app.cell
def _(decide, mo):
    _edge = [
        ("refund missing amount", "refund", {"limit": 100, "ticket": "INC-1"}),
        ("refund wrong type", "refund", {"amount": "lots", "limit": 100, "ticket": "INC-1"}),
        ("send_email empty list", "send_email", {"to": []}),      # every([]) → allow
        ("send_email missing arg", "send_email", {}),
    ]
    _rows = ["| case | pydantic | wasm | agree |", "|---|---|---|---|"]
    for _label, _tool, _args in _edge:
        _py, _wo = decide("default", _tool, _args)
        _rows.append(f"| {_label} | **{_py}** | **{_wo}** | {'✅' if _py == _wo else '❌'} |")
    mo.md("\n".join(_rows))
    return


@app.cell
def _(mo):
    mo.md("""## 4 · Try it yourself""")
    return


@app.cell
def _(mo):
    # A form: edit the inputs, then click the submit button to apply them.
    # `try_it.value` stays None until the first submit, and only changes on
    # subsequent submits — so nothing recomputes until you ask it to.
    try_it = (
        mo.md(
            """
            **role** {role} &nbsp; **tool** {tool}

            **args** (JSON)

            {args}
            """
        )
        .batch(
            role=mo.ui.dropdown(["default", "admin"], value="default"),
            tool=mo.ui.dropdown(
                ["send_email", "refund", "read_file", "deploy"], value="refund"
            ),
            args=mo.ui.text_area(
                value='{"amount": 50, "limit": 100, "ticket": "INC-7"}',
                full_width=True,
            ),
        )
        .form(submit_button_label="▶ Check decision")
    )
    try_it
    return (try_it,)


@app.cell
def _(decide, json, mo, try_it):
    # Each box's colour reflects THAT engine's decision (allow ✅ green /
    # deny ❌ red / approval 🔶 amber). Agreement is a separate line below.
    def _box(engine, outcome):
        label, kind = {
            "allow": ("✅ allow", "success"),
            "deny": ("❌ deny", "danger"),
            "needs_approval": ("🔶 needs approval", "warn"),
        }.get(outcome, (f"— {outcome}", "neutral"))
        return mo.callout(mo.md(f"**{engine}**\n\n### {label}"), kind=kind)

    if try_it.value is None:
        _out = mo.callout(
            mo.md("Edit role / tool / args above, then click **▶ Check decision**."),
            kind="info",
        )
    else:
        _v = try_it.value
        try:
            _args = json.loads(_v["args"] or "{}")
            _py, _wo = decide(_v["role"], _v["tool"], _args)
            _agree = _py == _wo
            _out = mo.vstack(
                [
                    mo.md(f"`{_v['role']}` → `{_v['tool']}({_args})`"),
                    mo.hstack(
                        [_box("pydantic · dev", _py), _box("wasm · prod bundle", _wo)],
                        widths="equal",
                    ),
                    mo.md(
                        "### ✅ the two engines agree"
                        if _agree
                        else "### ❌ the two engines DISAGREE"
                    ),
                ]
            )
        except json.JSONDecodeError as _exc:
            _out = mo.callout(mo.md(f"Invalid JSON in args: {_exc}"), kind="warn")
    _out
    return


if __name__ == "__main__":
    app.run()
