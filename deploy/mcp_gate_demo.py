"""Hexgate MCP gate demo (marimo) — a third-party MCP server, gated by policy.

Attaches a real MCP server over stdio, auto-enumerates its tools under the
`mcp-<server>-<tool>` namespace, and runs every call through the SAME policy
engine (and constraint DSL) that guards native tools — default-deny, an
allowlist, and per-argument constraints. Allowed calls actually execute against
the live server; denied ones are blocked before the server ever sees them.

The server is a tiny FastMCP script (deploy/_mcp_demo_server.py) this notebook
spawns as a subprocess — no external services, no LLM key.

Run with `marimo edit deploy/mcp_gate_demo.py`.
"""

import marimo

__generated_with = "0.23.10"
app = marimo.App(width="medium")


@app.cell
def _():
    import asyncio
    import json
    import sys
    from pathlib import Path

    import marimo as mo
    import yaml

    from hexgate.adapters.langchain.tools import GuardedTool
    from hexgate.mcp import MCPServerConfig, MCPToolset
    from hexgate.security.enforcer import build_enforcer
    from hexgate.security.policy_set import load_policy_set_from_dict

    # The FastMCP server this notebook spawns over stdio (its own file so
    # marimo's format round-tripping can't strip it).
    SERVER_PATH = str(Path(__file__).resolve().parent / "_mcp_demo_server.py")
    return (
        GuardedTool,
        MCPServerConfig,
        MCPToolset,
        Path,
        SERVER_PATH,
        asyncio,
        build_enforcer,
        json,
        load_policy_set_from_dict,
        mo,
        sys,
        yaml,
    )


@app.cell
def _(mo):
    mo.md(
        """
        # 🔌🛡️ Hexgate — gating an MCP server

        An agent connects to a third-party **MCP server** and inherits *all* its
        tools. That's the risk: the server decides what to expose, but **you**
        decide what the agent may actually call.

        Hexgate runs every MCP tool call through the same policy engine — and the
        same constraint DSL — that guards native tools. This notebook:

        1. spawns a real MCP server and auto-enumerates its tools,
        2. gates them with a **default-deny** policy + an allowlist + **per-argument
           constraints**,
        3. lets you fire calls and watch the gate decide — allowed calls run for
           real against the server, denied ones never reach it.
        """
    )
    return


@app.cell
def _(Path, SERVER_PATH, mo):
    _src = Path(SERVER_PATH).read_text()
    # Show just the tool definitions — the transport boilerplate isn't the point.
    _tools = _src[_src.index("server = FastMCP") :]
    mo.md(
        f"""
        ## 1 · The MCP server

        A stock FastMCP server exposing three tools. We don't control its code —
        we only control what our agent is allowed to do with it. It's spawned over
        **stdio** (`python deploy/_mcp_demo_server.py`); a real deployment would
        point at, say, `npx @modelcontextprotocol/server-filesystem` or a Slack
        MCP server instead.

        ```python
        {_tools}```
        """
    )
    return


@app.cell
def _():
    # The gate. default-deny means the agent can touch NOTHING on the server
    # unless a rule allows it — so a server that ships 50 tools can't smuggle in
    # the 47 you never vetted. Then per-tool rules, including DSL constraints on
    # the call's arguments (consts + comparisons), decide the rest.
    POLICY = """
    version: 1
    roles:
      default:
        consts:
          max_bill: 1000          # compute_tip refuses absurd amounts
          max_invoice: 500        # invoices over this need a human
        default_policy:
          mode: deny              # nothing on the server is callable by default
        tools:
          "mcp-demo-compute_tip":
            mode: allow
            constraints:
              - args.amount <= consts.max_bill        # arg-gated allow
          "mcp-demo-read_secret":
            mode: deny                                # explicitly blocklisted
          "mcp-demo-send_invoice":
            mode: approval_required
            constraints:
              - args.amount <= consts.max_invoice     # gated, then a human approves
    """
    return (POLICY,)


@app.cell
def _(POLICY, mo):
    mo.md(
        f"""
        ## 2 · The policy that gates it

        The tool names are `mcp-<server>-<tool>` — exactly what the proxy
        registers — so gating an MCP tool is no different from gating a native
        one. Note `compute_tip` is `allow` *but* argument-constrained, and
        `read_secret` is denied even though the server offers it.

        ```yaml{POLICY}```
        """
    )
    return


@app.cell
def _(GuardedTool, MCPServerConfig, MCPToolset, SERVER_PATH, build_enforcer, sys):
    def _classify(env):
        """Map a GuardedTool envelope onto (outcome, detail)."""
        if isinstance(env, dict) and env.get("ok", False):
            return "allow", str(env.get("content", ""))
        err = env.get("error", {}) if isinstance(env, dict) else {}
        kind = err.get("type", "denied")
        outcome = "approval" if kind == "approval_required" else "deny"
        return outcome, err.get("message", "")

    async def run_batch(engine, cases):
        """Open ONE connection, enumerate tools, run each (tool, args) case.

        Returns (catalog, results). Each result is a dict with the policy
        outcome and — for allowed calls — the real value the MCP server returned.
        """
        cfg = MCPServerConfig(
            name="demo",
            transport="stdio",
            command=sys.executable,
            args=(SERVER_PATH,),
        )
        enforcer = build_enforcer(engine, agent_name="demo")
        async with MCPToolset(cfg) as mcp:
            catalog = [
                {
                    "name": p.qualified_name,
                    "desc": (p.description or "").splitlines()[0],
                    "params": list(p.input_schema.get("properties", {})),
                }
                for p in mcp.proxies
            ]
            wrapped = {
                t.name: GuardedTool.wrap(t, enforcer=enforcer, approval_handler=None)
                for t in mcp.tools
            }
            results = []
            for tool, args in cases:
                if tool not in wrapped:
                    results.append({"tool": tool, "args": args, "outcome": "unknown"})
                    continue
                env = await wrapped[tool].ainvoke(args)
                outcome, detail = _classify(env)
                results.append(
                    {"tool": tool, "args": args, "outcome": outcome, "detail": detail}
                )
        return catalog, results

    return (run_batch,)


@app.cell
async def _(POLICY, load_policy_set_from_dict, run_batch, yaml):
    CANONICAL_CASES = [
        ("mcp-demo-compute_tip", {"amount": 42.5, "percent": 20}),  # allow
        ("mcp-demo-compute_tip", {"amount": 5000}),  # arg > max_bill
        ("mcp-demo-read_secret", {"key": "prod_db_password"}),  # blocklisted
        ("mcp-demo-send_invoice", {"order_id": "ORD-7", "amount": 199.0}),  # approval
        ("mcp-demo-send_invoice", {"order_id": "ORD-8", "amount": 9000.0}),  # > max
    ]
    engine = load_policy_set_from_dict(yaml.safe_load(POLICY))
    catalog, demo_rows = await run_batch(engine, CANONICAL_CASES)
    return catalog, demo_rows, engine


@app.cell
def _(catalog, mo):
    _rows = ["| tool (namespaced) | what it does | arguments |", "|---|---|---|"]
    for _t in catalog:
        _rows.append(f"| `{_t['name']}` | {_t['desc']} | {', '.join(_t['params'])} |")
    mo.md(
        "### The server's tools, auto-registered\n\n"
        "Enumerated live over the connection — the proxy namespaces each one so "
        "policy can address it:\n\n" + "\n".join(_rows)
    )
    return


@app.cell
def _(demo_rows, mo):
    _icon = {"allow": "✅", "deny": "❌", "approval": "🔶", "unknown": "•"}
    _rows = ["| call | decision | why / result |", "|---|---|---|"]
    for _r in demo_rows:
        _label = {
            "allow": "ALLOW",
            "deny": "DENY",
            "approval": "APPROVAL",
            "unknown": "—",
        }[_r["outcome"]]
        _detail = (_r.get("detail") or "").replace("\n", " ")[:70]
        _rows.append(
            f"| `{_r['tool'].split('-', 2)[-1]}({_r['args']})` | "
            f"{_icon[_r['outcome']]} {_label} | {_detail} |"
        )
    mo.md(
        "## 3 · The gate in action\n\n"
        "One row per policy outcome. The two `compute_tip` / `send_invoice` rows "
        "differ only by an **argument** — the DSL constraint is what splits "
        "them.\n\n" + "\n".join(_rows)
    )
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 4 · Try it yourself

        Pick a tool, edit the arguments, and submit. Allowed calls run for real
        against the MCP server; denied calls are stopped before it.
        """
    )
    return


@app.cell
def _(mo):
    try_it = (
        mo.md(
            """
            **tool** {tool}

            **arguments** (JSON)

            {args}
            """
        )
        .batch(
            tool=mo.ui.dropdown(
                [
                    "mcp-demo-compute_tip",
                    "mcp-demo-read_secret",
                    "mcp-demo-send_invoice",
                ],
                value="mcp-demo-compute_tip",
            ),
            args=mo.ui.text_area(
                value='{"amount": 250, "percent": 18}', full_width=True
            ),
        )
        .form(submit_button_label="▶ Call through the gate")
    )
    try_it
    return (try_it,)


@app.cell
async def _(engine, json, mo, run_batch, try_it):
    if try_it.value is None:
        _out = mo.callout(
            mo.md("Pick a tool and arguments above, then **▶ Call through the gate**."),
            kind="info",
        )
    else:
        _v = try_it.value
        try:
            _args = json.loads(_v["args"] or "{}")
            _catalog, _res = await run_batch(engine, [(_v["tool"], _args)])
            _r = _res[0]
            _kind = {"allow": "success", "deny": "danger", "approval": "warn"}.get(
                _r["outcome"], "neutral"
            )
            _head = {
                "allow": "✅ ALLOW — call reached the server",
                "deny": "❌ DENY — blocked before the server",
                "approval": "🔶 APPROVAL REQUIRED — held for a human",
            }.get(_r["outcome"], f"• {_r['outcome']}")
            _body = _r.get("detail") or ""
            _out = mo.vstack(
                [
                    mo.md(f"`{_v['tool']}({_args})`"),
                    mo.callout(
                        mo.md(f"### {_head}\n\n```\n{_body[:300]}\n```"), kind=_kind
                    ),
                ]
            )
        except json.JSONDecodeError as _exc:
            _out = mo.callout(mo.md(f"Invalid JSON in arguments: {_exc}"), kind="warn")
    _out
    return


if __name__ == "__main__":
    app.run()
