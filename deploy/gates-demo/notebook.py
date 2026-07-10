"""Hexgate gates demo (marimo) — one agent, one MCP server, one policy, three roles.

The story: hexgate plugs into whatever app you already run your agents in. This
notebook is the *definition* side — the agent's code, the MCP tools it inherits,
a diagram of the gate, and a complex allow/deny policy. The gate then runs live,
in-kernel, over a real (fake) Google Docs MCP server, so you can watch the same
call be allowed for one role and denied for another — no OpenAI key needed.

The last section links out to the *runtime* side: the same agent driven from a
different UI (hexkit), with the policy console (the dashboard) showing and
editing the very policy loaded here.

Files in this folder:
  * gdocs_mcp_server.py — the third-party MCP server we do NOT control
  * policy.yaml         — the gate we DO control
  * README.md           — how to run it

Run with `marimo edit deploy/gates-demo/notebook.py`.
"""

import marimo

__generated_with = "0.23.13"
app = marimo.App(width="medium")


@app.cell
def _():
    import sys
    from pathlib import Path

    import marimo as mo

    HERE = Path(__file__).resolve().parent
    SERVER_PATH = str(HERE / "gdocs_mcp_server.py")
    POLICY_PATH = str(HERE / "policy.yaml")

    from hexgate.adapters.langchain.tools import GuardedTool
    from hexgate.mcp import MCPServerConfig, MCPToolset
    from hexgate.runtime import User
    from hexgate.security.enforcer import build_enforcer
    from hexgate.security.policy_set import load_policy_set

    return (
        GuardedTool,
        MCPServerConfig,
        MCPToolset,
        POLICY_PATH,
        Path,
        SERVER_PATH,
        User,
        build_enforcer,
        load_policy_set,
        mo,
        sys,
    )


@app.cell
def _(mo):
    mo.md("""
    # 🔌🛡️ Hexgate — gating an agent's MCP tools

    Point an agent at a third-party **MCP server** and it inherits *every*
    tool that server exposes. The server decides what's on the menu; **you**
    decide what your agent may actually order.

    Hexgate is the gate in between. It runs every tool call — native or MCP —
    through one policy engine that resolves the caller's **role**, checks the
    **arguments** against a constraint DSL, and returns **allow** or **deny**
    *before the call ever reaches the server*.

    This notebook is the agent's **definition**: its code, its tools, the gate
    diagram, and the policy. Then it runs the gate for real. The same agent
    can run inside any app — the last section links to one (hexkit) plus the
    policy console.
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ## How the gate works
    """)
    return


@app.cell
def _(mo):
    # A picture of the one thing that matters: every tool call detours through
    # the gate, which answers allow/deny from the policy + the caller's role.
    _diagram = mo.mermaid(
        """
        flowchart LR
            A["🤖 Agent<br/>(runs in any app)"] -->|"proposes<br/>tool call + args"| G
            subgraph GATE ["🛡️ Hexgate gate"]
                direction TB
                G["PolicyEnforcer"] --> R{"role?<br/>constraints<br/>on args?"}
            end
            R -->|allow| M["🔌 MCP server<br/>(Google Docs)"]
            R -->|deny| X["⛔ blocked<br/>call never sent"]
            M -->|result| A
            X -.->|"structured<br/>error"| A
        """
    )
    mo.vstack(
        [
            _diagram,
            mo.md(
                "The agent never talks to the MCP server directly — hexgate wraps "
                "each tool, so a denied call is stopped here and the server never "
                "sees it. Same engine, same DSL, whether the tool is native or MCP."
            ),
        ]
    )
    return


@app.cell
def _(Path, SERVER_PATH, mo):
    _src = Path(SERVER_PATH).read_text()
    _tools = _src[_src.index("server = FastMCP") :]
    mo.md(
        f"""
        ## 1 · The MCP server (we don't control this)

        A stock FastMCP server standing in for a real Google Docs MCP. It exposes
        six tools — some safe, some destructive, some that could exfiltrate data.
        We can't edit it; we only gate it. It's spawned over **stdio**
        (`python gdocs_mcp_server.py`); a real deployment would point at, say, an
        official `@google/docs-mcp` or a Slack MCP server instead.

        ```python
        {_tools}```
        """
    )
    return


@app.cell
def _(mo):
    mo.md("""
    ## 2 · The agent (this is what runs in hexkit)

    Wiring an MCP server into a hexgate agent is three lines: open the
    toolset, hand its tools to `create_agent`, and bind the policy. This is
    verbatim what the **hexkit** backend runs (`demo/gdocs-agent/`) — a normal
    LangChain graph, gated on every call.

    ```python
    from hexgate import create_agent
    from hexgate.mcp import MCPServerConfig, MCPToolset

    gdocs = MCPServerConfig(
        name="gdocs",                       # tools land under mcp-gdocs-*
        transport="stdio",
        command="python",
        args=("gdocs_mcp_server.py",),      # or: npx @google/docs-mcp
    )

    async with MCPToolset(gdocs) as mcp:
        agent, _handler = create_agent(
            model="gpt-4o-mini",
            tools=mcp.tools,                # every MCP tool, auto-enumerated
            system_prompt="You help manage the team's Google Docs.",
            name="docs_agent",             # the policy's lookup key
            bind_policy=True,              # fetch + enforce the PLATFORM policy,
        )                                  #   hot-reloaded on every run
        # ... agent.ainvoke(...) — every tool call is now policed by the
        #     docs_agent policy you edit in the dashboard (section 6)
    ```

    The policy lives on the **platform**, not in the code — so you edit it in the
    dashboard and the next call reflects it. Below, we run that *same* policy
    directly in this notebook (no model, no key) so you can see every decision;
    the model just decides *which* call to propose — the gate decides whether it
    goes through.
    """)
    return


@app.cell
def _(POLICY_PATH, Path, mo):
    _policy = Path(POLICY_PATH).read_text()
    mo.md(
        f"""
        ## 3 · The policy (this is what you control)

        This is the `docs_agent` policy — seeded to the platform, shown/edited in
        the dashboard (section 6), and bound by the hexkit agent. One file governs
        three roles. It's **default-deny**, so the six-tool server can't smuggle
        in a tool you never vetted, and each `allow` is narrowed by **argument
        constraints**. Note the DSL features in play:

        | feature | where | what it stops |
        |---|---|---|
        | `startswith` | `read_doc` | reading `CONF-*` docs |
        | `every(...)` + `endswith` | `share_doc` | sharing outside `@hexamind.ai` |
        | `count(...)` | `share_doc` | mass fan-out (> 5 recipients) |
        | `in consts.*` | `create_doc` | writing to un-sanctioned folders |
        | `matches` (regex) | `export_doc` | exporting anywhere but the internal drive |
        | `== true` | `delete_doc` | accidental deletes (needs `confirm`) |
        | role inheritance / override | `admin` | admin reads `CONF-*`; editors can't |

        ```yaml
        {_policy}```
        """
    )
    return


@app.cell
def _(
    GuardedTool,
    MCPServerConfig,
    MCPToolset,
    SERVER_PATH,
    User,
    build_enforcer,
    sys,
):
    def _classify(env):
        """Map a GuardedTool envelope onto (outcome, detail)."""
        if isinstance(env, dict) and env.get("ok", False):
            return "allow", str(env.get("content", ""))
        err = env.get("error", {}) if isinstance(env, dict) else {}
        return "deny", err.get("message", "") or ""

    async def run_batch(engine, cases):
        """Open ONE connection, enumerate tools, run each (role, tool, args) case.

        The caller's role is set via the `User` scope for each call — exactly how
        the platform resolves it from the signed-in user at runtime. Returns
        (catalog, results); allowed calls carry the value the server returned.
        """
        cfg = MCPServerConfig(
            name="gdocs", transport="stdio", command=sys.executable, args=(SERVER_PATH,)
        )
        enforcer = build_enforcer(engine, agent_name="docs_agent")
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
            for role, tool, args in cases:
                if tool not in wrapped:
                    results.append(
                        {"role": role, "tool": tool, "args": args, "outcome": "unknown"}
                    )
                    continue
                async with User(user_id="demo", role=role):
                    env = await wrapped[tool].ainvoke(args)
                outcome, detail = _classify(env)
                results.append(
                    {
                        "role": role,
                        "tool": tool,
                        "args": args,
                        "outcome": outcome,
                        "detail": detail,
                    }
                )
        return catalog, results

    return (run_batch,)


@app.cell
async def _(POLICY_PATH, load_policy_set, run_batch):
    # The same handful of calls, some fired by an editor and some by an admin, to
    # show the gate deciding on role + arguments — not just tool name.
    CASES = [
        ("analyst", "mcp-gdocs-search_docs", {"query": "launch"}),
        ("analyst", "mcp-gdocs-read_doc", {"doc_id": "DOC-101"}),
        ("analyst", "mcp-gdocs-read_doc", {"doc_id": "CONF-900"}),  # confidential
        ("admin", "mcp-gdocs-read_doc", {"doc_id": "CONF-900"}),  # admin may
        ("editor", "mcp-gdocs-create_doc", {"title": "", "folder": "Drafts"}),  # empty
        ("editor", "mcp-gdocs-create_doc", {"title": "Plan", "folder": "Drafts"}),
        (
            "editor",
            "mcp-gdocs-share_doc",
            {"doc_id": "DOC-101", "recipients": ["dana@hexamind.ai"], "role": "viewer"},
        ),
        (
            "editor",
            "mcp-gdocs-share_doc",
            {
                "doc_id": "DOC-101",
                "recipients": ["someone@gmail.com"],
                "role": "viewer",
            },
        ),  # external
        (
            "editor",
            "mcp-gdocs-export_doc",
            {"doc_id": "DOC-101", "url": "https://pastebin.com/x"},
        ),
        (
            "admin",
            "mcp-gdocs-export_doc",
            {"doc_id": "DOC-101", "url": "https://drive.hexamind.ai/exports/1"},
        ),
        (
            "editor",
            "mcp-gdocs-delete_doc",
            {"doc_id": "DOC-101", "confirm": True},
        ),  # editors can't
        (
            "admin",
            "mcp-gdocs-delete_doc",
            {"doc_id": "DOC-101", "confirm": False},
        ),  # needs confirm
        ("admin", "mcp-gdocs-delete_doc", {"doc_id": "DOC-101", "confirm": True}),
    ]
    engine = load_policy_set(POLICY_PATH)
    catalog, demo_rows = await run_batch(engine, CASES)
    return catalog, demo_rows, engine


@app.cell
def _(catalog, mo):
    _rows = ["| tool (namespaced) | what it does | arguments |", "|---|---|---|"]
    for _t in catalog:
        _rows.append(f"| `{_t['name']}` | {_t['desc']} | {', '.join(_t['params'])} |")
    mo.md(
        "### The server's tools, auto-registered\n\n"
        "Enumerated live over the connection — the proxy namespaces each one "
        "`mcp-gdocs-<tool>` so the policy can address it:\n\n" + "\n".join(_rows)
    )
    return


@app.cell
def _(demo_rows, mo):
    _icon = {"allow": "✅", "deny": "❌", "unknown": "•"}
    _label = {"allow": "ALLOW", "deny": "DENY", "unknown": "—"}
    _rows = ["| role | call | decision | why / result |", "|---|---|---|---|"]
    for _r in demo_rows:
        _detail = (_r.get("detail") or "").replace("\n", " ")[:64]
        _rows.append(
            f"| `{_r['role']}` | `{_r['tool'].split('-', 2)[-1]}({_r['args']})` | "
            f"{_icon[_r['outcome']]} {_label[_r['outcome']]} | {_detail} |"
        )
    mo.md(
        "## 4 · The gate in action\n\n"
        "One row per call. Watch the pairs that differ only by **role** "
        "(`read_doc` on `CONF-900`) or by an **argument** (`share_doc` recipient "
        "domain, `delete_doc` confirm) — the tool name is the same; the gate "
        "splits them.\n\n" + "\n".join(_rows)
    )
    return


@app.cell
def _(mo):
    mo.md("""
    ## 5 · Try it yourself

    Pick a role and a call, edit the arguments, submit. Allowed calls run for
    real against the MCP server; denied calls are stopped before it.
    """)
    return


@app.cell
def _(mo):
    try_it = (
        mo.md(
            """
            **role** {role}   **tool** {tool}

            **arguments** (JSON)

            {args}
            """
        )
        .batch(
            role=mo.ui.dropdown(["analyst", "editor", "admin"], value="editor"),
            tool=mo.ui.dropdown(
                [
                    "mcp-gdocs-search_docs",
                    "mcp-gdocs-read_doc",
                    "mcp-gdocs-create_doc",
                    "mcp-gdocs-share_doc",
                    "mcp-gdocs-export_doc",
                    "mcp-gdocs-delete_doc",
                ],
                value="mcp-gdocs-share_doc",
            ),
            args=mo.ui.text_area(
                value='{"doc_id": "DOC-101", "recipients": ["dana@hexamind.ai"], "role": "viewer"}',
                full_width=True,
            ),
        )
        .form(submit_button_label="▶ Call through the gate")
    )
    try_it
    return (try_it,)


@app.cell
async def _(engine, mo, run_batch, try_it):
    import json

    if try_it.value is None:
        _out = mo.callout(
            mo.md(
                "Pick a role, tool, and arguments above, then **▶ Call through the gate**."
            ),
            kind="info",
        )
    else:
        _v = try_it.value
        try:
            _args = json.loads(_v["args"] or "{}")
            _catalog, _res = await run_batch(engine, [(_v["role"], _v["tool"], _args)])
            _r = _res[0]
            _kind = {"allow": "success", "deny": "danger"}.get(_r["outcome"], "neutral")
            _head = {
                "allow": "✅ ALLOW — call reached the server",
                "deny": "❌ DENY — blocked before the server",
            }.get(_r["outcome"], f"• {_r['outcome']}")
            _body = _r.get("detail") or ""
            _out = mo.vstack(
                [
                    mo.md(f"**{_v['role']}** → `{_v['tool']}({_args})`"),
                    mo.callout(
                        mo.md(f"### {_head}\n\n```\n{_body[:300]}\n```"), kind=_kind
                    ),
                ]
            )
        except json.JSONDecodeError as _exc:
            _out = mo.callout(mo.md(f"Invalid JSON in arguments: {_exc}"), kind="warn")
    _out
    return


@app.cell
def _(mo):
    mo.md(
        """
        ## 6 · Now run it for real — in a different app

        Everything above is the **definition**. hexgate's point is that this same
        gated agent runs wherever you already work — here, in **hexkit**, a chat
        UI that never imported hexgate. The gate rides along; blocked calls show
        up as denials right in the conversation.

        The live agent needs an OpenAI key (**BYOK** — sent straight to the
        throwaway hexkit backend's memory, never stored). Paste it and send, then
        open hexkit and sign in as `ana` (analyst), `ed` (editor), or `adah`
        (admin) — password `hexademo` — to see the same request allowed for one
        role and denied for another.
        """
    )
    return


@app.cell
def _(mo):
    # BYOK for the live hexkit agent. The value is live as you type; the button
    # posts it. The key goes only to the local hexkit backend's memory.
    byok_key = mo.ui.text(kind="password", placeholder="sk-...", full_width=True)
    byok_send = mo.ui.run_button(label="↪ Send key to the hexkit agent")
    mo.vstack(
        [mo.md("**OpenAI API key** (for the live hexkit agent)"), byok_key, byok_send]
    )
    return byok_key, byok_send


@app.cell
def _(byok_key, byok_send, mo):
    import json as _json
    import os as _os
    import urllib.request as _urllib

    # The hexkit gdocs backend runs in this same container. run-integrated.sh
    # exports its URL (single source of truth for the port); default matches the
    # backend's own default (:8880). POST the key to /byok — in-memory handoff.
    _backend = _os.environ.get("HEXGATE_GDOCS_BACKEND_URL", "http://127.0.0.1:8880")
    if byok_send.value:
        if not byok_key.value:
            _o = mo.md("⚠️ **Enter your OpenAI key above**, then click Send.")
        else:
            try:
                _req = _urllib.Request(
                    f"{_backend}/byok",
                    data=_json.dumps({"openai_key": byok_key.value}).encode(),
                    headers={"content-type": "application/json"},
                    method="POST",
                )
                _urllib.urlopen(_req, timeout=5).read()
                _o = mo.md(
                    f"✅ Key `…{byok_key.value[-4:]}` sent to the hexkit agent — "
                    "open hexkit below and start chatting."
                )
            except Exception as _e:  # noqa: BLE001
                _o = mo.md(
                    f"❌ Couldn't reach the hexkit backend ({_e}). Is the "
                    "integrated demo running? (Locally, this notebook alone "
                    "doesn't start hexkit — see the README.)"
                )
    else:
        _o = mo.md("_Paste your key and click Send before chatting in hexkit._")
    _o
    return


@app.cell
def _(Path, mo):
    # boot.py writes the public dashboard + hexkit URLs here when the integrated
    # demo runs in a sandbox. Locally they're absent — degrade to a note.
    def _url(path: str) -> str | None:
        p = Path(path)
        if p.exists():
            u = p.read_text().strip().rstrip("/")
            return u or None
        return None

    _dash = _url("/tmp/hexgate_dash_url")
    _hexkit = _url("/tmp/hexkit_url")

    _links = []
    if _hexkit:
        _links.append(f"### [▶ Chat with this agent in hexkit →]({_hexkit})")
    if _dash:
        _links.append(f"### [🛡️ Open the policy console →]({_dash}/v1/demo-login)")
    _body = (
        "\n\n".join(_links)
        if _links
        else (
            "_Running locally — start the integrated demo (see this folder's "
            "README) to get live hexkit + dashboard links._"
        )
    )

    mo.md(
        f"""
        And **the policy console** (the dashboard) shows this exact `docs_agent`
        policy — edit a constraint there and hexkit's next call picks it up, no
        redeploy. It's the single source of truth; the gate table above runs a
        local mirror of it so this page works with no key.

        {_body}
        """
    )
    return


@app.cell
def _():
    return


if __name__ == "__main__":
    app.run()
