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

__generated_with = "0.23.14"
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
    # 🔌🛡️ Hexgate — govern what your agent can actually do

    An agent on an **MCP server** inherits **all** its tools. Hexgate is the gate
    between them: one policy says **allow / deny** on every call — by role, by
    arguments — *before* it runs.

    Below: the agent, the policy, the gate deciding live. Then the same agent
    running in a real app.
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
                "Every tool call detours through the gate: **allowed** → it runs; "
                "**denied** → the server never sees it."
            ),
        ]
    )
    return


@app.cell
def _(Path, SERVER_PATH, mo):
    import textwrap as _textwrap

    _src = Path(SERVER_PATH).read_text()
    _tools = _src[_src.index("server = FastMCP") :]
    # Dedent the prose, then append the fenced block flush-left. Interpolating
    # the column-0 file content directly into an indented f-string defeats
    # marimo's dedent (common indent → 0), which would render the prose as an
    # indented code block and leak the file's `#` lines as headings.
    _intro = _textwrap.dedent(
        """\
        ## 1 · The tools (we don't own these)

        A Google Docs MCP server — six tools, someone else's code. Our agent
        inherits all of them. We can't edit it; we just gate it.
        """
    )
    mo.md(_intro + f"\n```python\n{_tools}\n```\n")
    return


@app.cell
def _(mo):
    mo.md("""
    ## 2 · The agent — 3 lines to gate it

    Open the MCP toolset, hand its tools to `create_agent`, bind the policy.
    That's the whole thing — and it's exactly what runs in hexkit.

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

    The policy lives on the **platform**, not the code — edit it in the dashboard,
    the next call obeys. Below we run that same policy right here (no key needed):
    the model picks *which* tool to call; the gate decides *whether* it runs.
    """)
    return


@app.cell
def _(POLICY_PATH, Path, mo):
    import textwrap as _textwrap

    _policy = Path(POLICY_PATH).read_text()
    # See the section-1 cell: dedent the prose, append the fenced YAML flush-left
    # so the column-0 policy content doesn't defeat marimo's dedent.
    _intro = _textwrap.dedent(
        """\
        ## 3 · The policy (what you control)

        **Default-deny**, three roles — `analyst` < `editor` < `admin`. In plain
        English:

        - **analysts** read docs, but not the confidential `CONF-*` ones
        - **editors** create, and share only inside `@hexamind.ai`
        - **admins** can delete — but only with `confirm`

        One file, on the platform. Here it is:
        """
    )
    mo.md(_intro + f"\n```yaml\n{_policy}\n```\n")
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
    # Three crisp pairs — the SAME tool, split only by role or by an argument.
    _internal = {
        "doc_id": "DOC-101",
        "recipients": ["dana@hexamind.ai"],
        "role": "viewer",
    }
    _external = {
        "doc_id": "DOC-101",
        "recipients": ["someone@gmail.com"],
        "role": "viewer",
    }
    CASES = [
        (
            "analyst",
            "mcp-gdocs-read_doc",
            {"doc_id": "CONF-900"},
        ),  # confidential → deny
        (
            "admin",
            "mcp-gdocs-read_doc",
            {"doc_id": "CONF-900"},
        ),  # admin override → allow
        ("editor", "mcp-gdocs-share_doc", _internal),  # internal recipient → allow
        ("editor", "mcp-gdocs-share_doc", _external),  # outside domain → deny
        (
            "editor",
            "mcp-gdocs-delete_doc",
            {"doc_id": "DOC-101", "confirm": True},
        ),  # editor → deny
        (
            "admin",
            "mcp-gdocs-delete_doc",
            {"doc_id": "DOC-101", "confirm": True},
        ),  # admin → allow
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
        "### The six tools our agent inherited\n\n"
        "Auto-enumerated from the server, namespaced `mcp-gdocs-<tool>` so the "
        "policy can address each one:\n\n" + "\n".join(_rows)
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
        "## 4 · Watch it decide\n\n"
        "Read it in pairs: the **same call**, split only by **role** or an "
        "**argument**. The tool name never changes — the gate does.\n\n"
        + "\n".join(_rows)
    )
    return


@app.cell
def _(mo):
    mo.md("""
    ## 5 · Your turn

    Pick a role, edit the arguments, fire it through the gate. Allowed calls hit
    the real server; denied ones stop here.
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
            if not isinstance(_args, dict):
                raise ValueError(
                    'arguments must be a JSON object, e.g. {"doc_id": "DOC-101"}'
                )
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
        except Exception as _exc:  # noqa: BLE001
            # Args that parse but don't fit the tool (wrong types, missing keys)
            # would otherwise escape as a raw traceback — render them instead.
            _out = mo.callout(
                mo.md(f"⚠️ Couldn't run that call: `{type(_exc).__name__}: {_exc}`"),
                kind="warn",
            )
    _out
    return


@app.cell
def _(mo):
    mo.md("""
    ## 6 · The same agent, in a real app

    This exact agent runs in **hexkit** — a chat UI that never imported hexgate.
    The gate rides along; blocked calls show up right in the conversation.

    Add your OpenAI key (**BYOK** — kept in the throwaway backend's memory, never
    stored), open hexkit, and sign in as `ana`, `ed`, or `adah` (password
    `hexademo`) to watch the same request allowed for one role, denied for another.
    """)
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
