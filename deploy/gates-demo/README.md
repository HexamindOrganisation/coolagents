# Gates demo — one agent, one MCP server, one policy

A self-contained showcase of hexgate's **gate**: an agent connects to a
third-party MCP server, inherits all its tools, and every call is run through a
role-aware, constraint-based policy — **allow or deny, before the call reaches
the server**.

The story it tells: *hexgate plugs into whatever app you run your agents in.*
The notebook is the agent's **definition** (code + tools + gate diagram +
policy); the same gated agent then runs from a different UI (hexkit) with the
policy console showing the exact policy loaded here.

## Files

| file | what it is |
|---|---|
| `notebook.py` | the marimo showcase — diagram, agent code, policy, and the live gate |
| `gdocs_mcp_server.py` | a fake Google Docs MCP server (6 tools) we gate but don't control |
| `policy.yaml` | the complex policy — default-deny, 3 roles, argument constraints |

## Run it

### 1 · Just the notebook (fastest — no OpenAI key)

The gate runs in-kernel over the real MCP server, so you see every decision
without a model. From the repo root:

```bash
uv run --active marimo edit deploy/gates-demo/notebook.py
```

(Needs `marimo` in the active env: `uv pip install --python platform/api/.venv marimo`.)

Read it top to bottom: the gate diagram, the agent code you'd write, the policy,
then the decision table + a "try it" form where you pick a role, edit the args,
and watch the gate decide.

### 2 · The one-box integrated demo (the full story)

This is where "hexgate plugs into any app" becomes real: **platform + dashboard
+ marimo (this notebook) + hexkit**, all in one container, running the *same*
gated agent.

- The notebook is the landing page (the **definition**).
- **hexkit** runs the agent (`docs` / "Docs Assistant") from a chat UI — the
  gdocs backend is `github.com/.../hexkit` at `demo/gdocs-agent/`.
- The **dashboard** holds the authoritative `docs_agent` policy (seeded by
  `deploy/provision.py`); edit it there and hexkit's next call reflects it.

`deploy/gates-demo/run-integrated.sh` brings the whole box up (platform + marimo
+ gdocs backend + proxy + front-app); the notebook's section 6 collects the BYOK
key (posted in-memory to the backend) and links to hexkit + the dashboard.

Sign in to hexkit as `ana` (analyst), `ed` (editor), or `adah` (admin) —
password `hexademo` — to watch the same request allowed for one role and denied
for another.

Build/spawn it with the combined snapshot: `deploy/daytona_full_snapshot.py`
then `deploy/daytona_full_spawn.py` (requires the hexgate + hexkit branches
pushed, since the snapshot clones them).

## What the policy shows

`policy.yaml` is **default-deny** and governs three roles (`analyst` → `editor`
→ `admin`) that inherit from a read-only base, so one file decides what each
role may do. Every `allow` is narrowed by the constraint DSL:

| feature | rule | stops |
|---|---|---|
| `startswith` | `read_doc` | reading `CONF-*` docs (admins excepted, by override) |
| `every(...)` + `endswith` | `share_doc` | sharing outside `@hexamind.ai` |
| `count(...)` | `share_doc` | mass fan-out (> 5 recipients) |
| `in consts.*` | `create_doc` | writing to un-sanctioned folders |
| `matches` (regex) | `export_doc` | exporting anywhere but the internal drive |
| `== true` | `delete_doc` | accidental deletes (needs `confirm`) |

The same DSL gates native tools and MCP tools identically — MCP tools are just
named `mcp-<server>-<tool>`. See the DSL grammar in
`hexgate/security/constraints.py` and more policy examples in
`examples/demo_policy.yaml`.
