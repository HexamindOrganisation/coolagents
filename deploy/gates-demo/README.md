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

### 2 · The one-box end-to-end demo (platform + marimo + hexkit)

The full story: **platform + dashboard + marimo (this notebook) + hexkit**, all
in one Daytona sandbox, running the *same* gated agent.

- The notebook is the landing page (the **definition**).
- **hexkit** runs the agent (`docs` / "Docs Assistant") from a chat UI — the
  gdocs backend lives in the hexkit repo at `demo/gdocs-agent/`.
- The **dashboard** holds the authoritative `docs_agent` policy (seeded by
  `deploy/provision.py`); edit it there and hexkit's next call reflects it.

`deploy/gates-demo/run-integrated.sh` brings the whole box up (platform + marimo
+ gdocs backend + proxy + front-app).

#### Build + spawn

The combined snapshot/spawn are `deploy/daytona_full_snapshot.py` +
`deploy/daytona_full_spawn.py` (the manual end-to-end launcher).

> **Interim (until #81 merges).** `daytona_full_snapshot.py` defaults hexgate to
> `feat/gates-demo` (the gates code isn't on `main` yet), so the build just
> works. Once #81 lands, run with `HEXGATE_REF=main` — the post-#81
> productionization flips the default and wires this into CI.

```bash
export DAYTONA_API_KEY=dtn_...

# Build the combined snapshot (few minutes). --force replaces a stale snapshot
# (needed whenever you change branches or push new commits).
uv run --with daytona python deploy/daytona_full_snapshot.py --force

# Spawn a sandbox, boot the stack, print the signed URLs. Enter to delete.
uv run --with daytona python deploy/daytona_full_spawn.py
```

The spawn prints three signed URLs: **marimo notebook** (:3000), **dashboard**
(:8000), **hexkit UI** (:8873).

#### 1. Notebook — start the agent (BYOK)

Open the marimo URL, read top to bottom, and at **section 6** paste your OpenAI
key → **Send**. The key is posted in-memory to the gdocs backend (never written
to disk); the live hexkit agent uses it.

#### 2. hexkit — chat as different roles

Open the hexkit URL and sign in (password **`hexademo`** for all):

| login | role | can do |
|---|---|---|
| `ana@hexamind.ai` | analyst | search + read (not confidential docs) |
| `ed@hexamind.ai` | editor | + create, share inside `@hexamind.ai` |
| `adah@hexamind.ai` | admin | everything, with guardrails |

Pick **Docs Assistant**, then type these — the agent turns each into a
`mcp-gdocs-*` tool call and the gate decides; a **denied** call shows as a failed
call in the tool-calls widget. (Docs in the fake server: `DOC-101` "Q3 launch
plan", `DOC-102` "Onboarding checklist", `CONF-900` "Acquisition terms".)

**As `ana` (analyst):**
| say | expect | why |
|---|---|---|
| `Search docs for "launch"` | ✅ allow | reads are always allowed |
| `Read DOC-101` | ✅ allow | non-confidential read |
| `Read CONF-900` | ❌ deny | `not startswith(doc_id, "CONF-")` |
| `Create a doc called "Notes" in Drafts` | ❌ deny | analyst has no create rule (default-deny) |

**As `ed` (editor):**
| say | expect | why |
|---|---|---|
| `Create a doc "Sprint plan" in Drafts` | ✅ allow | title set + Drafts is a sanctioned folder |
| `Share DOC-101 with dana@hexamind.ai` | ✅ allow | recipient is internal |
| `Share DOC-101 with someone@gmail.com` | ❌ deny | `every(recipients, endswith "@hexamind.ai")` |
| `Share DOC-101 with dana@hexamind.ai as owner` | ❌ deny | `role != "owner"` |
| `Export DOC-101 to https://pastebin.com/x` | ❌ deny | editors can't export at all |
| `Delete DOC-102` | ❌ deny | editors can't delete |

**As `adah` (admin):**
| say | expect | why |
|---|---|---|
| `Read CONF-900` | ✅ allow | admin overrides the confidential-read block |
| `Export CONF-900 to https://drive.hexamind.ai/exports/1` | ✅ allow | `matches` the internal-drive URL |
| `Export CONF-900 to https://pastebin.com/x` | ❌ deny | not the internal drive |
| `Delete DOC-102 — yes, confirm` | ✅ allow | `confirm == true` |

The headline moment: the **same** request (`share_doc`, `read_doc`, `delete_doc`)
is allowed for one role/arg and denied for another — the tool name never
changes, the gate does.

#### 3. Dashboard — edit the policy live

Open the dashboard URL + `/v1/demo-login` → **Policies → `docs_agent`**. Change a
constraint (e.g. add `"@partner.com"` to the allowed share domains, or flip a
`deny` to `allow`) and save — hexkit's **next** message reflects it, no restart.

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
