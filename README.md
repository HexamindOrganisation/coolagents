<div align="center">

<img src="./icon.svg" alt="Hexgate" width="96" height="96" />

# Hexgate

**Authorization infrastructure for AI agents.**
Policy enforcement, signed policy bundles, per-request user scope, audit trail — for OpenAI Agents, LangChain, Google ADK, Pydantic AI, or a native runtime.

[**Website**](https://hexgate.ai) · [Docs](https://docs.hexgate.ai) · [PyPI](https://pypi.org/project/hexgate/) · [Discussions](https://github.com/HexamindOrganisation/hexgate/discussions)

[![PyPI](https://img.shields.io/pypi/v/hexgate?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/hexgate/)
[![CI](https://github.com/HexamindOrganisation/hexgate/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/HexamindOrganisation/hexgate/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/HexamindOrganisation/hexgate/branch/main/graph/badge.svg?flag=sdk)](https://codecov.io/gh/HexamindOrganisation/hexgate)
[![Downloads](https://img.shields.io/pypi/dm/hexgate?color=blueviolet)](https://pypi.org/project/hexgate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<br />

<img src="./assets/hero.png" alt="Control what your agents do — not just what they say. Policy decisions streaming live from the PolicyEnforcer." />

<br />

[Quick Start](#-quick-start--local-cli) · [Two paths](#-which-path-do-i-pick) · [Framework adapters](#-framework-agent-wrapping) · [Policy bundles](#-policy-bundles--compile-sign-enforce-wasm) · [User scope](#-user-scope--roles) · [Platform](#-hexgate-platform)

</div>

---

## What is Hexgate?

Hexgate is two things that move together:

- **`hexgate` — the SDK.** A Python runtime that gates every tool call through a typed `Decision` (allow / deny / approval-required), wraps your existing OpenAI / LangChain / Google ADK / Pydantic AI agent without rewriting it, and threads per-request user identity through tracing + audit.
- **The Hexgate platform** *(optional)* — a FastAPI control plane + React dashboard for editing policy in a browser, minting per-project tokens, watching live decisions stream from a serving agent, and shipping signed WASM policy bundles to production.

You can use the SDK with nothing else (single-process REPL, YAML on disk). Or plug in the platform when you want auditable decisions in ClickHouse, a shared Playground UI, and live policy edits.

```text
                      ┌─────────────────────────────────────────┐
   your code  ───►    │   create_agent / wrap_*_agent / Runner  │
                      │            ↓                            │
                      │     PolicyEnforcer.decide(role, tool)   │
                      │            ↓                            │
                      │   allow · deny · approval_required      │
                      └────────────────────┬────────────────────┘
                                           │
                  ┌────────────────────────┼─────────────────────────┐
                  ▼                        ▼                         ▼
        ┌────────────────┐       ┌──────────────────┐       ┌────────────────┐
        │  Local policy  │       │ Signed WASM      │       │   Audit log    │
        │  (YAML / dir,  │       │ bundle from      │       │   (ClickHouse  │
        │  hot reload)   │       │ Hexgate cloud   │       │   via REST)    │
        └────────────────┘       └──────────────────┘       └────────────────┘
```

## Table of contents

- [Prerequisites](#-prerequisites)
- [Quick Start — Local CLI](#-quick-start--local-cli)
- [Which path do I pick?](#-which-path-do-i-pick) — chat vs serve
- [Quick Start — Platform](#-quick-start--platform)
- [Core primitives](#-core-primitives)
- [Build an agent — end to end](#-build-an-agent--end-to-end)
- [What you can import](#-what-you-can-import)
- [Framework agent wrapping](#-framework-agent-wrapping) — OpenAI, LangChain, Google ADK, Pydantic AI
- [Define agents in code](#-define-agents-in-code)
- [Builtin and local agents](#-builtin-and-local-agents)
- [Policy shape](#-policy-shape)
- [Tool-call policy enforcement](#-tool-call-policy-enforcement)
- [Policy bundles — compile, sign, enforce (WASM)](#-policy-bundles--compile-sign-enforce-wasm)
- [Approval-required tool calls](#-approval-required-tool-calls)
- [Workspace sandbox](#-workspace-sandbox)
- [Environment](#-environment)
- [Tests & dev tooling](#-tests--dev-tooling)
- [CLI reference](#-cli-reference)
- [Hexgate platform](#-hexgate-platform)
- [User scope + roles](#-user-scope--roles)
- [Stream results](#-stream-results)

## 🛠️ Prerequisites

The SDK itself only needs Python — but a few of the bundled tools shell out to native binaries that you'll want installed on the host before running an agent that uses them.

| Required when you use… | Install |
|---|---|
| **`grep`, `glob`, `bash`, `read_file`, `edit_file`, `write_file`** — anything filesystem-shaped | [`ripgrep`](https://github.com/BurntSushi/ripgrep) — `brew install ripgrep` (macOS), `apt install ripgrep` (Debian/Ubuntu), `winget install BurntSushi.ripgrep.MSVC` (Windows) |
| **The dashboard** under `platform/dashboard/` | Node 18+ and `pnpm` — `corepack enable` or `npm i -g pnpm` |
| **The control plane** under `platform/api/` | [`uv`](https://docs.astral.sh/uv/) — `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

`web_search` and `fetch` have no system dependencies — pure Python. If you're only using those, ignore the table above.

The runtime preflights `ripgrep` at agent build time and refuses to start when it's missing — fail-fast is friendlier than silently falling back to a 100× slower path.

## ⚡ Quick Start — Local CLI

If you just want to install `hexgate` and try the terminal chat:

1. Install the package in editable mode.
2. Copy the sample environment file.
3. Fill in the required API keys.
4. Run the chat CLI against the included local example agent.

```bash
python -m pip install -e .
cp .env.sample .env
hexgate chat --agent example_agent
```

Required keys for the example CLI flow:

- `OPENAI_API_KEY`
- `LINKUP_API_KEY`
- `TAVILY_API_KEY`

Run `hexgate --help` to see all subcommands (`chat`, `serve`, `register`), and `hexgate <subcommand> --help` for the flags each one accepts.

Useful next commands:

```bash
hexgate chat --list-agents
hexgate chat --agent researcher                                      # by id
hexgate chat --agent examples.customer_bot:agent                     # by module:attr (same shape as `hexgate serve`)
hexgate chat --use examples/file_agents.py --agent workspace_explorer
hexgate chat --use examples/research_agents.py --agent update_researcher
```

The included local agent lives in `examples/example_agent/`, and the CLI can also load:

- builtin packaged agents like `researcher`
- code-defined agents registered from `examples/file_agents.py`
- code-defined research agents registered from `examples/research_agents.py`

## 🧭 Which path do I pick?

The two Quick Starts above aren't competing — they answer different questions.

**Inner loop — `hexgate chat`.** A single-process REPL against a local or builtin agent. No platform, no Docker, no browser. The chat command sets `HEXGATE_LOCAL_MODE=1` automatically so audit stays on your machine even if `HEXGATE_KEY` lives in your `.env` from an earlier session. Denies and approval-required calls render as inline panels in the terminal — same `Decision` data the platform would log, surfaced where you're iterating. Reach for `chat` when you're authoring a policy YAML, tweaking a tool, or shaping a system prompt.

**Team loop — `hexgate serve` + dashboard Playground.** Same agent code, but the policy + decisions round-trip through the platform. You get auditable decisions in ClickHouse, the shared Playground UI, and live policy edits via the dashboard. Reach for `serve` when you're collaborating on an agent's behaviour, debugging a production-like trace, or demoing.

| Path | Needs platform? | Audit destination | Policy edits visible at | Best for |
|------|-----------------|-------------------|--------------------------|----------|
| `hexgate chat --agent ...` | No | Local terminal panel | Edit + restart (hot-reload only when `HEXGATE_LOCAL_POLICY` is set) | Inner loop, policy authoring |
| `hexgate serve --agent ...` + Playground | Yes | ClickHouse via `/v1/audit/decisions` | Per-turn fetch from dashboard | Team review, demos, integration testing |

Both commands accept either a plain agent id (`--agent researcher`) or a uvicorn-style `module.path:attr` spec (`--agent examples.customer_bot:agent`), so the same entry-point string works in both workflows.

## 🚀 Quick Start — Platform

To run the full Hexgate control plane locally (FastAPI backend + dashboard + your local agent serving over WebSocket), you need **three terminals**. The Makefile has a target that prints the recipe:

```bash
make demo-platform     # prints the 3-terminal recipe below
```

```bash
# Terminal 1 — backend (FastAPI + SQLite on :8000)
make platform-api

# Terminal 2 — dashboard (Vite + React on :5173)
make dashboard

# Terminal 3 — mint a token, then serve your local agent
#   1. Open http://localhost:5173/tokens, click "Mint new token", copy the value.
#   2. Add to asianf/.env:  HEXGATE_KEY=fty_live_...
#   3. Pick the agent's Python entrypoint (module:attr — uvicorn-style)
#      and let `hexgate serve` take over:
make serve                                          # default — examples.customer_bot:agent
# or, for a different agent:
uv run hexgate serve my_app.agents:my_agent
```

On first serve, `hexgate serve` auto-registers the agent's manifest on
the platform (the server generates a starter role-aware policy from the
tool list). Subsequent serves short-circuit if the manifest hasn't
changed. Pass `--no-auto-register` for CI / deliberate-deployment flows.

First-time setup (each sub-project has its own deps):

```bash
make platform-api-install   # uv sync inside platform/api/
make dashboard-install      # pnpm install inside platform/dashboard/
```

Then open http://localhost:5173/playground — type a message, watch the live stream of tool calls and policy decisions from your local agent.

### Control-plane database (SQLite / Postgres)

`make platform-api` uses a local **SQLite** file — zero setup, fine for
dev and the test suite. Set `DATABASE_URL` to run on **Postgres** instead
(what deployments use); bare `postgres://` URLs are normalized to the
`asyncpg` driver. A local Postgres is in the dev compose:

```bash
make platform-api-pg      # starts Postgres (Docker) + runs the API against it
# equivalent to:
make postgres-up          # start Postgres, wait until healthy
DATABASE_URL=postgresql+asyncpg://hexgate:hexgate-dev-password@localhost:5433/hexgate make platform-api
make postgres-reset       # wipe ONLY the Postgres data volume
```

No migration system: the schema is created with `create_all`, so a model
change means resetting the volume (`make postgres-reset`), not migrating —
data is treated as disposable. A managed Postgres (e.g. Scaleway) needs SSL
in the DSN, e.g. `…/hexgate?ssl=require`.

`DATABASE_URL` is read from the real environment or `platform/api/.env`
(see `.env.sample`). The opt-in `tests/test_postgres_smoke.py` is the only
test that exercises the Postgres path (the rest run on SQLite); it runs
when `DATABASE_URL` points at Postgres.

### Audit log (ClickHouse)

Policy decisions are written to a local ClickHouse instance for the audit dashboard. Requires Docker.

```bash
make clickhouse-up        # start the server (first run also creates the schema)
make clickhouse-cli       # interactive SQL shell
make clickhouse-down      # stop (keeps data)
make clickhouse-reset     # wipe and recreate (also re-applies the schema)
```

Schema lives in `platform/clickhouse/init/schema.sql`.

**Not a migration system.** That init directory is a POC scaffold — the Docker image runs it exactly once, on first container start with an empty data volume. Editing the SQL after that point is silently ignored on existing environments. To apply schema changes locally, either `make clickhouse-reset` (wipes data) or `make clickhouse-cli` and run the SQL by hand. A real migration runner should replace this directory the first time a second schema change is needed.

The service binds to **127.0.0.1 only, on host ports 8124 (HTTP) and 9001 (native)** rather than ClickHouse's default 8123/9000, so it coexists with any other local ClickHouse instance (e.g. a Langfuse-bundled one).

Once both `make clickhouse-up` and `make platform-api` are running, `GET /ready` reports `"clickhouse": "ok"` (the `/health` liveness probe stays dependency-free) and the ingest endpoint `POST /v1/audit/decisions` accepts one decision per request:

```bash
curl -X POST localhost:8000/v1/audit/decisions \
  -H "Authorization: Bearer fty_test_..." \
  -H "Content-Type: application/json" \
  -d '{"event_id":"9f1e3c5a-4d2b-4b8e-9c8a-1f4e2d8a7c3b",
       "occurred_at":"2026-05-29T14:00:00Z",
       "agent_name":"researcher","tool_name":"read_file","outcome":"deny"}'
# → 202 {"event_id":"9f1e3c5a-..."}
```

Integration tests (`pytest -m integration`) round-trip rows through the live ClickHouse — opt-in so the default `make platform-api-test` stays offline-friendly.

The dashboard's `/policies` page lets you edit each agent's policy. `hexgate serve` re-fetches at every turn boundary, so your edits take effect on the next chat message without a restart.

### Outbound email (Resend)

Verification emails and password-reset links go through [Resend](https://resend.com). The platform API has two senders:

- **Dev (default)** — `StderrEmailSender` prints the mail body (including the magic link) to stderr. No keys needed; click the link out of the terminal to exercise the flow end-to-end.
- **Production** — `ResendEmailSender`, picked up automatically when both `RESEND_API_KEY` and `HEXGATE_EMAIL_FROM` are set. The from-address must be on a verified Resend domain.

```bash
# platform/api/.env
RESEND_API_KEY=re_…
HEXGATE_EMAIL_FROM="Hexgate <noreply@yourdomain.com>"
HEXGATE_DASHBOARD_URL=https://app.yourdomain.com   # ← link host inside the email
```

Partial config (only one var set) keeps the dev stderr sender so an operator notices the misconfig in the startup log line instead of silently failing every send at delivery. Resend API failures are logged at error level but never 5xx the calling endpoint — the user can request a new link.

## ✨ Core Primitives

The two main primitives are:

- `create_agent(...)`
- `@agent_tool(...)`

Use them when you want to define everything directly in Python.

```python
from hexgate import agent_tool, create_agent


@agent_tool(name="my_lookup")
async def my_lookup(query: str) -> dict:
    """Look up something useful."""
    return {"query": query, "results": []}

agent, handler = create_agent(
    model="openai:gpt-5.4",
    tools=[my_lookup],
    system_prompt="You are a helpful research assistant.",
)
```

## 🚀 Build an Agent — End to End

Devs pick one of two shapes. Both end up at the same enforcement seam — they differ only in **where the policy comes from**.

### Shape A — "I have an existing framework agent"

Dev wrote an OpenAI Agents / LangChain / Google ADK / Pydantic AI agent. They wrap it once and they're done:

```python
from hexgate.adapters.openai import HexgateRunner   # or .langchain.wrap_langchain_agent, .google.HexgateRunner, .pydantic_ai.wrap_pydantic_agent
from hexgate.runtime import User

runner = HexgateRunner()                            # picks up HEXGATE_KEY from env
await runner.run(
    my_agent,
    "refund 30",
    user=User(user_id="alice", role="billing"),     # per-call scope
)
```

That's it. They get:

- Tool-call enforcement at every tool boundary (`PolicyEnforcer.decide()`)
- Role resolution from the active `User.role` at call time
- Per-request biscuit attenuation
- Langfuse traces tagged with the caller's identity

### Shape B — "I want the platform to own the agent's YAML"

Dev authored the agent's `agent.yaml` / `policy.yaml` / `system.md` in the dashboard. SDK fetches them:

```python
from hexgate import load_hexgate_agent, stream_agent, User

agent, handler = load_hexgate_agent("default")      # explicit name — the SDK's loader requires it

async with User(user_id="alice", role="billing"):
    async for ev in stream_agent(agent, handler, "refund 30"):
        ...
```

Same enforcement seam, same `User` scope. The difference is whose system of record holds the YAML — the dev's code vs the dashboard.

### Env vars: that *is* the whole config surface

| What dev sets | What changes |
|---|---|
| `HEXGATE_KEY=fty_live_<project>_…` | Wakes up the platform path. Without it, adapters / `load_agent` fall back to local / builtin. |
| `HEXGATE_API_URL=http://localhost:8000` *(optional)* | Platform endpoint. Defaults to localhost. |
| `HEXGATE_LOCAL_POLICY=./policy.yaml` *or* `./bundle/` | Dev escape hatch: enforce a policy from disk, hot-reload on save. Wins over the platform's bundle. |
| `HEXGATE_BUNDLE_SIGN_KEY_PATH=./keys/dev.private` *(optional)* | Sign locally-recompiled yaml so `bundle.is_signed` reads True. |
| `HEXGATE_BUNDLE_PUBKEY_PATH=./keys/prod.public` *(optional)* | Verify a pre-built bundle dir against this pubkey on every reload. |
| `HEXGATE_BUNDLE_REQUIRE_SIGNATURE=true` *(optional)* | Strict mode — refuse any unsigned or unverifiable bundle at startup. |

No config object to instantiate, no `enforce_policy(...)` call to remember on the platform path. The adapter / loader threads it all through.

### Where enforcement actually happens

Walk through one tool call:

1. The model emits a tool call. The framework's tool dispatcher invokes the tool.
2. The tool is *not the dev's original* — it's a copy our adapter made, whose body starts with `enforcer.decide(role, tool_name, args)`.
3. `PolicyEnforcer.decide` reads `self.policy` — that's either a `PolicySet` (pydantic engine, default fallback) or a `PolicyBundle` (WASM engine, what production runs).
4. Decision is `allow` → the original tool runs. `deny` → returns a `[policy_denied]` marker the model sees as the tool result. `approval_required` → either calls the dev-supplied approval handler or returns an `[approval_required]` marker.
5. **Before step 2, every turn:** `refresh_policy()` calls `self._policy_source.fetch()`. If the source returns a new bundle instance, `enforcer.policy` is swapped in place. Tools don't get re-wrapped — they hold a reference to the enforcer, not the bundle.

`_policy_source` is set automatically by the loader based on env:

- `HEXGATE_LOCAL_POLICY` set → `YamlPolicySource` or `BundleDirPolicySource` (mtime-driven refresh)
- `HEXGATE_KEY` set, no local override → `PlatformPolicySource` (ETag / `304 Not Modified` refresh)
- Neither → no source attached; enforcement uses whatever was loaded once

**Scope of the per-turn refresh:** only the policy bundle. `system_prompt`, the manifest's tool list, and the model id are read once at agent construction and stay fixed for the lifetime of the process. Edit those on the dashboard and the change lands at the next `hexgate serve` restart — not at the next turn. The split is deliberate: policy is the operator's primary lever (and the one that needs to be auditable per-decision), while the manifest is an author-time concept.

### Two carve-outs worth knowing

1. **Per-call identity stays explicit.** `User` is the one piece the adapter can't infer from env, because it's per-request, not per-process. One line wrapping each call (`user=User(...)` kwarg on adapters, `async with User(...)` for native).
2. **`approval_required` tools.** If the policy uses that mode, dev decides what happens — pass `approval_handler=` (True / False / callable) when wrapping. Default for `hexgate serve` is auto-approve; for `hexgate chat` it prompts the TTY. Native code gets whatever the dev wires.

Everything else — fetch, verify, hot-reload, role selection, signature check, decision rendering, tracing — the runtime handles. Set `HEXGATE_KEY` and wrap, or set `HEXGATE_LOCAL_POLICY` and wrap. That's the surface.

## 📦 What You Can Import

The current curated surface includes:

- `create_agent`
- `create_manifest`
- `AgentManifest`
- `enforce_policy` — accepts an optional `approval_handler=` for `NEEDS_APPROVAL` outcomes
- `invoke_agent`
- `stream_agent`
- `stream_agent_raw`
- `load_builtin_agent`
- `list_builtin_agents`
- `load_hexgate_agent`
- `User` — async context manager for per-request user attenuation (see [User Scope](#-user-scope))
- `agent_tool`
- `web_search`
- `fetch`

Example:

```python
from hexgate import (
    create_agent,
    edit_file,
    enforce_policy,
    glob,
    grep,
    read_file,
    write_file,
    agent_tool,
    load_agent,
    load_builtin_agent,
    load_hexgate_agent,
    register_agent,
    fetch,
    web_search,
    User,
)
```

## 🤝 Framework Agent Wrapping

In addition to its native `create_agent(...)` runtime, `hexgate` ships adapters that wrap agents built with **OpenAI Agents SDK**, **LangChain / LangGraph**, **Google ADK**, or **Pydantic AI** to add two things without touching the agent's logic:

1. **Tool-call policy enforcement.** Each tool the agent can invoke is gated by a `PolicyEnforcer` that returns a typed `Decision` (allow / deny / needs-approval) per call. Non-allow outcomes render as a `[policy_denied]` / `[approval_required]` marker the model sees as tool output (or, for pydantic_ai, a `ModelRetry`) rather than aborting the run, so the agent can recover.
2. **User-aware observability.** Every run is traced through Langfuse with the active `User`'s identity (user id, session id, role) propagated onto the spans.

The four integrations differ in shape because the underlying SDKs do:

| | OpenAI Agents SDK | LangChain / LangGraph | Google ADK | Pydantic AI |
| --- | --- | --- | --- | --- |
| Entry point | `HexgateRunner` (replaces `Runner`) | `wrap_langchain_agent` (returns a proxy) | `HexgateRunner` (replaces `Runner`) | `wrap_pydantic_agent` (returns a proxy) |
| Tool wrapping | Copies each `FunctionTool`, replaces `on_invoke_tool` with a `PolicyEnforcer`-gated version | Mutates each `BaseTool` in place (`install_enforcer_on_tool`), replaces `func`/`coroutine` with enforcer-gated versions, sets `handle_tool_error=True` | Copies each `BaseTool` (normalizing bare callables to `FunctionTool`), replaces `run_async` with a gated version | Copies each `Tool` and overrides `function_schema.call` with a gated version |
| Denial behavior | Returns `decision.as_error_message()` as the tool output (`[policy_denied]` / `[approval_required]` markered string) | Returns `{"ok": False, "error": decision.as_error_payload()}` so LangChain emits the structured dict as the tool result | Returns `decision.as_error_message()` as the tool output | Raises `ModelRetry(decision.as_error_message())`; pydantic_ai surfaces it back to the model as a tool-result message |
| Tracing | `OpenAIAgentsInstrumentor` + `propagate_attributes` | Langfuse `CallbackHandler` injected into each call's `RunnableConfig` + `propagate_attributes` | `GoogleADKInstrumentor` + `propagate_attributes` | `Agent.instrument_all()` + `propagate_attributes` |
| Per-call identity | `user: User` keyword on `run` / `run_sync` / `run_streamed` | `user: User` keyword on `invoke` / `ainvoke` / `stream` / `astream` / `astream_events` | `user: User` keyword on `run` / `run_async` | `user: User` keyword on `run` / `run_sync` / `run_stream` / `iter` |

Role resolution happens **at call time** from the active `User` contextvar — one wrapped agent serves many users concurrently because the scope is per-call. The original agent object is left intact (or, for LangChain BYO-graph tools, mutated by design so the same `tools` list flows through `create_react_agent`); the wrapper holds the policy.

All adapters resolve the API key the same way: from the explicit `api_key=` argument, falling back to the `HEXGATE_KEY` environment variable.

### OpenAI Agents SDK — `HexgateRunner`

`HexgateRunner` is a drop-in replacement for `agents.Runner`. It wraps the agent's tools with a `PolicyEnforcer` at construction time and opens a `User` scope around each `Runner.run` / `run_sync` / `run_streamed` call so role resolution happens at call time.

```python
import asyncio
from agents import Agent, function_tool
from dotenv import load_dotenv

from hexgate.runtime import User
from hexgate.adapters.openai import HexgateRunner


@function_tool
def get_weather(city: str) -> str:
    return f"{city}: sunny, 23°C"


async def main():
    load_dotenv()

    agent = Agent(
        name="Weather Agent",
        instructions="Use get_weather when asked about weather.",
        tools=[get_weather],
        model="gpt-4o-mini",
    )

    runner = HexgateRunner()  # picks up HEXGATE_KEY from env
    result = await runner.run(
        agent,
        "What's the weather in Cherbourg?",
        user=User(user_id="user_1", session_id="session_1", role="member"),
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
```

What happens under the hood:

- `HexgateRunner.run` calls `wrap_openai_agent`, which builds a `PolicySet` for `(api_key, agent.name, tool_names)`, constructs one `PolicyEnforcer`, and returns a `dataclasses.replace`'d copy of the agent with policy-gated tool copies — your original `agent` is untouched.
- The runner opens an `async with user:` scope around the underlying `Runner.run*` call. When the model calls a tool, the guard asks `enforcer.decide(...)` for a `Decision`. On non-allow, it returns `decision.as_error_message()` — a `[policy_denied]` or `[approval_required]` markered string the model can interpret and recover from.
- The run executes inside `propagate_attributes(user_id=..., session_id=..., metadata={"user_role": ...})`, so Langfuse spans carry the caller identity.

`run_sync` and `run_streamed` work the same way.

### LangChain / LangGraph — `wrap_langchain_agent`

`wrap_langchain_agent` builds a `PolicyEnforcer` once and installs it on each tool in place (`install_enforcer_on_tool`) so the same instances inside the compiled graph become policy-gated. It returns a `HexgateLangchainAgent` proxy that opens a `User` scope and injects a Langfuse callback into every `invoke` / `ainvoke` / `stream` / `astream` / `astream_events` call. The `user` is supplied **per call**, so a single wrapped agent can serve many users concurrently — role resolution happens at call time from the contextvar.

```python
import asyncio
from dotenv import load_dotenv
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from hexgate.runtime import User
from hexgate.adapters.langchain import wrap_langchain_agent


@tool
def get_weather(city: str) -> str:
    """Return a weather report for a city."""
    return f"The weather in {city} is 21°C and sunny."


@tool
def delete_user(user_id: str) -> str:
    """Delete a user account. Destructive."""
    return f"User {user_id} deleted."


TOOLS = [get_weather, delete_user]


async def main():
    load_dotenv()

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    graph = create_react_agent(llm, TOOLS)

    agent = wrap_langchain_agent(
        agent=graph,
        tools=TOOLS,          # same list passed to create_react_agent — wrapped in place
        api_key="sk-...",     # or rely on HEXGATE_KEY
    )

    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "What is the weather in Tokyo?"}]},
        user=User(user_id="langchain_user_1", role="member", session_id="session_abc"),
    )
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
```

What happens under the hood:

- `wrap_langchain_agent` builds a `PolicySet` for the agent, constructs one `PolicyEnforcer(policy_set, agent_name=…)`, and calls `install_enforcer_on_tools(tools, enforcer=…)` to mutate each tool's `func` and `coroutine` with enforcer-gated closures. `handle_tool_error` is forced to `True`. Installation is idempotent — re-installing rebinds the captured originals to the new enforcer without stacking gates.
- Each invocation method on `HexgateLangchainAgent` takes `user=` and opens an `async with user:` (or `user.sync_scope()` for sync) around the delegated `CompiledStateGraph` call. The active `User` is pushed onto a contextvar; the guards read it at tool-call time to resolve the matching role's policy.
- A non-allow `Decision` is rendered as `{"ok": False, "error": decision.as_error_payload()}` so the LangChain runtime surfaces the structured dict as the tool result instead of raising.
- The wrapper also enters `propagate_attributes(user_id=..., session_id=..., metadata={"user_role": ...})` and merges a Langfuse `CallbackHandler` into the `RunnableConfig.callbacks` for the duration of the call. Anything not explicitly proxied falls through via `__getattr__`.

### Google ADK — `HexgateRunner`

The Google ADK wrapper exposes its own `HexgateRunner`. It's constructed up front with the agent, app name, and session service (mirroring the ADK `Runner` constructor) — the underlying ADK `Runner` is built once and reused since role resolution happens at call time. `run` / `run_async` then yield ADK events.

```python
import asyncio
from datetime import datetime

from dotenv import load_dotenv
from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.sessions import InMemorySessionService
from google.genai import types

from hexgate.runtime import User
from hexgate.adapters.google import HexgateRunner


def get_weather(city: str) -> str:
    """Get the current weather for a given city."""
    return f"{city}: sunny, 23°C, humidity 50%, wind 10 m/s"


def get_current_time() -> str:
    """Return the current local time as an ISO-8601 string."""
    return datetime.now().isoformat()


async def main():
    load_dotenv()

    agent = Agent(
        name="google_runner_example_agent",
        model=LiteLlm(model="openai/gpt-4o"),
        instruction="Use get_current_time and get_weather when asked.",
        tools=[get_current_time, get_weather],
    )

    user = User(
        user_id="google_user_1",
        session_id="google_session_1",
        role="user",
    )

    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name="google_runner_example",
        user_id=user.user_id,
        session_id=user.session_id,
    )

    runner = HexgateRunner(
        agent=agent,
        app_name="google_runner_example",
        session_service=session_service,
    )  # picks up HEXGATE_KEY from env

    user_msg = types.Content(
        role="user", parts=[types.Part(text="What is the weather in New Delhi?")]
    )

    async for event in runner.run_async(new_message=user_msg, user=user):
        if event.is_final_response():
            print(event.content.parts[0].text)


if __name__ == "__main__":
    asyncio.run(main())
```

What happens under the hood:

- At construction, `HexgateRunner` calls `wrap_google_agent`, which builds a `PolicySet`, constructs one `PolicyEnforcer`, and returns `agent.model_copy(update={"tools": guarded_tools})` — your original `agent` is untouched.
- Each tool is normalized first: bare callables in `agent.tools` are wrapped into `FunctionTool` (matching what ADK does internally) so the guard has a stable `BaseTool` surface. Each tool is then `copy.copy`'d and its `run_async` replaced with an enforcer-gated version.
- Each `run` / `run_async` call opens a `User` scope (`user.sync_scope()` / `async with user:`) and dispatches to the cached underlying `Runner`. On non-allow, the guard returns `decision.as_error_message()` — a `[policy_denied]` or `[approval_required]` markered string — so the ADK runtime forwards it to the model as the tool output instead of aborting the run.
- Observability is set up lazily on each call: `GoogleADKInstrumentor().instrument()` plus `nest_asyncio.apply()` (ADK's runner spins its own loop), and the run executes inside `propagate_attributes(user_id=..., session_id=..., metadata={"user_role": ...}, tags=["google.runner.run.<agent_name>"])` so Langfuse spans carry the caller identity.

### Pydantic AI — `wrap_pydantic_agent`

`wrap_pydantic_agent` returns a `HexgatePydanticAgent` proxy backed by a clone of the original agent whose tools are gated by a freshly built `PolicyEnforcer`. Tools registered via the `Agent(...)` constructor or via `@agent.tool` / `@agent.tool_plain` are all picked up. The `user` is supplied **per call**, so a single wrapped agent can serve many users concurrently — role resolution happens at call time from the contextvar.

```python
import asyncio
from dotenv import load_dotenv
from pydantic_ai import Agent

from hexgate.runtime import User
from hexgate.adapters.pydantic_ai import wrap_pydantic_agent


async def main():
    load_dotenv()

    agent = Agent("openai:gpt-4o-mini")

    @agent.tool_plain
    def get_weather(city: str) -> str:
        """Return a weather report for a city."""
        return f"The weather in {city} is 21°C and sunny."

    @agent.tool_plain
    def delete_user(user_id: str) -> str:
        """Delete a user account. Destructive."""
        return f"User {user_id} deleted."

    agent = wrap_pydantic_agent(
        agent=agent,
        api_key="sk-...",  # or rely on HEXGATE_KEY
    )

    result = await agent.run(
        "What is the weather in Tokyo?",
        user=User(
            user_id="pydantic_ai_user_1",
            role="member",
            session_id="pydantic_ai_session_1",
        ),
    )
    print(result.output)


if __name__ == "__main__":
    asyncio.run(main())
```

What happens under the hood:

- `wrap_pydantic_agent` builds a `PolicySet`, constructs one `PolicyEnforcer`, reads tools off the agent's internal `_function_toolset`, copies each tool with an enforcer-gated `function_schema.call`, and returns a shallow-copied agent whose toolset holds those gated copies — your original `agent` is untouched, so it can be reused or wrapped again independently.
- Each invocation method on `HexgatePydanticAgent` (`run` / `run_sync` / `run_stream` / `iter`) takes `user=` and opens a `User` scope around the delegated `Agent` call. The contextvar is per-task, so concurrent `run` calls for different users do not see each other's policies.
- A non-allow `Decision` raises `ModelRetry(decision.as_error_message())`; pydantic_ai surfaces it back to the model as a tool-result message — `[policy_denied]` / `[approval_required]` markers in the same shape as the OpenAI/Google adapters — instead of aborting the run.
- Identity propagation uses `propagate_attributes(...)` so Langfuse spans carry the caller identity. Global tracing is enabled via `Agent.instrument_all()` on construction.

### Runnable examples

Working scripts in `examples/`:

- `examples/customer_bot.py` — canonical Hexgate path: `create_agent(...)` + the dashboard register/serve loop end-to-end.
- `examples/openai_demo.py` — `HexgateRunner` (OpenAI Agents SDK) end-to-end.
- `examples/google_demo.py` — `HexgateRunner` (Google ADK) end-to-end with `InMemorySessionService`.
- `examples/pydantic_ai_demo.py` — `wrap_pydantic_agent` (Pydantic AI) end-to-end.

> **Note on naming.** These demo files end in `_demo.py` so their filenames don't shadow the installed packages they import (`agents`, `google`, `langchain`, `openai`, `pydantic_ai`). Without the suffix, running any script inside `examples/` would put the directory on `sys.path[0]` and Python would import the demo files instead of the real packages.

## 🧠 Define Agents In Code

You can define agents directly in Python with `create_agent(...)`.

If you want the CLI and shared loader to resolve that agent by name, register it first and then load it through `load_agent(...)`.

A small end-to-end example registry lives in:

- `examples/file_agents.py`
- `examples/research_agents.py`

It demonstrates:

- building one agent with `create_agent(...)` only
- building another with `create_agent(...)` plus `enforce_policy(...)`
- building a research agent with approval-gated file writes via `enforce_policy(..., approval_handler=...)`
- registering it with `register_agent(...)`
- loading it through the shared `load_agent(...)` path

For the CLI, you can import that script and then pick one of its registered agents:

```bash
hexgate chat --use examples/file_agents.py --agent workspace_explorer
hexgate chat --use examples/file_agents.py --agent repo_editor
hexgate chat --use examples/research_agents.py --agent update_researcher
```

## 🗂️ Builtin And Local Agents

The package now ships with a small `hexgate.builtin_agents` directory for official starter agents.

Current builtin agents:

- `researcher`

Example:

```python
from hexgate import load_builtin_agent

agent, handler = load_builtin_agent("researcher")
```

The CLI also discovers local agents from:

- `./<agent_dir>/agent.yaml`
- `./agents/<agent_dir>/agent.yaml`
- `./examples/<agent_dir>/agent.yaml`

This repo ships a demo agent at `examples/example_agent/`, so from the project root you can simply run:

```bash
hexgate chat --agent example_agent
```

## 🔐 Policy Shape

Each tool gets a mode and an optional list of constraints:

```yaml
version: 1

default_policy:
  mode: deny

tools:
  web_search:
    mode: allow
  fetch:
    mode: allow
  refund_order:
    mode: allow
    constraints:
      - args.amount <= 500
      - args.currency == "USD"
```

Supported modes:

- `allow`
- `deny`
- `approval_required`

Constraint operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`. Strings on the right use JSON double quotes. Every constraint must pass for the call to authorize (implicit AND). See [User Scope + Roles](#-user-scope--roles) for the role-aware policy bundle shape that picks a per-role policy at call time.

## 🛡️ Tool-Call Policy Enforcement

Every tool call routes through a `PolicyEnforcer` that returns `allow` / `deny` / `approval_required`. Deny-by-default; the policy file lists what's allowed.

`create_agent(...)` stays close to LangChain. Policy enforcement is applied after agent creation:

```python
from hexgate import AgentPolicy, create_agent, enforce_policy, fetch, web_search

policy = AgentPolicy.model_validate(
    {
        "version": 1,
        "default_policy": {"mode": "deny"},
        "tools": {
            "web_search": {"mode": "allow"},
            "fetch": {"mode": "allow"},
        },
    }
)

agent, handler = create_agent(
    model="openai:gpt-5.4",
    tools=[web_search, fetch],
    system_prompt="You are a careful research assistant.",
)

agent = enforce_policy(agent, policy)
```

`enforce_policy(...)` accepts either:

- a Pydantic `AgentPolicy`
- a YAML file path

That means the same agent code can stay simple in development, while deployment systems can inject policy later.

`approval_required` is special:

- if no approval handler is attached, it behaves like a graceful block — the tool returns a structured `ok: False` result with `error_type: "approval_required"` so the agent can try a fallback instead of crashing
- if an approval handler is attached (via `enforce_policy(..., approval_handler=...)`), the host can decide whether to allow the action at runtime

## 🧩 Policy Bundles — Compile, Sign, Enforce (WASM)

Hexgate has **two policy enforcement engines** that return identical decisions (there's a parity test suite that proves it):

- **pydantic** (default) — evaluates constraints in-process. Zero setup; this is what every example above uses.
- **WASM** — compiles `policy.yaml` → Rego → a WebAssembly module evaluated via `wasmtime`. This is the path production ships: one compiled artifact, byte-for-byte reproducible, cryptographically signed by the platform.

Why a second engine: the WASM path produces a **portable, signed artifact** (a "bundle"), surfaces **structured deny reasons** (exactly which constraints failed), and chains trust back to the platform's signing key — the same key that signs your biscuit tokens.

### Prerequisite — `opa`

The WASM compile step shells out to the [Open Policy Agent](https://www.openpolicyagent.org/) binary. Install it once:

```bash
brew install opa            # macOS
# or see https://www.openpolicyagent.org/docs/latest/#running-opa
```

Without `opa` on `PATH`, `hexgate policy build --no-wasm` still emits the yaml + rego (no `.wasm`), and the pydantic engine keeps working.

### The `hexgate policy` CLI

```bash
# Validate a policy.yaml without the network — parse + check every constraint
hexgate policy validate policy.yaml

# See the Rego your YAML compiles to (stdout)
hexgate policy show-rego policy.yaml

# Dry-run a single decision. --engine wasm compiles + evaluates in wasmtime
# (matching production); the default pydantic engine needs no opa.
hexgate policy test policy.yaml --role billing --tool refund_order \
    --args '{"amount": 200, "currency": "USD"}' --engine wasm

# Compile a bundle: writes {stem}.yaml + .rego + .wasm + .bundle.json
hexgate policy build policy.yaml --out ./bundle
```

On a denied decision, `test` prints the reason; the wasm engine additionally lists each violated constraint string verbatim:

```text
✗ DENY · billing → refund_order({"amount": 700})
  reason: Policy denied tool "refund_order": args.amount <= 500
  violations:
    • args.amount <= 500
```

### What's in a bundle

`hexgate policy build` produces a directory:

| File | Contents |
|---|---|
| `{stem}.yaml` | the source policy (verbatim) |
| `{stem}.rego` | the compiled Rego module |
| `{stem}.wasm` | the WebAssembly module — what actually evaluates at runtime |
| `{stem}.bundle.json` | manifest: sha256 of each artifact + a `wasm_hash` |
| `{stem}.bundle.json.sig` | detached Ed25519 signature over the manifest (signed bundles only) |

The manifest's hashes authenticate the files; the signature authenticates the manifest. Verifying both proves the whole bundle came from the trusted signer, untampered.

### Local enforcement — `HEXGATE_LOCAL_POLICY`

Point an agent at a local source and every tool call routes through the WASM engine instead of pydantic — no platform needed. Two shapes are accepted, and both **hot-reload on save** (no restart, no manual rebuild between turns):

| `HEXGATE_LOCAL_POLICY=…` | What happens | When to use |
|---|---|---|
| **`./bundle/`** (output of `hexgate policy build`) | Stat the bundle manifest each turn; reload if its mtime changed. | Production-shaped local testing — exercises the exact signed-bundle path. |
| **`./policy.yaml`** | Stat the yaml each turn; recompile via `opa` when its mtime changed. | The tight dev loop — edit yaml, save, ask again. No build step. |

```bash
# Pre-built bundle dir — rebuild it mid-session, next chat picks it up
hexgate policy build policy.yaml --out ./bundle
HEXGATE_LOCAL_POLICY=./bundle hexgate chat --agent researcher
# [hexgate] HEXGATE_LOCAL_POLICY active (bundle-dir): ./bundle (wasm_hash=7e6d1f8b..., unsigned)

# Raw yaml — edit policy.yaml in your editor, save, next chat sees the new policy
HEXGATE_LOCAL_POLICY=./policy.yaml hexgate chat --agent researcher
# [hexgate] HEXGATE_LOCAL_POLICY active (yaml): ./policy.yaml (wasm_hash=ab12..., unsigned)
```

The bundle's integrity (files match the manifest) is verified on every reload — a stale or corrupt bundle fails immediately, not at the first tool call. Yaml sources default to **unsigned**: set `HEXGATE_BUNDLE_SIGN_KEY_PATH=./keys/dev.private` to sign each recompile with your `hexgate policy keygen` key, so downstream gates that check `bundle.is_signed` see what they expect.

> **Same refresh seam as the platform.** Under the hood both sources implement `PolicySource.fetch()`; the agent runtime calls it at the top of every turn and only swaps the active policy when the returned bundle is a new instance. Unchanged → identity match → no work. That's the same hot-reload path `hexgate serve` uses for platform-edited YAML.

### Signing & verification

Production bundles are signed so the runtime can prove a bundle is genuine before trusting it. The integrity hash chain catches accidental corruption; the signature catches a malicious author who edits a file *and* updates the manifest to match.

Generate a keypair and sign a bundle locally:

```bash
hexgate policy keygen --out ./keys/dev          # → dev.private (0600) + dev.public
hexgate policy build policy.yaml --out ./bundle --sign-key ./keys/dev.private
# → ./bundle/policy.bundle.json.sig
```

At runtime, point the verifier at the public key:

```bash
HEXGATE_LOCAL_POLICY=./bundle \
HEXGATE_BUNDLE_PUBKEY_PATH=./keys/dev.public \
HEXGATE_BUNDLE_REQUIRE_SIGNATURE=true \
hexgate chat --agent researcher
# [hexgate] HEXGATE_LOCAL_POLICY active (bundle-dir): ./bundle (wasm_hash=..., signed)
```

`HEXGATE_BUNDLE_REQUIRE_SIGNATURE` controls strictness — warn-by-default keeps local dev frictionless; opt into refusal for CI/prod:

| Bundle | `PUBKEY_PATH` set | `REQUIRE_SIGNATURE` | Outcome |
|---|---|---|---|
| signed | yes | either | verify; **refuse if it fails** |
| signed | no | `false` | load with warning (can't verify) |
| signed | no | `true` | **refuse** (no key to check against) |
| unsigned | — | `false` (default) | load with warning |
| unsigned | — | `true` | **refuse** |

Keys are raw Ed25519, base64url-encoded — the same format the platform's JWKS endpoint publishes, so production verification reuses the public key your SDK already trusts for biscuit tokens. One root key, two artifacts.

> **Keys are gitignored.** `*.private` and `*.pem` are in `.gitignore` so a signing key never lands in version control. Public keys (`*.public`) are safe to commit.

## ✅ Approval-Required Tool Calls

Approval handlers are the bridge between static policy and real product interaction. Use them when a tool should be **generally allowed in principle** but only after a user, CLI host, or UI host explicitly approves the specific call.

The handler is threaded through `enforce_policy(...)` at wrap time:

- `enforce_policy(agent, policy, approval_handler=handler)`
- `handler` can be:
  - `True` — auto-approve every approval-required call
  - `False` — auto-deny every approval-required call
  - sync function `(action: dict, context: dict | None) -> bool`
  - async function `(action: dict, context: dict | None) -> bool | Awaitable[bool]`

The `action` dict carries `{"tool_name", "arguments", "agent_name"}`; `context` is reserved for future host-supplied runtime metadata and is `None` today.

Example:

```python
from hexgate import (
    AgentPolicy,
    create_agent,
    edit_file,
    enforce_policy,
    read_file,
)

policy = AgentPolicy.model_validate(
    {
        "version": 1,
        "default_policy": {"mode": "deny"},
        "tools": {
            "read_file": {"mode": "allow"},
            "edit_file": {"mode": "approval_required"},
        },
    }
)

def approval_handler(action: dict, _context: dict | None) -> bool:
    print("approval requested:", action["tool_name"], action["arguments"])
    return True

agent, handler = create_agent(
    model="openai:gpt-5.4",
    tools=[read_file, edit_file],
    system_prompt="You are a careful editor.",
)

agent = enforce_policy(agent, policy, approval_handler=approval_handler)
```

The handler returns a boolean today. Future evolution (richer approval decisions, interrupt/resume flows, UI approval cards, audit metadata) is intentionally left open — the current `(action, context) -> bool` API is enough for CLI and simple hosted apps.

## 🧱 Workspace Sandbox

When the `bash` tool executes a command it runs inside an OS-level sandbox configured from the agent's workspace. This is filesystem + network enforcement at the kernel level — a separate concern from policy enforcement, which decides *whether* a tool may be invoked at all.

### Runtime requirement

The `bash` tool depends on **`srt`** (Anthropic's `sandbox-runtime`). It wraps each command in `sandbox-exec` + a Seatbelt profile (macOS) or `bubblewrap` + a network namespace + a seccomp filter (Linux).

Install before using the `bash` tool:

```bash
npm install -g @anthropic-ai/sandbox-runtime
```

Supported on **macOS and Linux only** (Windows is unsupported). If `srt` is not on `PATH`, `run_command` raises `SrtUnavailableError` rather than falling back to unsandboxed execution — *fail closed by design*.

### Configuration

Tune the boundary through `LocalWorkspace`:

```python
from hexgate.runtime import LocalWorkspace

workspace = LocalWorkspace(
    root_dir="./project",
    allowed_domains=["api.github.com", "*.pypi.org"],
    extra_read_paths=["/etc/ssl"],
    extra_write_paths=["/tmp/build"],
    deny_write_paths=[".env"],
    allow_unix_sockets=["/var/run/docker.sock"],
    allow_local_binding=False,
    extra_env={"NODE_ENV": "test"},
)
```

| Knob | What it controls | Default |
|---|---|---|
| `root_dir` | Workspace root; reads + writes allowed inside | required |
| `allowed_domains` | Hostnames the proxy forwards | `()` — no egress |
| `denied_domains` | Hostnames the proxy refuses | `()` |
| `extra_read_paths` | Read-only paths beyond the workspace | `()` |
| `extra_write_paths` | Writable paths beyond workspace + `/tmp` | `()` |
| `deny_write_paths` | Paths the agent can never write to | `()` |
| `allow_unix_sockets` | Unix sockets the agent can `connect()` | `()` — no IPC |
| `allow_local_binding` | Whether the agent can `bind(127.0.0.1, …)` | `False` |
| `extra_env` | Env vars passed into the sandbox | `{}` |

Defaults add up to: no network egress, no IPC sockets, no localhost bind, reads allowed inside the workspace and on system paths but not `$HOME`, writes allowed only inside the workspace + `/tmp`.

`allowUnixSockets` and `allowLocalBinding` exist because they're the two ways traffic can leave the proxy lane (Unix-domain IPC and inbound localhost). Default-deny on both; opt in per-deployment when you actually need docker-socket access, a local dev server, etc.

### Env scrubbing

The sandboxed child does **not** inherit the parent process's environment. Only an explicit allowlist passes through:

- `PATH` (curated baseline including `/opt/homebrew/bin` for Apple Silicon)
- `HOME` (set to the workspace root, so cache writes land inside `allowWrite`)
- `TMPDIR`, `TERM`
- Locale keys: `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_COLLATE`, `LC_MESSAGES`
- Anything operator-supplied via `extra_env`

This means parent-process secrets — `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GH_TOKEN`, `SSH_AUTH_SOCK`, etc. — **don't leak** into the agent. Tools that legitimately need credentials should receive them through `extra_env`, where you control exactly what's passed.

### Layering with policy + approval

| Layer | Question | Mechanism |
|---|---|---|
| **Policy** | Is this tool allowed at all for this caller's role? | adapter / `enforce_policy(...)` |
| **Approval** | Should this specific call go ahead? | `enforce_policy(..., approval_handler=...)` |
| **Sandbox** | What can the spawned shell actually do? | OS-level via `srt` |

Policy decides whether the `bash` tool is callable. The approval handler inspects each call gated by `approval_required`. The sandbox bounds reach *if a call does run*. They're complementary — deploy whichever combination matches your threat model.

### What the sandbox does NOT do

Worth being explicit about the gaps so operators know where to layer their own checks:

- **Resource limits.** No CPU/memory/fork caps. A fork-bomb runs to completion. Use cgroups or `ulimit` if that matters.
- **Command-string semantics.** `srt` sees `sh -c "<command>"` as an opaque arg. The sandbox bounds *reach*, not intent — `rm -rf <workspace>` is permitted because the workspace is in `allowWrite`.
- **Inside-sandbox actions.** The sandbox stops the agent from exfiltrating a workspace file over the network or writing outside the boundary, but doesn't reason about what the agent does *within* the boundary.

## 🔧 Environment

Copy `.env.sample` to `.env` and set:

- `OPENAI_API_KEY`
- `LINKUP_API_KEY`
- `TAVILY_API_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_PUBLIC_KEY`
- optional `LANGFUSE_HOST`

Policy-bundle enforcement (see [Policy Bundles](#-policy-bundles--compile-sign-enforce-wasm)) reads a few more, all optional:

| Env var | Purpose |
|---|---|
| `HEXGATE_LOCAL_POLICY` | Path to a bundle directory **or** a `policy.yaml`; routes enforcement through the WASM engine and hot-reloads on save |
| `HEXGATE_BUNDLE_PUBKEY_PATH` | base64url Ed25519 public key used to verify a bundle's signature |
| `HEXGATE_BUNDLE_SIGN_KEY_PATH` | base64url Ed25519 private key used to sign locally-compiled yaml sources (so `bundle.is_signed` is True) |
| `HEXGATE_BUNDLE_REQUIRE_SIGNATURE` | `true` to refuse unsigned or unverifiable bundles (default: warn only) |
| `HEXGATE_OPA_BIN` | Override the `opa` binary location (default: search `PATH`) |

## 🧪 Tests & Dev Tooling

A `Makefile` at the repo root wraps the day-to-day commands so you don't have to remember the `uv` incantations.

```bash
make help            # list every target with descriptions
make install-dev     # uv sync --extra dev (first time only)
make test            # full SDK test suite, quiet
make check           # lint + fmt-check + test (matches CI)
make test-one T=tests/security/test_bundle.py   # single file
```

Targets at a glance:

| Target | What it runs |
|---|---|
| **SDK dev loop** | |
| `test` / `test-verbose` / `test-failed` / `test-one` | `pytest tests/` with various flags |
| `lint` / `lint-fix` | `ruff check` (with `--fix` for autofixes) |
| `fmt` / `fmt-check` | `ruff format` |
| `check` | `lint` + `fmt-check` + `test` — pre-push gate |
| **M2 policy demo** | |
| `policy-build` | Compile the example policy.yaml to a bundle |
| `policy-test-wasm` | Smoke a WASM-engine decision |
| `demo-override` | Build a deny bundle + chat with `HEXGATE_LOCAL_POLICY` |
| **Platform demo** (multi-terminal — see `make demo-platform`) | |
| `platform-api` / `platform-api-install` / `platform-api-test` | FastAPI control plane in `platform/api/` |
| `dashboard` / `dashboard-install` | Vite + React app in `platform/dashboard/` |
| `serve` | `hexgate serve` — bridge this SDK to the platform |
| `demo-platform` | Print the 3-terminal recipe |
| **Misc** | |
| `build` / `clean` | Package + tidy |

By default `uv` manages its own `.venv` (created by `make install-dev`). If you keep your dev environment elsewhere — e.g. a `micromamba` env — point `uv` at it once and `make` picks it up:

```bash
export UV_PROJECT_ENVIRONMENT=/Users/<you>/micromamba/envs/<your-env>
uv sync --extra dev           # one-time: install dev deps into that env
make test                     # now runs against the micromamba env
```

Drop the `export` into your shell rc (or a `direnv` `.envrc`) and forget about it. Without `--extra dev`, `pytest-asyncio` is missing and you'll see *"async functions are not natively supported"* across every async test — same trap on a fresh env.

The platform-side test suite is separate and lives at `platform/api/tests/`:

```bash
cd platform/api && uv run pytest tests/
```

## 🖥️ CLI reference

The `hexgate` binary exposes `chat`, `serve`, `register`, and `policy` subcommands. The [Quick Start](#-quick-start--local-cli) covers `chat`; this section drills into `register` and `serve` for the platform path.

```bash
hexgate --help                                     # list subcommands
hexgate <subcommand> --help                        # flags for a subcommand
hexgate chat --list-agents                         # show resolvable agents
hexgate chat --use examples/file_agents.py --agent workspace_explorer
hexgate chat --use examples/research_agents.py --agent update_researcher --approval-mode ask
```

### `hexgate register` — push a manifest to the platform

Register a code-defined agent's manifest with the Hexgate platform. `--agent`
takes a Python import path of the form `module.path:attribute`, the same shape
as ASGI/WSGI entrypoints. The CLI imports the module, grabs the agent object,
and POSTs its manifest to `${HEXGATE_API_URL}/v1/agents` using
`${HEXGATE_KEY}` as the bearer token:

```bash
hexgate register --agent examples.customer_bot:agent
hexgate register --agent my_app.agents:my_agent --description "Customer support bot"
```

On first register, the platform auto-generates a starter role-aware
policy from the manifest's tool list (`read_only` mixin + `default` +
`member` + `admin`) and signs a WASM bundle so `hexgate serve` runs
against real enforcement from the first request. Edit the policy in
the dashboard's `/policies` page; subsequent re-registers preserve
those edits — only the manifest snapshot grows.

LangGraph compiled graphs don't expose their tool nodes — nor the model or
system prompt baked into them — after compilation, so when registering one
you can pass each of those pieces explicitly. Only `--tools` is required;
`--model` and `--system-prompt` are optional and just populate the matching
fields on the manifest so the dashboard can show them:

```bash
hexgate register \
    --agent my_app.agents:graph \
    --tools my_app.tools:my_tools \
    --model gpt-4o-mini \
    --system-prompt prompts/support.md
```

For everyone else — agents built with `hexgate.create_agent(...)`, OpenAI
Agents, Pydantic AI, Google ADK — the manifest reads tools, model, and
system prompt directly off the object. No flags needed.

`--system-prompt` accepts either a literal string or a path to a `.md` /
`.txt` / `.jinja` file (read as text at register time).

Supported frameworks: OpenAI Agents SDK, Google ADK, Pydantic AI, LangChain/LangGraph, Hexgate agents.

### `hexgate serve` — bridge a local agent to the platform's relay

`hexgate serve` takes the **same** `module:attr` spec as `hexgate register`.
The CLI imports the agent, derives the manifest in one call, auto-registers
on the platform (idempotent — content-hash short-circuits no-ops), fetches
the operator's policy from the cloud, and opens the WebSocket relay so the
dashboard's Playground can drive it. Policy edits in `/policies` take
effect at the next chat-turn boundary.

```bash
hexgate serve examples.customer_bot:agent

# CI / deliberate-deploy: error if not pre-registered
hexgate serve examples.customer_bot:agent --no-auto-register
```

There is **no** `HEXGATE_AGENT_NAME` env var anymore — the name lives in
the agent's `.name` attribute (or the `name=` kwarg you passed to
`create_react_agent` / `create_agent`). The platform is the source of
truth for policy; your Python file is the source of truth for code.

### Build A Manifest Programmatically — `create_manifest`

If you need the manifest object without POSTing it to the platform — to
inspect it, persist it elsewhere, diff it across versions, or wire it
into a custom registration flow — call `create_manifest` directly:

```python
from hexgate import create_manifest

manifest = create_manifest(agent, description="Customer support bot")
print(manifest.model_dump())
```

`create_manifest` dispatches on the framework of `agent`. The supported
types are the same set `hexgate register` accepts: Hexgate, OpenAI Agents
SDK, Google ADK, Pydantic AI, and LangChain/LangGraph compiled graphs.
For LangGraph you must pass `tools=` explicitly, and may pass `model=` /
`system_prompt=`, since compiled graphs don't expose those fields after
compilation.

The return value is an `AgentManifest` (a Pydantic model, also re-exported
from `hexgate` for type annotations) — the same schema the platform
stores and the dashboard renders.

## 🌐 Hexgate Platform

The `platform/` directory contains an optional control plane that hosts agent definitions, dev tokens, and a live debug surface. The SDK works fully without it (`load_local_agent`, `load_builtin_agent` keep their existing semantics) — but with it you get:

- A web dashboard for editing agent YAMLs and viewing the project graph
- Mintable dev tokens (`fty_test_*`, `fty_live_*`) that authenticate the SDK
- A live Playground that streams tool calls and decisions from your running agent
- **Turn-level policy refresh** — edit YAML in the UI, the next chat picks it up

### Backend (`platform/api/`)

FastAPI over SQLite. Run with:

```bash
cd platform/api
uv run uvicorn hexgate_api.main:app --reload --port 8000
```

The default `support-bot` project is seeded on first boot with two agents — `default` (broad access, side-effects gated by `approval_required`) and `read_only` (everything mutating denied).

Endpoints:

- `POST /v1/projects/:id/tokens` — mint a dev token (returned in full once)
- `GET /v1/projects/:id/tokens` — list dev tokens (masked)
- `DELETE /v1/projects/:id/tokens/:tid` — revoke
- `GET /v1/projects/:id/agents` — list agents with their YAMLs
- `GET /v1/projects/:id/agents/:name` — read one agent
- `PUT /v1/projects/:id/agents/:name` — save agent / policy / system YAMLs
- `WS /v1/projects/:id/serve` — producer socket (the `hexgate serve` CLI dials here)
- `WS /v1/projects/:id/chat` — consumer socket (the dashboard Playground dials here)

DB lives at `platform/api/hexgate.db`. Delete it and restart to wipe state.

### Dashboard (`platform/dashboard/`)

Vite + React + Tailwind + shadcn/ui + React Flow.

```bash
cd platform/dashboard
pnpm install        # first time
pnpm dev
```

Routes:

- `/` — overview KPIs
- `/agents` — file-tree YAML editor + live mini-graph per agent
- `/graph` — read-only project overview (everyone → agents → tools)
- `/playground` — chat with a serving agent, watch tool decisions stream live
- `/tokens` — mint, list, revoke dev tokens
- `/settings` — project settings

The dev server proxies `/v1/*` (HTTP and WebSocket) to `localhost:8000`, so HMR works through the same origin as the API.

### Serve Mode (`hexgate serve`)

Bridges your local agent runtime to the dashboard via the platform's WebSocket relay — same pattern as Cloudflare Tunnel or ngrok.

```bash
# in asianf/.env
HEXGATE_KEY=fty_live_<project>_<biscuit>
HEXGATE_API_URL=http://localhost:8000       # optional, defaults to localhost:8000

# pick an agent module:attr — uvicorn-style spec
uv run hexgate serve examples.customer_bot:agent
```

Behaviour:

- Loads the agent object from the `module:attr` spec — same form as
  `hexgate register`. The agent's name, tools, model, and system
  prompt come from the object directly (no flags duplicating
  what's already in code).
- Auto-registers the manifest on first run via `POST /v1/agents`
  (idempotent — content-hash short-circuits no-ops). Skip with
  `--no-auto-register` for CI / deliberate deployments.
- Fetches the operator's policy from `GET /v1/agents/{name}`. Local
  code is authoritative for code; the platform is authoritative for
  policy.
- Connects `wss://${HEXGATE_API_URL}/v1/serve` with the bearer
  percent-encoded into the WebSocket subprotocol (Phase 6 — the WS
  handshake grammar doesn't allow `=` padding in plain headers).
  Server echoes `hexgate.v1` to confirm the contract.
- Sends a `hello` frame announcing the agent name (the dashboard's
  "Serving" indicator reads this).
- On each inbound `chat` message, **refreshes the active policy**
  before running. Refresh is an `If-None-Match` round-trip to the
  platform: a 304 reuses the cached WASM module, a 200 swaps in the
  new bundle. Dashboard edits take effect at turn boundaries without
  restarting the process or re-wrapping the tools.
- Streams every `StreamEvent` (text deltas, tool start/end, run end)
  back as JSON.
- Auto-approves any `approval_required` tools — there's no TTY in
  serve mode for prompts (planned: dashboard-side approval UI).
- Reconnects with exponential backoff on socket drop.

There's no longer a `HEXGATE_AGENT_NAME` env var, `--agent` flag, or
`--use` flag — the spec carries everything. If you've been setting
`HEXGATE_AGENT_NAME` in `.env`, drop it.

### How `load_agent()` resolves with `HEXGATE_KEY`

```python
from hexgate import load_agent

agent, handler = load_agent("read_only")     # explicit name required
```

When `HEXGATE_KEY` is set, `load_agent(name)` fetches the named agent from
the platform (via `load_hexgate_agent`). When `HEXGATE_KEY` is not set, it
falls back to local / registered / builtin resolution — no platform call.

The legacy `HEXGATE_AGENT_NAME` env-var fallback was removed in Phase 7;
direct callers of `load_hexgate_agent` / `load_agent` must pass an
explicit name. For the CLI workflow, `hexgate serve <module:attr>` derives
the name from the loaded agent's `.name` attribute — no env var needed.

## 👤 User Scope + Roles

Real backends serve many users, and different users get different capabilities. Hexgate splits that into two pieces:

- **`User`** — the per-request scope. Marks "this invocation acts on behalf of alice, in role X." Async context manager; pushes a fact-bearing Biscuit through the agent runtime.
- **Role policies** — one `policy.yaml` per role, optionally inheriting from a base mixin. The runtime picks the right one at call time based on the active `User.role`.

The two are deliberately decoupled: tokens carry **identity** (who is calling), policy files carry **rules** (what they can do).

### Minimal example

```python
from hexgate import User, load_hexgate_agent, stream_agent

agent, handler = load_hexgate_agent("support-bot")          # client + roles attached at load

async with User(user_id="alice", role="billing", ttl_seconds=300):
    async for event in stream_agent(agent, handler, "refund customer 30"):
        ...
```

That's it — no manual `attenuate_for_user`, `extract_facts`, or `ToolUseContext` plumbing at the call site. The runtime mints the per-request token, picks the `billing` role's policy file, and evaluates its constraints against each tool call.

### FastAPI middleware pattern

The cleanest production shape — set the scope once in middleware, every endpoint runs in the right user's role:

```python
from fastapi import FastAPI
from hexgate import User, load_hexgate_agent, stream_agent

app = FastAPI()
agent, handler = load_hexgate_agent("support-bot")          # at startup

@app.middleware("http")
async def attach_user(request, call_next):
    auth = await authenticate(request)                       # your auth
    async with User(
        user_id=auth.id,
        role=auth.role,                                       # e.g. "billing"
        session_id=request.state.session_id,
        ttl_seconds=300,
    ):
        return await call_next(request)

@app.post("/chat")
async def chat(req):
    async for event in stream_agent(agent, handler, req.message):
        yield event                                          # already scoped
```

### `User` fields

| Field | Type | Required | Effect |
|---|---|---|---|
| `user_id` | `str` | ✅ | Becomes `user("alice")` in the attenuated Biscuit. |
| `role` | `str?` | optional | Becomes `role("billing")` in the Biscuit. Selects which role policy file applies at tool-call time. Fall-back: the `default` role. |
| `session_id` | `str?` | optional | Trace tagging — surfaces on Langfuse spans. |
| `ttl_seconds` | `int?` | optional | Embeds a `check if time($t), $t < now+ttl` predicate so the token can't outlive the request. |

### Role policies — one file per role

Agents that need per-role behaviour ship a `policies/` directory instead of a single `policy.yaml`:

```text
agent/
├── agent.yaml
├── system.md
└── policies/
    ├── default.yaml          # fallback when User.role is None / unknown
    ├── read_only.yaml        # mixin — is_mixin: true
    ├── support.yaml          # inherits: [read_only]
    └── billing.yaml          # inherits: [read_only, support]
```

Each role file is a complete `AgentPolicy`. Inheritance is left-to-right, child wins on conflicts:

```yaml
# policies/read_only.yaml  (mixin — safe base)
version: 1
is_mixin: true
default_policy:
  mode: deny
tools:
  view_orders:  { mode: allow }
  list_tickets: { mode: allow }
```

```yaml
# policies/billing.yaml
version: 1
inherits: [read_only]
tools:
  refund_order:
    mode: allow
    constraints:
      - args.amount <= 500
      - args.currency == "USD"
  wire_transfer:
    mode: approval_required
    constraints:
      - args.amount <= 100000
```

### Constraints — Rego-compatible expressions

Each tool can carry a `constraints:` list of string expressions evaluated against the call's arguments. Every constraint must pass for the call to authorize (implicit AND).

| Operator | Example | Notes |
|---|---|---|
| `==` `!=` | `args.currency == "USD"` | Strings use JSON double quotes |
| `<` `<=` `>` `>=` | `args.amount <= 500` | Type-mismatched comparisons fail-closed |
| `in` | `args.template in ["a", "b"]` | RHS must be a JSON list |
| `not in` | `args.priority not in ["urgent"]` | Two-word operator, treated as one |

Constraints are Rego conditions by design: the [WASM engine](#-policy-bundles--compile-sign-enforce-wasm) compiles them to OPA Rego unchanged, and the pydantic engine evaluates the same strings in-process — both produce identical decisions. To compose with AND, emit multiple lines; to compose with OR, emit two tools or two roles.

### Policy + role end-to-end

With the `billing.yaml` policy above and `async with User(user_id="alice", role="billing")`:

- `refund_order(amount=200, currency="USD")` → ✅ allowed
- `refund_order(amount=600, currency="USD")` → ❌ denied — constraint `args.amount <= 500`
- `refund_order(amount=200, currency="EUR")` → ❌ denied — constraint `args.currency == "USD"`
- `wire_transfer(amount=50000)` → ✋ requires approval (mode = `approval_required`)

Switch to `User(user_id="alice", role="default")` and `refund_order` itself is missing from the policy — falls through to the `default_policy.mode` (deny).

### Notes

- **Single-file policies still work.** A legacy `policy.yaml` is treated as the `default` role — no migration needed for agents that don't yet differentiate by role.
- **Lazy attenuation.** `User.__aenter__` only pushes a contextvar — the cryptographic work happens inside `stream_agent` / `invoke_agent` the first time the agent runs. Errors surface at first agent call, not at scope entry.
- **Local agents skip attenuation.** A `User` scope around a `load_local_agent` / `load_builtin_agent` agent logs a warning and runs with no facts. The `default` policy still applies — use `load_hexgate_agent` for the full signed chain.
- **Explicit override.** Passing `tool_use_context=` explicitly to `stream_agent` / `invoke_agent` wins over an active `User` scope. Useful for tests or one-off bypass.
- **Sync callers.** `User` exposes both `async with user:` and `user.sync_scope()`. The async form is the primary API (room for KMS / audit / JWKS I/O in `__aenter__` / `__aexit__` later); the sync mirror exists for CLI loops and `Runner.run_sync`-style callers where the async ctxmgr protocol is unavailable.

## 📡 Stream Results

For direct Python usage, the simplest runtime path is:

```python
from hexgate import stream_agent

async for event in stream_agent(agent, handler, "latest AI breakthroughs"):
    ...
```

`stream_agent(...)` yields normalized events for:

- assistant text deltas
- tool lifecycle
- final run completion

---

If Hexgate looks useful, [give it a ⭐ on GitHub](https://github.com/HexamindOrganisation/hexgate) — it helps more than you'd think. Built by [Hexamind](https://hexgate.ai).
