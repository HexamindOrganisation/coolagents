<div align="center">

<img src="./icon.svg" alt="Hexgate" width="96" height="96" />

# Hexgate

**Authorization infrastructure for AI agents.**
Policy enforcement, signed policy bundles, per-request user scope, audit trail — for OpenAI Agents, LangChain, Google ADK, Pydantic AI, or a native runtime.

[**Website**](https://hexgate.ai) · [**Docs**](https://docs.hexgate.ai) · [PyPI](https://pypi.org/project/hexgate/) · [Discussions](https://github.com/HexamindOrganisation/hexgate/discussions)

[![PyPI](https://img.shields.io/pypi/v/hexgate?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/hexgate/)
[![CI](https://github.com/HexamindOrganisation/hexgate/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/HexamindOrganisation/hexgate/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/HexamindOrganisation/hexgate/branch/main/graph/badge.svg?flag=sdk)](https://codecov.io/gh/HexamindOrganisation/hexgate)
[![Downloads](https://img.shields.io/pypi/dm/hexgate?color=blueviolet)](https://pypi.org/project/hexgate/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<br />

<img src="./assets/hero.png" alt="Control what your agents do — not just what they say. Policy decisions streaming live from the PolicyEnforcer." />

</div>

---

## What is Hexgate?

Hexgate is two things that move together:

- **`hexgate` — the SDK.** A Python runtime that gates every tool call through a typed `Decision` (allow / deny / approval-required), wraps your existing OpenAI / LangChain / Google ADK / Pydantic AI agent without rewriting it, and threads per-request user identity through tracing + audit.
- **The Hexgate platform** *(optional)* — a FastAPI control plane + React dashboard for editing policy in a browser, minting per-project tokens, watching live decisions stream from a serving agent, and shipping signed WASM policy bundles to production. Available as **[Hexgate Cloud](https://app.hexgate.ai)** (hosted — set one env var, no infra) or self-hosted.

You can use the SDK three ways: **local** (YAML/bundle on disk, no platform), **Hexgate Cloud** (remote enforcement + audit — just set `HEXGATE_API_KEY`), or **self-hosted** (run the control plane yourself). `HEXGATE_API_URL` defaults to `https://app.hexgate.ai`, so remote enforcement is one env var away.

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

## Quickstart

```bash
pip install hexgate
cp .env.sample .env                       # fill in the keys you use
hexgate chat --agent example_agent        # terminal REPL against the demo agent
```

`hexgate chat` runs a single-process REPL with policy decisions rendered inline in
the terminal — no platform, no Docker. See the [full quickstart →](https://docs.hexgate.ai/quickstart)

## Documentation

Full documentation lives at **[docs.hexgate.ai](https://docs.hexgate.ai)**.

| | |
|---|---|
| [Build an agent](https://docs.hexgate.ai/guides/build-an-agent) | The two shapes — wrap an existing agent, or let the platform own the YAML. |
| [Framework adapters](https://docs.hexgate.ai/adapters/openai) | OpenAI Agents, LangChain/LangGraph, Google ADK, Pydantic AI. |
| [Policy](https://docs.hexgate.ai/policy/yaml-shape) | YAML shape, constraints, WASM bundles, signing, local override. |
| [User scope + roles](https://docs.hexgate.ai/concepts/user-scope) | Per-request identity, role resolution, biscuit attenuation. |
| [CLI](https://docs.hexgate.ai/cli/chat) | `chat`, `serve`, `register`, `policy`. |
| [MCP servers](https://docs.hexgate.ai/concepts/mcp) | Wrap any Model Context Protocol server as policy-enforced tools. |
| [Hexgate Cloud (hosted)](https://docs.hexgate.ai/platform/hosted) | Remote policy enforcement + audit with zero infra — get a key, set one env var. |
| [Platform (self-hosted)](https://docs.hexgate.ai/platform/overview) | Run the control plane, dashboard, ClickHouse audit, and Resend email yourself. |

## Development

Contributor setup, `make` targets, and the test suites are documented in
[Development & testing](https://docs.hexgate.ai/internals/development). The short
version:

```bash
make install-dev     # uv sync --extra dev (first time only)
make check           # lint + fmt-check + test (matches CI)
```

## License

MIT — see [LICENSE](LICENSE).

---

If Hexgate looks useful, [give it a ⭐ on GitHub](https://github.com/HexamindOrganisation/hexgate) — it helps more than you'd think. Built by [Hexamind](https://hexgate.ai).
