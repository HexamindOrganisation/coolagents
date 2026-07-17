# Framework version-compatibility suite

Determines which released versions of each supported framework hexgate can
wrap with **working policy enforcement**. Full strategy:
`plans/framework-version-compat-testing.md`.

Frameworks: `pydantic_ai`, `openai-agents`, `google-adk`, `langchain`,
`deepagents`.

## What each probe asserts

Every adapter splices `enforcer.decide(...)` in front of a framework's real
tool call by patching a *private* callable on the framework's tool type. That
splice is what breaks across versions — and the dangerous failure is **silent
bypass** (the patch stops attaching, the tool runs unguarded), not an
exception. So the probes assert the **deny path**, not just that a run
completes.

Three checks per framework:

- **Tier 0 — `test_contract`**: the private surfaces the adapter depends on
  still exist (imports, `Agent` is a dataclass / pydantic model, the tool type
  exposes the patched callable). Fast; pinpoints *why* a version broke.
- **Tier 1 — `test_deny_path_*` + `test_allow_decision`**: build a 2-tool
  agent (`get_weather`=allow, `delete_user`=deny), wrap it, invoke the guarded
  tool callable **directly** with denied args, and assert it returns/raises the
  deny marker and the underlying function **never ran** (`_probe.was_executed`).
  Deterministic, no LLM. This is the version-matrix signal.
- **Tier 2 — `test_e2e_*`**: a full model run drives the framework's own
  tool-calling loop through the seam. Auto-skips without a provider key
  (`OPENAI_API_KEY`, or `GOOGLE_API_KEY`/`GEMINI_API_KEY` for google).

## Running

This suite is **opt-in**: every module is marked `version_compat`, and the
default `pytest` run excludes it (`addopts = ... -m "not version_compat"` in
`pytest.ini`). So `make test` / `make coverage` / CI never run it — the
per-commit regression gate for the *pinned* versions is `tests/adapters/`.
Run this one explicitly with `-m version_compat`.

Default is **local + offline**: policy resolves from `probe_policy.yaml` via
`HEXGATE_LOCAL_POLICY` (opa-compiled to WASM), audit is inert
(`HEXGATE_LOCAL_MODE=1`), and the ban gate auto-disables. A red result means
"the framework version broke the wrap," never "the platform 404'd."

```bash
# Tier 0 + Tier 1 only (no keys, no network):
uv run pytest -m version_compat tests/version_compat/

# + Tier 2 end-to-end:
OPENAI_API_KEY=sk-... uv run pytest -m version_compat tests/version_compat/
```

`opa` must be on `PATH` (compiles the local YAML). Confirmed with opa 1.17.

### SaaS confirmation pass

To prove the platform enforcement path (not just local YAML):

```bash
HEXGATE_PROBE_MODE=saas HEXGATE_API_KEY=... \
  uv run pytest -m version_compat tests/version_compat/
```

First register each `version_probe_*` agent (see `AGENT_NAMES` in
`conftest.py`) on the platform with a policy equivalent to `probe_policy.yaml`
(allow `get_weather`, deny `delete_user`) — the wrappers fail-loud on a 404.

## Known results (as of this scaffolding)

Installed: pydantic-ai-slim 1.89.1 · openai-agents 0.15.1 · google-adk 1.32.0
· langchain 1.2.16 / langchain-core 1.3.2 / langgraph 1.1.10 · deepagents 0.6.10.

- pydantic_ai, openai-agents, google-adk, langchain — Tier 0/1 **pass**.
- **deepagents 0.6.10 is incompatible with langchain 1.2.16**: `create_deep_agent`
  fails at import (`cannot import name 'InputAgentState' from
  langchain.agents.middleware.types`). The module skips with that reason. This
  is a real matrix result — the driver (plan step 4) will vary the versions to
  find the compatible langchain range for deepagents.

## Next (plan steps 4–5)

- `scripts/version_matrix.py` — iterate `(framework, version)` cells in isolated
  `uv` venvs, run Tier 0/1 then Tier 2 on greens, emit the compatibility table,
  bisect range boundaries.
- One platform-backed confirmation pass per framework.
