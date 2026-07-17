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
  tool-calling loop through the seam. Every probe runs on OpenAI `gpt-4o-mini`
  with `OPENAI_API_KEY` (google-adk reaches OpenAI via its LiteLLM wrapper), so
  the matrix needs a single provider key. Auto-skips when it's unset.

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
make version-compat            # or: uv run pytest -m version_compat tests/version_compat/

# + Tier 2 end-to-end:
OPENAI_API_KEY=sk-... make version-compat
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

## Running the matrix

`scripts/version_matrix.py` drives this suite across a version grid — each
`(framework, version)` cell installed into an isolated `uv` venv under
`build/version-matrix/` (gitignored), results classified per tier.

```bash
# Preview the grid (floor + samples + latest per framework):
make version-matrix ARGS="--dry-run"   # or: python scripts/version_matrix.py --dry-run

# Full grid, Tier 0/1 only:
python scripts/version_matrix.py

# One framework, explicit versions, + Tier 2 e2e:
OPENAI_API_KEY=sk-... python scripts/version_matrix.py \
  --frameworks pydantic --versions pydantic=1.88.0,1.89.1,2.12.0
```

The table (per-cell T0/T1/T2 + supported Tier-1-green range) prints to the
console and writes to `build/version-matrix/results.md`.

## Verdicts & findings

Each cell is classified as:

- **OK** — enforcement (Tier 1) works; e2e (Tier 2) passed or was skipped.
- **BROKEN ⚠** — Tier 1 failed: the wrap stopped attaching. The signal that matters.
- **T1✓ T2✗** — enforcement works but the e2e run failed; investigate (may be model
  flakiness or an unrelated ecosystem-version clash, not a wrap break).
- **UNUSABLE / INCOMPAT** — the framework or probe couldn't load or construct at that
  version (old API, transitive-dep conflict).

Current per-framework supported ranges and open issues are recorded in
`plans/framework-version-compat-testing.md`; the last generated table is
`build/version-matrix/results.md`.
