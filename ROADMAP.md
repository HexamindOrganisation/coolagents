# Roadmap

Now / Next / Later for the tool-guards and plugins line of work. Curated and
bounded on purpose ("Now" is the actionable scope, not a strategy dump). Other
tracks can be added as their own sections.

## Now

- **Tool-guard pipeline (PR1).** Pre/post guards around each guarded tool call:
  observe, halt, and pre-guard arg rewrite, on the LangChain seam. Up as PR #118.
  Decisions recorded in `docs/adr/R-GUARD-001..003`.
- **Naming, settled before it ships.** Guards are authored with the
  `@before_tool` / `@after_tool` decorators (dual-form: bare, or called with
  `tool_names=[...]` to scope, default every tool, and `observe=True` for the
  fail-open tier). They register as one flat `guards=[...]` list on the agent,
  split into pre/post internally with order preserved within each. No public
  `Guard` / `PreGuard` / `PostGuard` / `ToolPipeline` types; `Halt`, `Proceed`,
  `ToolCall`, `ToolOutcome`, and `Modification` stay. "guards" is the collective
  arg and the mechanism name; the packaged reusable units are "plugins"
  (`hexgate.plugins`, landing with PR3).

## Next

- **PR2: the other three adapters.** Point OpenAI, Google ADK, and Pydantic AI at
  the shared `run_guarded` so all four frameworks share one guard path. Mostly
  deleting duplicated decide-then-invoke.
- **PR3: official plugins.** `hexgate.plugins`: one secret detector exposed as a
  guard (halt), a redactor (pre rewrite), and a watcher (post observe), plus a
  safe-`reason` builder.

## Later

- **Result rewrite.** Post-guard `Proceed(result=...)` behind a projection rule
  (walk JSON-ish in place, flag opaque objects rather than mutate). `secret_watch`
  graduates to `secret_scrubber`. See `docs/adr/R-GUARD-003`.
- **Tool-local co-location.** Attach a before/after guard directly to a tool
  object so it lives with the tool (a tool-author channel), merged with the
  central `guards=[...]` list at wrap time. Only about locality;
  `@before_tool(tool_names=[...])` already covers tool-scoping from the central
  list. No global auto-registering decorator (a process-wide registry built from
  import side effects is the wrong shape for a security layer).
- **Hard stop.** A `stop_run` that aborts the run for genuinely unfixable
  refusals, once cross-adapter exception propagation is spiked.
- **Egress post-guards** on HTTP responses.
- **PII / email plugins**, as observe or as redactors.
- **Declarative guard bindings** in the policy / platform.
