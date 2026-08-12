# Tool hooks — a pre/post plugin pipeline around guarded tool calls

**Status:** phase 1 (PR1) implemented — LangChain seam only
**Scope:** `hexgate/hooks/**`, `hexgate/adapters/langchain/tools.py`,
`HexgateAgent.enforce_policy` (`hexgate/agents/factory.py`)
**Date:** 2026-08-12

A second extension point next to `PolicyEnforcer.decide`. `decide` answers one
question (allow / deny / approval); hooks are the open surface for everything
else an operator bolts on around a tool call: strip a secret out of args,
rate-limit per user, watch a result before the model sees it. A hook is a plain
callable registered on a `ToolPipeline(pre=[...], post=[...])` and threaded into
each guarded tool via `enforce_policy(..., pipeline=...)`.

## The order is a security invariant, not a preference

`run_guarded` (`hexgate/hooks/runner.py`) runs a fixed sequence:

```
1. pre-hooks   observe / rewrite args / halt
2. decide(name, final_args)      the authorization verdict, unchanged
3. run the tool on final_args
4. post-hooks  observe / halt
```

**Pre-hooks MUST run before `decide`, and `decide` MUST evaluate the exact args
that execute.** A pre-hook that rewrites args and runs *after* `decide` is a
policy bypass: the engine authorizes the old args, the tool runs the new ones. So
arg rewrite happens in step 1 and `decide` re-authorizes its output in step 2.
The property this buys: hooks can only ever narrow. A pre-hook can add a denial
(halt), it can never force an allow, because `decide` still runs on whatever it
produced.

MUST NOT reorder these steps, and MUST NOT add a second decide-free execution
path that skips step 2.

## What a hook may do

| | observe | halt | rewrite args | rewrite result |
|---|---|---|---|---|
| pre  | yes | yes | **yes (v1)** | n/a |
| post | yes | yes | n/a | **no — later phase** |

Arg rewrite is in v1 because tool arguments are always JSON (the model emits them
as JSON, so there is no opaque object on the args side). A pre-hook rewrites via a
clean recursive walk. Result rewrite is deferred because a tool result is an
arbitrary object, and the only safe redaction target is its serialized projection,
which needs a projection rule (walk JSON-ish in place, flag opaque rather than
mutate) that PR1 does not build.

MUST NOT wire `Proceed(result=...)` handling into post-hooks without that
projection rule. The type reserves the shape (`_UNSET` sentinel) and the runner
rejects it in v1 on purpose.

## The halt message has two audiences

A `Halt` renders through the same path a policy denial uses
(`Decision.as_error_payload`), so a blocked call reaches the model as
`{"ok": False, ...}` tool output.

- `Halt.reason` is the **only** field the model sees. It MUST name the rule and
  category, never the offending input. Echoing the input both leaks it and hands
  the model a substring to obfuscate and resend. No arg snapshot is attached, so
  the payload cannot echo the args either.
- `Halt.detail` is operator-only and rides the observer channel, never the model.
- Rendered halts carry `retryable: False` and the terminal phrasing already in
  `Decision.as_error_message`. v1 has no hard `stop_run`; every halt is a
  recoverable tool error the model can rework, so official refusal plugins should
  give an *actionable* reason ("remove the credential") to keep the rework loop
  from thrashing.

## Error tiers

A hook that can halt or rewrite is **fail-closed**: a raise denies the call,
because a crash inside the trust boundary MUST NOT be a silent allow. A pure
side-effect hook opts into `observe_only`, which is **fail-open** (a raise is
swallowed and logged) and whose return value is ignored, so it can neither rewrite
nor halt. Default is fail-closed; loose only when the author says so.

A registered pre-hook is inside the trust boundary (it can rewrite args before
`decide`). A hook that coerces args into policy compliance is possible by design;
the `Modification` record below makes it visible in the audit trail.

## Provenance

A rewrite records a `Modification(plugin, target, summary)`. `summary` MUST be
operator-safe (name the field and a count, not the stripped value). The pipeline
accumulates them per call and reports a `HookEvent` to `ToolPipeline.observer`, a
local-process, fire-and-forget hook isolated like `decision_observer`. PR1
delivers the observer channel only; durable persistence of modifications into the
platform audit (`AuditEvent` / ClickHouse) is a later increment and the
enforcer's own audit is unchanged.

## Placement, and two things deliberately not touched

The pipeline lives in the tool-wrapper layer via one shared `run_guarded`, called
by `GuardedTool` and `install_enforcer_on_tool`. Rationale for two non-obvious
omissions, recorded so they are not "fixed" later:

- **Not on `PolicyEnforcer`.** The enforcer stays pure (`decide → Decision`, no
  execution). The pipeline rides `enforce_policy → GuardedTool.wrap` instead.
- **Not on `PolicyBinding`.** `refresh()` swaps `enforcer.policy` in place
  (`hexgate/security/binding.py`) and never rebuilds tools, so the pipeline held on
  the `GuardedTool` already survives hot reload. Storing it on the binding would be
  dead wiring.

## Deferred (not in this PR)

Result rewrite (post `Proceed(result=...)` + projection rule); a hard `stop_run`
that aborts the run (needs each adapter to propagate the error past its tool node);
the other three adapters onto `run_guarded` (PR2); official plugins and the secret
detector (PR3); egress post-hooks. See `tool-hooks-design.md` for the full plan.

## Verify

```
pytest tests/hooks tests/adapters/langchain
# decide sees rewritten args, halt echoes no input, fail-closed vs observe-open.
```
