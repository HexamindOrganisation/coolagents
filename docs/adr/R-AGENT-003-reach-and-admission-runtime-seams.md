# R-AGENT-003: Reach and admission are enforced at per-framework runtime seams

**Status:** Accepted · 2026-08-26 · builds on R-AGENT-002
**Applies to:** `hexgate/security/agent_gate.py`, `hexgate/security/naming.py`, `hexgate/adapters/openai/runner.py`, `hexgate/adapters/google/runner.py`, `hexgate/adapters/pydantic_ai/wrapper.py`, `hexgate/adapters/langchain/wrapper.py`, `hexgate/agents/factory.py`

## Decision

Agent-level admission (`agent.run`) and reach (`agent.handoff:<t>` / `agent.tool:<t>`) are enforced at framework-specific runtime seams by two gates that reuse `PolicyEnforcer.decide`, mirroring the egress `Gate`. R-AGENT-002 defined the policy model; this defines where and how it runs.

- **One canonical name.** A target's name at a seam derives identically to an agent's own name via `canonical_agent_name` (trim, blank/None → `"default"`, no case folding). Own-name and target-name must agree or a reach key would not match the name its target registers with. This is the one derivation; the two prior per-adapter spellings are gone.
- **Reach is governed by the source agent's policy, at the seam, before control transfers.** `ReachGate.check_reach(target, via)` decides the lowered key and raises `ReachNotAllowedError` on a deny.
  - **OpenAI:** the SDK `on_handoff` hook (awaited before the transfer completes, so raising vetoes it) → `via="handoff"`.
  - **Google ADK:** a `BasePlugin.before_tool_callback` intercepting the two shapes ADK expresses as tool calls: `transfer_to_agent` (`via="handoff"`) and `AgentTool` (`via="tool"`).
  - Only reach from a **Hexgate-governed source** (the resolved top-level agent) is gated; a transfer from an un-governed sub-agent is left alone (sub-agent governance is a later slice).
- **Admission is enforced at run entry for the top-level agent**, inside the context scope so the caller's role is visible, on the OpenAI and Google runners. A non-admitted caller is refused before the run starts.
- **Handoff depth is a per-run runaway cap, independent of reach policy.** A handoff transfers control forward, so the count of handoffs within one run is the chain depth; past `max_handoff_depth` the seam raises `HandoffDepthExceededError`. OpenAI counts on the per-run hook; Google counts per `invocation_id` on the shared plugin and clears it in `after_run_callback`.
- **Where the framework hides the target, warn — never silently pass.** pydantic_ai (delegation inside a tool body), the native single-graph agent (no handoff seam), and agent-as-tool on OpenAI expose no target handle, so a declared block is surfaced by `warn_if_admission_unenforced` / `warn_if_reach_unenforced` at wrap time.

## Why

The two gates share `_PolicyGate` (enforcer + approval fold + fail-closed), so admission and reach behave identically and are defined once. Enforcing at the framework seam (not a wrapper around the whole run) is what lets reach fire at the exact moment control would transfer, so a denied handoff never starts the target. Governing reach by the **source** policy matches the model: the `agents` block on A says who A may reach; B's own admission is a separate direction (its run entry).

Counting handoffs as depth is exact for these SDKs because a handoff is a forward transfer with no return, so a run is a chain and the handoff count is its length. The cap is deliberately policy-independent: it stops a runaway even when every hop is allowed.

Warn-and-defer keeps closed-world honest across frameworks: enforcement lands only where a target handle exists, and everywhere else the gap is loud (one log per framework/agent) rather than a silent no-op, so an operator is never misled into thinking a declared block is enforced.

## Consequences

- Reach and admission are enforced end-to-end on OpenAI (handoff) and Google (handoff + agent-as-tool); the interim `warn_if_admission_unenforced` is gone from those adapters.
- A denied reach or admission fails closed by raising, aborting the run rather than degrading to an ungoverned continuation.
- `HexgateRunner(max_handoff_depth=N)` is opt-in on both adapters (None = no cap).

## Deferred (follow-ups, warned in the interim)

- **Per-sub-agent / post-handoff admission** (B re-checking admission at its run entry): needs resolving sub-agent policies and handling unregistered sub-agents, so it is out of this slice. Reach from the governed source is the boundary control today.
- **Agent-as-tool reach on OpenAI** (`Agent.as_tool`): no metadata links the produced function tool back to a target agent name at the seam.
- **pydantic_ai and native reach**: no runtime target handle.
- **Manifest drift lint** (reach key vs declared sub-agents/handoffs): needs `AgentManifest` to carry target declarations, a cross-package change.

## Verify

```
pytest tests/security/test_reach_gate.py tests/security/test_naming.py \
       tests/adapters/openai/test_runner_reach_admission.py \
       tests/adapters/google/test_runner.py -q
# reach denies an unlisted/deny target and vetoes the transfer; admission refuses a
# non-admitted caller at run entry; the depth cap raises past max_handoff_depth.
```
