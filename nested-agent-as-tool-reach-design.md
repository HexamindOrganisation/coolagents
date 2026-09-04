# Nested agent-as-tool reach — design & implementation plan

**Status:** proposal · **Scope:** OpenAI Agents adapter (Google ADK already covers this at its `before_tool_callback` seam) · **Depends on:** #142 (ReachGate, `agent.tool:`/`agent.handoff:` keys)

## 1. Problem

Reach isn't a flat "top agent → sub-agent" relation. An agent-as-tool can itself contain agent-as-tools, and those can contain handoffs, recursively:

```
orchestrator (A)
├─ tool: web_search              # ordinary tool
├─ tool: billing_bot  = B.as_tool()
│         └─ B.tools:
│            ├─ tool: ledger_lookup
│            └─ tool: refund_agent = C.as_tool()   # A→B→C, two reach hops deep
└─ handoff: escalation_agent (D)
             └─ D.handoffs: [ ... ]                # keeps going
```

So the agents form a **directed graph**: nodes are agents, edges are either **agent-as-tool** (`via: tool`, control stays with the caller) or **handoff** (`via: handoff`, control transfers). Each edge is governed by the **source** agent's policy on the synthetic key `agent.tool:<target>` / `agent.handoff:<target>`.

Two things make this non-trivial:

1. **Reach must be checked at every edge, not just the first.** Today `wrap_openai_agent` wraps only the *top* agent's `tools` (`hexgate/adapters/openai/wrapper.py:48-51`). When `billing_bot` runs, `Agent.as_tool()` drives the **original, unwrapped** `B` through the SDK's own `Runner.run` (the nested run closes over `self` in `_run_agent_impl`, `agents/agent.py:563`). So the `B→C` edge is never seen — deeper reach is invisible.
2. **The graph can loop.** `A.as_tool()` inside `B`, and `B.as_tool()` inside `A`. A naïve recursive wrap would recurse forever. We need cycle detection, and a decision on what a cycle *means* for enforcement.

The user-visible symptom: you can write `agents: { refund_agent: { via: [tool], mode: deny } }` on `B`'s policy, and nothing enforces it, because `B` never runs through Hexgate when it's invoked as a tool.

## 2. What we can rely on (verified against the installed SDK)

- **Agent-as-tools are self-identifying.** `Agent.as_tool()` stamps the returned `FunctionTool` (`agents/agent.py:891-898`): `_tool_origin = ToolOrigin(type=AGENT_AS_TOOL, agent_name=<target>, agent_tool_name=<tool name>)`, `_is_agent_tool = True`, `_agent_instance = <the target Agent object>`. Public accessor: `get_function_tool_origin(tool)` (`agents/tool.py:525`) → `ToolOrigin` with `.type` and `.agent_name`.
- **Handoffs are a first-class list.** `Agent.handoffs: list[Agent | Handoff]` (`agents/agent.py:258`).
- **Agents are cloneable without mutation.** `Agent.clone()` / `dataclasses.replace` shallow-copy `tools`/`handoffs` (`agents/agent.py:461`); our wrapper already returns clones, never mutates the caller's agent.
- **Our tool gate is name-keyed today.** `wrap_tool` decides `run_guarded_async(tool.name, …)` on the enforcer it closed over (`hexgate/adapters/openai/tools.py:61,101-104`).

## 3. Design

### 3.1 The agent graph

```
node   = an Agent (identified by id(); labelled by canonical_agent_name)
edge   = (source_agent, target_agent, via)   via ∈ {tool, handoff}
  tool     edge: a FunctionTool in source.tools with get_function_tool_origin().type == AGENT_AS_TOOL
  handoff  edge: an entry in source.handoffs
governance: edge (S, T, via) is decided by S's policy on agent_target_key(via, canonical_agent_name(T))
```

### 3.2 Split into two capabilities (scope discipline)

| capability | what it is | needs |
|---|---|---|
| **R** reach-edge enforcement | at every edge, refuse S→T if S's policy denies `agent.<via>:T` | discover edges + gate them under the source's key |
| **G** nested governance | when T runs (nested), T's own tools are gated and T's admission fires | drive T through Hexgate instead of the SDK's raw nested run |

R is the thing the matrix flags as a red cell; G is the deeper win. They share the same traversal but land in different phases (§5).

### 3.3 Core algorithm — bottom-up recursive rewrap, memoized

We rebuild the agent graph bottom-up: each agent is cloned with (a) its ordinary tools gated by its own enforcer, (b) each agent-as-tool edge replaced by a gated edge to the **wrapped** child, (c) each handoff pointing at the wrapped child. Memoize by `id()` so a shared sub-agent (DAG) is wrapped once and cycles terminate.

```python
def wrap_agent_graph(agent, *, resolve_binding, visiting, done):
    key = id(agent)
    if key in done:            # already fully wrapped (DAG sharing)
        return done[key]
    if key in visiting:        # cycle: A→…→A — don't recurse again
        return visiting[key]   # a placeholder clone; edge is still gated below

    binding = resolve_binding(agent)          # agent's OWN resolved policy/enforcer
    placeholder = shallow_clone(agent)        # so a cycle can reference us
    visiting[key] = placeholder

    new_tools = []
    for tool in agent.tools:
        origin = get_function_tool_origin(tool)        # capability-guarded (§4)
        if origin and origin.type is AGENT_AS_TOOL:
            child = wrap_agent_graph(tool._agent_instance, ...)   # recurse
            new_tools.append(gate_reach_edge(tool, source=binding, child=child, via="tool"))
        else:
            new_tools.append(wrap_tool(tool, binding.enforcer, ...))   # ordinary gate

    new_handoffs = [wrap_agent_graph(h, ...) if is_agent(h) else h
                    for h in agent.handoffs]

    wrapped = dataclasses.replace(agent, tools=new_tools, handoffs=new_handoffs)
    populate(placeholder, wrapped)   # fill the placeholder so cyclic refs resolve
    done[key] = wrapped
    visiting.pop(key)
    return wrapped
```

- **`resolve_binding(agent)`** resolves that agent's platform policy and builds an enforcer, exactly like `HexgateRunner._binding_for` — memoized by canonical name so shared nodes resolve once, and **fail-loud** on an unregistered sub-agent (same contract as today).
- **`gate_reach_edge`** is the crux; see §3.4.
- **Cycle semantics:** on a back-edge we still gate the reach at that edge (the check is per-source, computed from the source's binding we already have), but we do **not** re-enter the target — it is (or will be) wrapped via its own `visiting`/`done` entry. So `A→B→A` gates all three edges once and terminates.

### 3.4 The rebuild problem — a pick-2-of-3, rooted in `as_tool` being a one-way compile

To enforce the `B→C` edge, `B`'s nested run must use **wrapped-B** (whose C-edge carries the check), not the original `B`. But `Agent.as_tool()` is a **one-way compile**: its ~16 options (`custom_output_extractor`, `max_turns` `agent.py:590`, `run_config` `:591`, `on_stream`, `hooks`, `session`, `input_builder`, structured `parameters`, …) are baked into the returned tool's `on_invoke_tool` closure and are **not** readable back off the `FunctionTool` (its only real fields are `name`, `description`, `params_json_schema`, `on_invoke_tool`, `is_enabled`, guardrails, `needs_approval`, `timeout_*`, and the `_tool_origin`/`_agent_instance`/`_is_agent_tool` markers — `tool.py:287-388`). That single fact forces a **pick-2-of-3** for any pre-built tree:

1. **enforce deep edges** — the nested run uses the *wrapped* child
2. **preserve all `as_tool` options**
3. **don't mutate the caller's agents**

| approach | deep | options | no-mutate | notes |
|---|---|---|---|---|
| **(A) reconstruct** `child'.as_tool(name, description, …readable…)` + wrap `on_invoke_tool` | ✓ | ✗ | ✓ | unreadable options revert to defaults — silent behaviour change (e.g. a `max_turns=3` cap disappears) |
| **(B) clone-and-swap** `_agent_instance` | ✓ | ✗ | ✓ | **rejected** — `_agent_instance` is only metadata; the run uses the closure's `self`, so behaviour and metadata diverge |
| **mutate child's tools in place** | ✓ | ✓ | ✗ | reuses the original closure (options intact) but violates our no-mutation invariant |
| **(C) wrap `on_invoke_tool`, then call the *original* closure** | ✗ | ✓ | ✓ | lossless, but the original closure still runs the *unwrapped* child, so only the **top** edge is gated — not `B→C` |
| **`hexgate_as_tool(child, …)` constructor** | ✓ | ✓ | ✓ | all three — but the user must build the tree with our helper; not automatic for a tree already built with `.as_tool()` |

The key correction to an earlier draft of this doc: **(C) is not a free lunch.** It is lossless *only when it calls the original closure*, which means it cannot swap in the wrapped child and therefore cannot reach deep. To reach deep, (C) must re-drive the child itself and then hits the same unreadable-options wall as (A). There is no automatic approach that gets all three for a pre-built tree — that is a direct consequence of the one-way compile.

**Recommendation:**
- **Phase 1 (R, top edge, lossless):** wrap `on_invoke_tool` and call the original closure — gate the *top* reach edge under `agent.tool:<target>` with zero option loss. This already beats today (name-gating → real reach key) for the common single-level case.
- **Deep edges + nested governance (G):** offer **`hexgate_as_tool(child, …)`** as the *supported, lossless* path (the user passes options to us, so nothing is lost, and we own the nested run → deep reach + nested admission + nested handoffs all fall out). For trees already built with plain `.as_tool()`, offer **(A)** as an *opt-in, documented-lossy* auto-rewrap that detects exotic options and falls back to top-edge-only + a warning rather than silently dropping them.

In short: **the moment you need to govern *inside* a nested agent, you need to influence how its run is built — which means owning the `as_tool` construction.** Automatic recursion over a foreign tree can only ever be lossy or shallow.

### 3.5 Semantics decisions

- **Whose policy at each edge:** the **source** agent's. A shared child `T` reached by both `A` and `X` is *wrapped once* (its own tools use `T`'s policy), but the **edge check is computed per parent** — `A`'s binding for `A→T`, `X`'s binding for `X→T`. So memoize the wrapped *node*, not the edge.
- **Unregistered sub-agent:** fail-loud at wrap time, matching `_binding_for` (`register first`), so a typo in a nested agent name isn't a silent open door.
- **No mutation:** the caller's agents are never mutated; the whole graph is rebuilt from clones (matches `wrapper.py`'s existing invariant).
- **`via` correctness:** as-tool edges are `via: tool` (no control transfer, no depth increment); handoff edges are `via: handoff` (counts toward the runtime handoff-depth cap).

### 3.6 Two different "depths"

- **Structural nesting depth** — how deep the *build-time* graph goes. Bounded by the memoized traversal (finite graph); add a defensive cap + clear error to guard against pathological inputs.
- **Runtime handoff-chain depth** — already enforced via `max_handoff_depth` at the `on_handoff` seam (#142). Unchanged; as-tool nesting does **not** feed it (no control transfer).

## 4. SDK-capability guarding

`_is_agent_tool` / `_agent_instance` are semi-private and `get_function_tool_origin` lives in `agents.tool`; a different SDK version may lack them. Detect once:

```python
try:
    from agents.tool import get_function_tool_origin, ToolOriginType
    _CAN_DETECT_AGENT_TOOLS = True
except ImportError:
    _CAN_DETECT_AGENT_TOOLS = False
```

When detection is unavailable, fall back to **today's** behaviour: gate agent-as-tools by name and emit `warn_if_tool_reach_unenforced`. When it *is* available, enforce the reach key and drop the warning.

## 5. Implementation plan (phased)

### Phase 1 — top-edge reach enforcement, lossless (capability **R**, single level)
The 80% case (one level of `as_tool`) with zero option loss and no mutation.
- `hexgate/adapters/openai/tools.py`: in `wrap_tool`, detect agent-as-tools (`get_function_tool_origin`, capability-guarded) and gate them under `agent_target_key("tool", origin.agent_name)` — the reach key — instead of the raw tool name, while **calling the original `on_invoke_tool` unchanged** (options preserved). Ordinary tools unchanged.
- `hexgate/adapters/openai/runner.py`: emit `warn_if_tool_reach_unenforced` only when detection is unavailable.
- Tests: top `A→B` as-tool denied by `agent.tool:B`; `via`/constraints honoured; SDK-without-markers falls back to name-gating without crashing; a tool with exotic `as_tool` options still runs identically (we never rebuilt it).

### Phase 2 — deep + nested governance via `hexgate_as_tool` (capability **G**, lossless path)
The supported way to govern *inside* nested agents — the user opts in at construction, so nothing is lost.
- `hexgate/adapters/openai/as_tool.py` (new): `hexgate_as_tool(child, *, source_enforcer, **as_tool_kwargs)` that builds the `FunctionTool` itself: reach-check `source → agent.tool:child`, then drive a **Hexgate-wrapped** child through a nested run (its admission + `run_scope` + gated tools), forwarding every `as_tool` option the user gave us. Because we own construction, this recurses cleanly (the child's own `hexgate_as_tool` edges gate `B→C`), with memoized cycle/DAG handling and a structural-depth cap.
- Docs: position `hexgate_as_tool` as the way to get nested reach + admission on OpenAI.
- Tests: `A→B→C` deny at depth 2; nested admission refuses a caller not admitted to `B`; `B`'s own tools gated during the nested run; cycle `A→B→A` terminates; per-parent edge checks for a shared child.

### Phase 2b (optional) — opt-in lossy auto-rewrap of foreign trees
For trees already built with plain `.as_tool()`, an explicit opt-in (`HexgateRunner(deep_reach=True)`) that recursively rebuilds via approach **(A)**, detecting exotic `as_tool` options and falling back to top-edge-only + a warning for those tools rather than silently dropping them. Clearly documented as best-effort, since the one-way compile makes it lossy by nature.

### Phase 3 — parity + docs
- Confirm handoff-graph parity (nested handoffs now enforced via Phase 2) and the structural-depth cap.
- Correct the now-inaccurate claims: `docs/concepts/agent-level-enforcement.mdx` (as-tool-reach cell for OpenAI), the `_HexgateReachHooks` docstring (`runner.py:105`), and `docs/adapters/openai.mdx`. Update the framework matrix so OpenAI reads **enforced** for agent-as-tool reach.

## 6. Risks & open questions

- **SDK drift** on the private markers → mitigated by §4 capability detection + fallback.
- **`as_tool` option loss** under approach (A) → detect exotic options and fall back per-tool; fully resolved by (C) in Phase 2.
- **Context propagation** across the nested-run task in (C) — verify the caller's `HexgateContext` scope reaches the nested run (asyncio copies contextvars into new tasks, so the role should propagate; add a regression test that asserts it).
- **Per-node policy resolution cost** — one platform resolve per distinct sub-agent; memoized by name, and the per-handoff `ReachGate` allocation is already short-circuited on `declares_reach()` (#142 review fix).
- **Where does Google stand?** Google already gates both `transfer_to_agent` and `AgentTool` at `before_tool_callback`, but only for the *governed root* — the same "nested source isn't gated" gap exists there. Phase 2's approach generalizes; track a Google follow-up so the two adapters stay in step.
