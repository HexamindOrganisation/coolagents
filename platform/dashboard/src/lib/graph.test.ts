import { describe, expect, it, vi } from "vitest";
import { buildOverviewGraph } from "./graph";
import type { AgentManifestView, AgentRead } from "./api";

/**
 * Focused regressions for the overview-graph builder. Semantic parsing
 * (mergedTools, effectiveMode, inherits) is covered in policy.test.ts;
 * this file only pins the manifest-vs-agent_yaml source resolution that
 * unblocks the Graph tab for code-registered agents.
 */

const FLAT_POLICY = `
version: 1
default_policy: { mode: deny }
tools:
  web_search: { mode: allow }
  fetch: { mode: allow }
`;

function agent(name: string, agentYaml: string): AgentRead {
  return {
    name,
    agent_yaml: agentYaml,
    policy_yaml: FLAT_POLICY,
  } as unknown as AgentRead;
}

function manifestFor(
  name: string,
  tools: string[],
  model: string | null = "gpt-5.4",
): AgentManifestView {
  return {
    name,
    manifest: {
      name,
      description: null,
      framework: "langchain",
      model,
      system_prompt: null,
      tools: tools.map((t) => ({
        name: t,
        description: null,
        input_schema: { properties: {}, required: [] },
      })),
    },
    version: 1,
    content_hash: "hash",
    updated_at: "2026-07-03T00:00:00Z",
  } as unknown as AgentManifestView;
}

describe("buildOverviewGraph — manifest-fed tools unblock code-registered agents", () => {
  it("renders an agent whose agent_yaml is empty when the manifest is provided", () => {
    // Reproduces the reported bug: code-registered agents leave
    // agent_yaml as "". Without the manifest path, buildAgentView
    // returns null → agentViews.length === 0 → the Graph shows
    // "No agents yet." even though /agents and /policies show it fine.
    const graph = buildOverviewGraph(
      [agent("code_bot", "")],
      [manifestFor("code_bot", ["web_search", "fetch"])],
    );

    expect(graph.agentViews).toHaveLength(1);
    expect(graph.agentViews[0].tools).toEqual(["web_search", "fetch"]);
    // Agent node + everyone node + 2 tool nodes = 4.
    const nodeKinds = graph.nodes.map((n) => n.type);
    expect(nodeKinds.filter((t) => t === "agent")).toHaveLength(1);
    expect(nodeKinds.filter((t) => t === "tool")).toHaveLength(2);
  });

  it("falls back to agent_yaml parsing when no manifests are provided", () => {
    // Legacy YAML-edited agents (no registered manifest) still work
    // the way they used to.
    const graph = buildOverviewGraph([
      agent("legacy_bot", "name: legacy_bot\nmodel: gpt-4\ntools:\n  - fetch"),
    ]);

    expect(graph.agentViews).toHaveLength(1);
    expect(graph.agentViews[0].tools).toEqual(["fetch"]);
  });

  it("mixes manifest-fed and yaml-fed agents in the same project", () => {
    // One code-registered (manifest present) + one legacy YAML-edited
    // (no manifest entry). Both must appear on the graph.
    const graph = buildOverviewGraph(
      [
        agent("code_bot", ""),
        agent(
          "legacy_bot",
          "name: legacy_bot\nmodel: gpt-4\ntools:\n  - fetch",
        ),
      ],
      [manifestFor("code_bot", ["web_search"])],
    );

    expect(graph.agentViews).toHaveLength(2);
    const byName = Object.fromEntries(
      graph.agentViews.map((v) => [v.name, v.tools]),
    );
    expect(byName["code_bot"]).toEqual(["web_search"]);
    expect(byName["legacy_bot"]).toEqual(["fetch"]);
  });

  it("skips a code-registered agent whose manifest is not yet available", () => {
    // Timing edge case: agents.data landed before manifests.data. The
    // agent with empty agent_yaml and no matching manifest can't be
    // rendered — drop it rather than crash. Once the manifests query
    // finishes, the useMemo re-runs and the agent appears.
    const graph = buildOverviewGraph([agent("code_bot", "")], []);
    expect(graph.agentViews).toHaveLength(0);
  });

  it("empty manifest tool list is respected (agent shown with no tool edges)", () => {
    // A registered agent with zero tools should render as a node with
    // no outgoing edges, not vanish from the graph.
    const graph = buildOverviewGraph(
      [agent("skeleton", "")],
      [manifestFor("skeleton", [])],
    );
    expect(graph.agentViews).toHaveLength(1);
    expect(graph.agentViews[0].tools).toEqual([]);
    expect(graph.edges.filter((e) => e.source === "agent:skeleton")).toEqual(
      [],
    );
  });

  it("renders an agent whose envelope has manifest=null (registered, no version yet)", () => {
    // Post-review regression: pre-fix `?.manifest ?? null` collapsed
    // "no envelope" and "envelope with null manifest" into the same
    // fallback. The latter is a real state per AgentManifestView docs
    // (agent row exists, no persisted AgentVersion.manifest yet). We
    // now render a bare agent node in that case so the operator sees
    // the agent exists — dropping it silently would reproduce the
    // exact "No agents yet" bug this PR set out to fix.
    const envelope = {
      name: "half_registered",
      manifest: null,
      version: null,
      content_hash: null,
      updated_at: "2026-07-03T00:00:00Z",
    } as unknown as AgentManifestView;

    const graph = buildOverviewGraph(
      [agent("half_registered", "")],
      [envelope],
    );
    expect(graph.agentViews).toHaveLength(1);
    expect(graph.agentViews[0].name).toBe("half_registered");
    expect(graph.agentViews[0].tools).toEqual([]);
  });

  it("warns and keeps the first envelope on duplicate manifest names", () => {
    // Two envelopes for the same agent name would silently overwrite
    // each other under a naive Map.set loop, hiding a real backend
    // bug (join fan-out, stale envelope during rename). Log once and
    // keep the first so devtools surfaces the problem.
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      const first = manifestFor("dupe", ["first_tool"]);
      const second = manifestFor("dupe", ["second_tool"]);
      const graph = buildOverviewGraph([agent("dupe", "")], [first, second]);
      expect(graph.agentViews).toHaveLength(1);
      expect(graph.agentViews[0].tools).toEqual(["first_tool"]);
      expect(warnSpy).toHaveBeenCalledOnce();
      expect(warnSpy.mock.calls[0][0]).toMatch(/duplicate manifest envelope/);
    } finally {
      warnSpy.mockRestore();
    }
  });

  it("skips tool edges when the agent's policy_yaml won't parse", () => {
    // Post-review regression: rendering a parse-failed agent against
    // the fail-closed empty policy caused every tool edge to draw in
    // deny styling, telling the operator their real policy was
    // rejecting everything when the real problem was a YAML parse
    // error. Graph now skips the tool-edge loop for parse-failed
    // agents; the agent node still appears (carrying the
    // policyParseFailed flag) so the operator can spot + fix it in
    // the Policies editor.
    const broken = {
      name: "broken_bot",
      agent_yaml: "",
      policy_yaml: ":::garbage yaml",
    } as unknown as AgentRead;
    const graph = buildOverviewGraph(
      [broken],
      [manifestFor("broken_bot", ["web_search", "fetch"])],
    );

    expect(graph.agentViews).toHaveLength(1);
    expect(graph.agentViews[0].policyParseFailed).toBe(true);
    // Agent node exists, carries the flag for the UI to render a warning.
    const agentNode = graph.nodes.find((n) => n.id === "agent:broken_bot");
    expect(agentNode).toBeDefined();
    expect(
      (agentNode!.data as { policyParseFailed?: boolean }).policyParseFailed,
    ).toBe(true);
    // No tool edges emitted from this agent — misleading deny paint
    // suppressed at the source.
    expect(graph.edges.filter((e) => e.source === "agent:broken_bot")).toEqual(
      [],
    );
  });

  it("excludes parse-failed agents from the tool-node worst-case aggregate", () => {
    // The tool-node's left strip encodes worst-case mode across every
    // agent that references it. If we let a parse-failed agent's
    // fail-closed empty policy contribute, every shared tool would
    // display deny — poisoning the aggregate for well-formed agents
    // that also reference the same tool. Filter the parse-failed ones
    // out of the aggregate.
    const ok = {
      name: "ok_bot",
      agent_yaml: "",
      policy_yaml: FLAT_POLICY,
    } as unknown as AgentRead;
    const broken = {
      name: "broken_bot",
      agent_yaml: "",
      policy_yaml: ":::garbage",
    } as unknown as AgentRead;
    const graph = buildOverviewGraph(
      [ok, broken],
      [
        manifestFor("ok_bot", ["web_search"]),
        manifestFor("broken_bot", ["web_search"]),
      ],
    );

    const toolNode = graph.nodes.find((n) => n.id === "tool:web_search");
    expect(toolNode).toBeDefined();
    // FLAT_POLICY has web_search: allow, so the well-formed agent's
    // vote should win — the parse-failed one's fail-closed deny would
    // overpower it if it weren't filtered.
    expect((toolNode!.data as { mode: string }).mode).toBe("allow");
  });
});
