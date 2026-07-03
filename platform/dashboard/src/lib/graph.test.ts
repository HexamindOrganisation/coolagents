import { describe, expect, it } from "vitest";
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
});
