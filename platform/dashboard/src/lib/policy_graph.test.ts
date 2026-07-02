import { describe, expect, it } from "vitest";
import { buildPolicyGraph } from "./policy_graph";

/**
 * Focused regressions for buildPolicyGraph. The heavier semantic
 * coverage lives in policy.test.ts; this file only pins the graph-layer
 * decisions (invalid modes render as deny, mixin edges still emit).
 */

describe("buildPolicyGraph — invalid mode entries stay visible (finding #68)", () => {
  it("renders a tool with a mistyped mode as a deny-colored edge, not a missing edge", () => {
    // Capital "Deny" is not a valid Mode. Before the fix, readToolMap
    // dropped it entirely and the tool node had no incoming edge —
    // users concluded the tool was unconstrained. Fix: still emit an
    // edge, coerced to deny with a diagnostic label.
    const graph = buildPolicyGraph(`
version: 1
default_policy: { mode: deny }
roles:
  strict:
    tools:
      dangerous_op: { mode: Deny }
`);
    expect(graph.ok).toBe(true);
    const toolNode = graph.nodes.find((n) => n.id === "tool:dangerous_op");
    expect(toolNode).toBeDefined();
    const edge = graph.edges.find(
      (e) => e.source === "role:strict" && e.target === "tool:dangerous_op",
    );
    expect(edge).toBeDefined();
    expect(edge!.label).toContain("invalid mode");
    // Fail-closed — the stroke color is the deny semantic even though
    // the raw YAML said something the parser couldn't interpret.
    expect(
      (edge!.style as Record<string, unknown> | undefined)?.stroke,
    ).toContain("--semantic-deny");
  });

  it("still renders a valid entry alongside an invalid one under the same role", () => {
    const graph = buildPolicyGraph(`
version: 1
default_policy: { mode: deny }
roles:
  mixed:
    tools:
      good_tool: { mode: allow }
      typo_tool: { mode: Allow }
`);
    const goodEdge = graph.edges.find((e) => e.target === "tool:good_tool");
    const typoEdge = graph.edges.find((e) => e.target === "tool:typo_tool");
    expect(goodEdge!.label).toBe("allow");
    expect(typoEdge!.label).toContain("invalid mode");
  });
});
