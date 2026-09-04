/**
 * Pure tests for the module-tree builder + lint line anchoring. These back
 * the left pane (rows rendered as the SDK's on-disk layout) and the inline
 * gutter markers, so they're worth pinning without a DOM.
 */

import { describe, expect, it } from "vitest";

import type { PolicyLint, PolicyModuleRead } from "./api";
import { buildModuleTree, lintToLine, reparent } from "./module_tree";

function mod(tier: PolicyModuleRead["tier"], path: string): PolicyModuleRead {
  return {
    tier,
    path,
    content: "",
    content_hash: "h",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

describe("buildModuleTree", () => {
  it("always returns the two tier roots, even when empty", () => {
    const [boundaries, capabilities] = buildModuleTree([]);
    expect(boundaries.name).toBe("boundaries");
    expect(boundaries.tier).toBe("boundary");
    expect(boundaries.children).toEqual([]);
    expect(capabilities.name).toBe("capabilities");
    expect(capabilities.children).toEqual([]);
  });

  it("nests a slashed capability path into folders", () => {
    const [, capabilities] = buildModuleTree([
      mod("capability", "team_a/payments"),
    ]);
    expect(capabilities.children).toHaveLength(1);
    const folder = capabilities.children[0];
    expect(folder.type).toBe("folder");
    if (folder.type !== "folder") throw new Error("expected folder");
    expect(folder.name).toBe("team_a");
    expect(folder.prefix).toBe("team_a");
    const leaf = folder.children[0];
    expect(leaf).toMatchObject({
      type: "file",
      name: "payments",
      path: "team_a/payments",
    });
  });

  it("sorts folders before files, each group alphabetically", () => {
    const [, capabilities] = buildModuleTree([
      mod("capability", "zed"),
      mod("capability", "team_b/x"),
      mod("capability", "alpha"),
      mod("capability", "team_a/y"),
    ]);
    const names = capabilities.children.map((n) => n.name);
    expect(names).toEqual(["team_a", "team_b", "alpha", "zed"]);
  });

  it("injects a UI-only empty folder even with no modules", () => {
    const [, capabilities] = buildModuleTree(
      [],
      [{ tier: "capability", prefix: "team_a" }],
    );
    expect(capabilities.children).toHaveLength(1);
    const folder = capabilities.children[0];
    expect(folder).toMatchObject({
      type: "folder",
      name: "team_a",
      prefix: "team_a",
    });
    if (folder.type === "folder") expect(folder.children).toEqual([]);
  });

  it("routes modules to their own tier root", () => {
    const [boundaries, capabilities] = buildModuleTree([
      mod("boundary", "org_core"),
      mod("capability", "read_only"),
    ]);
    expect(boundaries.children.map((n) => n.name)).toEqual(["org_core"]);
    expect(capabilities.children.map((n) => n.name)).toEqual(["read_only"]);
  });
});

describe("reparent (drag-to-move target path)", () => {
  it("reparents a top-level module under a folder, keeping the basename", () => {
    expect(reparent("team_a", "payments")).toBe("team_a/payments");
  });

  it("keeps the basename when moving between folders", () => {
    expect(reparent("team_b", "team_a/payments")).toBe("team_b/payments");
  });

  it("moves back to the top level at a tier root (empty prefix)", () => {
    expect(reparent("", "team_a/payments")).toBe("payments");
  });
});

describe("lintToLine", () => {
  const content =
    "default_policy: { mode: allow }\ntools:\n  refund_order: { mode: allow }\n";

  function lint(tool: string | null): PolicyLint {
    return {
      code: "dead-grant",
      severity: "warning",
      message: "x",
      source: "cap",
      tier: "capability",
      tool,
      role: null,
    };
  }

  it("anchors a tool-scoped lint to the tool's line (1-based)", () => {
    expect(lintToLine(content, lint("refund_order"))).toBe(3);
  });

  it("returns null for a lint with no tool", () => {
    expect(lintToLine(content, lint(null))).toBeNull();
  });

  it("returns null when the tool isn't in the buffer", () => {
    expect(lintToLine(content, lint("delete_database"))).toBeNull();
  });

  it("skips a same-named top-level key and anchors to the nested tool", () => {
    const c = "refund_order: junk\ntools:\n  refund_order: { mode: allow }\n";
    expect(lintToLine(c, lint("refund_order"))).toBe(3);
  });
});
