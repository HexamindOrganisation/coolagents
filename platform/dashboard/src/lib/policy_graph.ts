/**
 * Build a React Flow graph from an inline-roles ``policy.yaml``.
 *
 * Visualization shape (node-edge):
 *
 *     roles (left)              tools (right)
 *     ───────────                ────────────
 *
 *     read_only [mixin]  ─ ─ ┐
 *                            │ inherits
 *     default ◄──────────────┤
 *                            │
 *     support  ──── allow ───┼──> web_search
 *                            │
 *                ──── allow ─┼──> refund_order  (≤50 USD)
 *                            │
 *     billing  ──── allow ───┼──> refund_order  (≤500 USD/EUR)
 *
 * Edges:
 *   * role → tool, color encodes mode (allow / approval_required / deny)
 *   * role → role, dashed, labeled "inherits" (mixin role on the right
 *     of the inheritance arrow)
 *
 * Inheritance is rendered as edges (the "innovative" node-edge view the
 * user picked over a flat matrix). Mixin roles are dimmed via the
 * RoleNode's ``muted`` flag.
 *
 * This module is intentionally a pure builder — no React, no state. The
 * Graph tab in /policies passes the output to <ReactFlow> verbatim.
 */

import yaml from "js-yaml";
import type { Edge, Node } from "@xyflow/react";
import { isMixinSpec, MODE_COLOR, readToolMap, type Mode } from "./policy";

// Re-export Mode so existing consumers of this file (if any) don't break.
export type { Mode } from "./policy";

interface RoleSpec {
  is_mixin?: unknown; // coerced by isMixinSpec()
  inherits?: string[];
  tools?: Record<string, unknown>; // shaped by readToolMap()
  default_policy?: { mode?: unknown };
  constraints?: string[];
}

interface InlinePolicy {
  version?: number;
  roles?: Record<string, RoleSpec>;
}

/**
 * Union of every tool name mentioned under a role's ``tools:`` map,
 * regardless of whether the mode is valid. readToolMap alone silently
 * drops entries with mistyped modes (e.g. capitalized ``Deny``); using
 * only its output as the tool-node source makes those tools disappear
 * from the graph entirely — the user sees no node and assumes the tool
 * is unconstrained. Fix: keep the tool visible; the edge renders with
 * a fail-closed deny color and a diagnostic label.
 */
function rawToolNames(rawTools: unknown): string[] {
  if (!rawTools || typeof rawTools !== "object") return [];
  return Object.keys(rawTools as Record<string, unknown>);
}

/** Extract a raw mode string from an unvalidated tool spec entry. */
function rawModeOf(spec: unknown): unknown {
  return (spec as { mode?: unknown } | undefined)?.mode;
}

const VALID_MODES: readonly Mode[] = ["allow", "deny", "approval_required"];
function isValidMode(m: unknown): m is Mode {
  return (
    typeof m === "string" && (VALID_MODES as readonly string[]).includes(m)
  );
}

/**
 * Extract constraint counts per role×tool. readToolMap() drops the
 * `constraints` field (it only reads mode + file_scope), so we walk
 * the raw spec ourselves to pull constraint counts for the edge
 * label — everything else routes through readToolMap for consistency.
 */
function constraintCount(spec: unknown): number {
  const c = (spec as { constraints?: unknown } | undefined)?.constraints;
  return Array.isArray(c) ? c.length : 0;
}

export interface PolicyGraph {
  nodes: Node[];
  edges: Edge[];
  /** True if the YAML parsed and has at least one role; false → tab should render an empty/invalid placeholder. */
  ok: boolean;
}

/**
 * Parse and lay out the policy graph. Returns ok=false when the YAML is
 * malformed or contains no ``roles:`` section — caller renders a friendly
 * "fix the YAML to see the graph" message.
 */
export function buildPolicyGraph(policyYaml: string): PolicyGraph {
  let parsed: unknown;
  try {
    parsed = yaml.load(policyYaml);
  } catch {
    return { nodes: [], edges: [], ok: false };
  }
  if (!parsed || typeof parsed !== "object") {
    return { nodes: [], edges: [], ok: false };
  }
  const doc = parsed as InlinePolicy;
  const rolesMap = doc.roles;
  if (!rolesMap || typeof rolesMap !== "object") {
    return { nodes: [], edges: [], ok: false };
  }

  const roleNames = Object.keys(rolesMap);
  // Tools = union across all roles' raw tool maps (not filtered) so an
  // entry with a mistyped mode still gets a node + a fail-closed edge.
  // Dropping typos silently made those tools disappear from the graph,
  // and the user assumed the tool was unconstrained. Fail-closed and
  // visible beats invisible-and-permissive.
  const toolMapsByRole: Record<string, ReturnType<typeof readToolMap>> = {};
  const toolSet = new Set<string>();
  for (const role of roleNames) {
    toolMapsByRole[role] = readToolMap(rolesMap[role]?.tools);
    for (const t of rawToolNames(rolesMap[role]?.tools)) toolSet.add(t);
  }
  const toolNames = Array.from(toolSet);

  // Layout constants: two columns, role boxes vertically stacked on the left,
  // tool nodes on the right. Vertical spacing tuned so the columns visually
  // balance for typical policies (≤8 roles, ≤8 tools).
  const COL_ROLES_X = 0;
  const COL_TOOLS_X = 480;
  const ROLE_GAP_Y = 110;
  const TOOL_GAP_Y = 80;
  const ROLE_Y_START = 0;
  const TOOL_Y_START = Math.max(
    0,
    (roleNames.length * ROLE_GAP_Y - toolNames.length * TOOL_GAP_Y) / 2,
  );

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Role nodes — mixin entries rendered with the muted flag so they read
  // as inheritance helpers rather than active personas.
  roleNames.forEach((role, idx) => {
    const spec = rolesMap[role];
    nodes.push({
      id: `role:${role}`,
      type: "role",
      position: { x: COL_ROLES_X, y: ROLE_Y_START + idx * ROLE_GAP_Y },
      data: {
        label: role,
        // Coerced check — accepts is_mixin: true / "true" / 1 uniformly
        // with parsePolicy so both views agree on which roles are mixins.
        muted: isMixinSpec(spec),
      },
    });
  });

  // Tool nodes — mode defaults to 'default' (renders as the muted strip);
  // the tool's mode varies per role, so this represents "the tool exists"
  // not "what mode it's in for any specific role."
  toolNames.forEach((tool, idx) => {
    nodes.push({
      id: `tool:${tool}`,
      type: "tool",
      position: { x: COL_TOOLS_X, y: TOOL_Y_START + idx * TOOL_GAP_Y },
      data: { name: tool, mode: "default" },
    });
  });

  // Inheritance edges — role → parent role, dashed, secondary color.
  for (const role of roleNames) {
    const parents = rolesMap[role]?.inherits ?? [];
    for (const parent of parents) {
      if (!rolesMap[parent]) continue;
      edges.push({
        id: `inh:${role}->${parent}`,
        source: `role:${role}`,
        target: `role:${parent}`,
        type: "smoothstep",
        animated: false,
        style: {
          stroke: "hsl(var(--muted-foreground))",
          strokeDasharray: "4 4",
          strokeWidth: 1.5,
        },
        label: "inherits",
        labelStyle: {
          fontSize: 10,
          fill: "hsl(var(--muted-foreground))",
        },
        labelBgStyle: { fill: "hsl(var(--background))" },
        labelBgPadding: [4, 2],
      });
    }
  }

  // Mode edges — role → tool, color encodes the policy mode. Constraint
  // count surfaces in the label so the user knows the rule has gates
  // without opening the YAML. Invalid-mode entries (e.g. capitalized
  // ``Deny``) render as deny with an "invalid mode" label so the user
  // spots the typo instead of finding a silently-missing edge.
  for (const role of roleNames) {
    const spec = rolesMap[role];
    // Mixins compose into children via `inherits` — no direct terminal
    // edges here (isMixinSpec accepts coerced truthy values, matching
    // parsePolicy's contract).
    if (isMixinSpec(spec)) continue;
    const validatedTools = toolMapsByRole[role] ?? {};
    const rawTools = (spec?.tools ?? {}) as Record<string, unknown>;
    for (const tool of rawToolNames(rolesMap[role]?.tools)) {
      const rawMode = rawModeOf(rawTools[tool]);
      const validEntry = validatedTools[tool];
      const mode: Mode = validEntry ? validEntry.mode : "deny";
      const cnCount = constraintCount(rawTools[tool]);
      const invalid = !isValidMode(rawMode);
      let label: string;
      if (invalid) {
        label = `invalid mode · deny`;
      } else if (cnCount > 0) {
        label = `${mode} · ${cnCount} check${cnCount === 1 ? "" : "s"}`;
      } else {
        label = mode;
      }
      edges.push({
        id: `mode:${role}->${tool}`,
        source: `role:${role}`,
        target: `tool:${tool}`,
        type: "smoothstep",
        animated: !invalid && mode === "allow",
        style: {
          stroke: MODE_COLOR[mode],
          strokeWidth: 2,
          ...(invalid ? { strokeDasharray: "3 3" } : {}),
        },
        label,
        labelStyle: {
          fontSize: 10,
          fill: invalid
            ? "hsl(var(--semantic-deny))"
            : "hsl(var(--foreground))",
        },
        labelBgStyle: { fill: "hsl(var(--background))" },
        labelBgPadding: [4, 2],
      });
    }
  }

  return { nodes, edges, ok: true };
}
