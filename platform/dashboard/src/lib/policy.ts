import yaml from "js-yaml";
import type { AgentRead } from "./api";

export type Mode = "allow" | "deny" | "approval_required";

export interface ToolPolicy {
  mode: Mode;
  file_scope?: {
    allowed_paths?: string[];
  };
}

export interface RolePolicy {
  /** Tools this role gates, AFTER inheritance resolution. Own entries
   *  override any inherited entry with the same tool name. */
  tools: Record<string, ToolPolicy>;
  /** Per-role default when a tool isn't listed. Falls back to the
   *  global default_policy when absent. Inherited from the closest
   *  ancestor that declares one. */
  default_policy?: { mode: Mode };
}

export interface ParsedPolicy {
  version: number;
  default_policy: { mode: Mode };
  /** Tools declared at the TOP level of policy.yaml (flat shape). Empty
   *  on inline-roles YAMLs. NOT augmented by role decisions — the user's
   *  edit at this level is authoritative. See `mergedTools` for the
   *  worst-case union across roles. */
  tools: Record<string, ToolPolicy>;
  /** Concrete roles present in the yaml, AFTER inheritance resolution.
   *  Each entry carries the effective tool map (own tools merged over
   *  ancestors) plus the resolved default_policy. Mixins compose in via
   *  `inherits:` and are not first-class entries here. A concrete role
   *  with no `tools:` map is still listed with `tools: {}` so this map
   *  agrees with parseRolesFromPolicy on which roles the picker offers. */
  roles: Record<string, RolePolicy>;
}

export interface ParsedAgent {
  name: string;
  model: string;
  tools: string[];
}

export interface AgentView {
  name: string;
  model: string;
  /** Tools the agent can invoke — equals agent.yaml's `tools:` list,
   *  in declared order. Role-only policy entries do NOT create display
   *  tools here; the runtime can't invoke what agent.yaml didn't
   *  declare. */
  tools: string[];
  policy: ParsedPolicy;
  /** Tools that appear in agent.yaml but have no policy entry (neither
   *  at flat top level nor in any role) → default_policy applies. */
  missingInPolicy: string[];
}

function isMode(x: unknown): x is Mode {
  return x === "allow" || x === "deny" || x === "approval_required";
}

/**
 * Return true for role specs that should be treated as MIXINS —
 * composed INTO concrete roles via `inherits:` at compile time, never
 * selectable on their own.
 *
 * Accepts the strict-true bool AND coerced truthy values (`"true"`,
 * `1`) so a hand-written `is_mixin: "true"` doesn't sneak through as
 * a "concrete role" and get double-counted in the merged view.
 * Exported so parsePolicy + parseRolesFromPolicy + any future consumer
 * agree on which roles are concrete.
 */
export function isMixinSpec(spec: unknown): boolean {
  if (!spec || typeof spec !== "object") return false;
  const raw = (spec as { is_mixin?: unknown }).is_mixin;
  if (raw === true) return true;
  if (raw === "true" || raw === "yes" || raw === "on" || raw === 1) return true;
  return false;
}

/**
 * Priority ordering when the graph needs a single mode for a tool
 * called from multiple roles: deny > approval > allow. Exported so
 * graph.ts + policy_graph.ts share one source of truth — a future
 * `redacted` mode landing between deny and approval only has to be
 * added here.
 */
export const MODE_STRENGTH: Record<Mode, number> = {
  deny: 3,
  approval_required: 2,
  allow: 1,
};

/** Return the strongest mode from a list, or ``null`` if empty. */
export function worstMode(modes: readonly Mode[]): Mode | null {
  if (modes.length === 0) return null;
  return modes.reduce((worst, m) =>
    MODE_STRENGTH[m] > MODE_STRENGTH[worst] ? m : worst,
  );
}

/**
 * Read a `{tool_name: {mode, file_scope?}}` map from an arbitrary
 * unknown-typed value. Filters entries whose mode isn't one of the
 * three canonical strings (fail-closed against typos). Exported so
 * policy_graph.ts and any future parser share the same isMode gate.
 */
export function readToolMap(raw: unknown): Record<string, ToolPolicy> {
  if (!raw || typeof raw !== "object") return {};
  const out: Record<string, ToolPolicy> = {};
  for (const [toolName, entry] of Object.entries(
    raw as Record<string, unknown>,
  )) {
    const e = entry as { mode?: unknown; file_scope?: unknown };
    if (!isMode(e?.mode)) continue;
    out[toolName] = {
      mode: e.mode,
      file_scope: e.file_scope as ToolPolicy["file_scope"],
    };
  }
  return out;
}

export function parseAgent(
  agentYaml: string,
  policyYaml: string,
): ParsedAgent | null {
  try {
    const agent = yaml.load(agentYaml) as Partial<ParsedAgent> | null;
    if (!agent || typeof agent !== "object") return null;
    return {
      name: String(agent.name ?? ""),
      model: String(agent.model ?? ""),
      tools: Array.isArray(agent.tools) ? agent.tools.map(String) : [],
    };
  } catch {
    return null;
  }
  void policyYaml;
}

/** Extract a role's inherits list, filtering non-string entries. */
function readInherits(spec: unknown): string[] {
  const raw = (spec as { inherits?: unknown } | undefined)?.inherits;
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === "string");
}

/**
 * Resolve a role's inheritance chain, merging ancestor tools into the
 * role's own map. Own tools override inherited tools; sibling ancestors
 * merge left-to-right (later ancestor overrides earlier on a name
 * collision). Cycle-safe via the ``stack`` guard — a re-entered role
 * short-circuits to an empty map, so cyclic inherits definitions parse
 * without hanging or throwing.
 *
 * Both mixins and concrete roles participate as ancestors; the mixin
 * filter only applies to which roles are returned to the caller (via
 * ``parsePolicy.roles``), not to which entries contribute during
 * resolution.
 */
function resolveInheritance(
  specs: Record<
    string,
    {
      tools: Record<string, ToolPolicy>;
      inherits: string[];
      defaultMode?: Mode;
    }
  >,
): Record<string, RolePolicy> {
  const memo: Record<string, RolePolicy> = {};
  const resolve = (name: string, stack: Set<string>): RolePolicy => {
    if (memo[name]) return memo[name];
    if (stack.has(name)) return { tools: {} };
    const spec = specs[name];
    if (!spec) return { tools: {} };
    stack.add(name);
    const tools: Record<string, ToolPolicy> = {};
    let defaultMode: Mode | undefined;
    // Walk ancestors first so own entries override inherited ones.
    for (const parent of spec.inherits) {
      const resolved = resolve(parent, stack);
      Object.assign(tools, resolved.tools);
      if (resolved.default_policy) defaultMode = resolved.default_policy.mode;
    }
    // Own tools + own default_policy override anything inherited.
    Object.assign(tools, spec.tools);
    if (spec.defaultMode) defaultMode = spec.defaultMode;
    stack.delete(name);
    memo[name] = {
      tools,
      ...(defaultMode ? { default_policy: { mode: defaultMode } } : {}),
    };
    return memo[name];
  };
  for (const name of Object.keys(specs)) resolve(name, new Set());
  return memo;
}

export function parsePolicy(policyYaml: string): ParsedPolicy | null {
  try {
    // `yaml.load` returns `unknown`; the shape checks below narrow it
    // before we dereference. Using `unknown` over `any` so a missed
    // check is a compile error rather than a silent dereference.
    const raw = yaml.load(policyYaml) as
      | Record<string, unknown>
      | null
      | undefined;
    if (!raw || typeof raw !== "object") return null;
    const defaultPolicy = raw.default_policy as { mode?: unknown } | undefined;
    const defaultMode = isMode(defaultPolicy?.mode)
      ? defaultPolicy.mode
      : "deny";

    // Two shapes coexist: (a) flat, with tools at top level; (b)
    // inline-roles, with concrete roles under `roles.<name>.tools`.
    // Both parsed — flat block stays as authored (never merged with
    // role decisions), roles carry the effective per-role view AFTER
    // inheritance resolution. Downstream picks: ``tools`` (flat) vs
    // ``roles[name]`` (fully-resolved role) vs ``mergedTools(policy)``
    // (worst-case across the whole policy).
    const flatTools = readToolMap(raw.tools);
    const rolesRaw = raw.roles;
    const roles: Record<string, RolePolicy> = {};
    if (rolesRaw && typeof rolesRaw === "object" && !Array.isArray(rolesRaw)) {
      // Two passes: (1) collect ALL role specs including mixins so they
      // can serve as inheritance parents; (2) resolve the graph; (3)
      // publish only concrete roles to the caller. Mixins participate
      // as ancestors — dropping them at step 1 was the "web_search
      // never appears" bug the review flagged.
      const rawSpecs: Record<
        string,
        {
          tools: Record<string, ToolPolicy>;
          inherits: string[];
          defaultMode?: Mode;
        }
      > = {};
      for (const [roleName, spec] of Object.entries(
        rolesRaw as Record<string, unknown>,
      )) {
        if (!spec || typeof spec !== "object") continue;
        const s = spec as { tools?: unknown; default_policy?: unknown };
        const roleDefault = s.default_policy as { mode?: unknown } | undefined;
        rawSpecs[roleName] = {
          tools: readToolMap(s.tools),
          inherits: readInherits(spec),
          ...(isMode(roleDefault?.mode)
            ? { defaultMode: roleDefault.mode }
            : {}),
        };
      }
      const resolved = resolveInheritance(rawSpecs);
      // Publish only concrete roles — mixins compose INTO them via
      // inherits and aren't selectable on their own.
      for (const [roleName, spec] of Object.entries(
        rolesRaw as Record<string, unknown>,
      )) {
        if (!spec || typeof spec !== "object") continue;
        if (isMixinSpec(spec)) continue;
        roles[roleName] = resolved[roleName] ?? { tools: {} };
      }
    }

    return {
      version: Number(raw.version ?? 1),
      default_policy: { mode: defaultMode },
      tools: flatTools,
      roles,
    };
  } catch {
    return null;
  }
}

/**
 * Worst-case merged view of tool decisions across every concrete role
 * PLUS the flat top-level `tools:` block. Used by the overview graph
 * when it needs one edge color per tool without picking a role first.
 *
 * Semantics: strongest mode wins across the whole policy (`deny` >
 * `approval_required` > `allow`). Flat top-level entries participate
 * as another voice, not as an override — a role deny stays visible on
 * the graph even when the flat block says allow, because at runtime
 * the role IS what gates the call. Later contributors beat earlier
 * ones on equal strength so the last-declared ``file_scope`` survives.
 *
 * Every consumer that wants "the color for this tool on the graph"
 * routes through this helper; the raw ``policy.tools`` / ``policy.roles``
 * fields stay pure representations of the YAML.
 */
export function mergedTools(policy: ParsedPolicy): Record<string, ToolPolicy> {
  const merged: Record<string, ToolPolicy> = {};
  const contribute = (entry: ToolPolicy, toolName: string): void => {
    const current = merged[toolName];
    if (current === undefined) {
      merged[toolName] = entry;
      return;
    }
    if (MODE_STRENGTH[entry.mode] >= MODE_STRENGTH[current.mode]) {
      merged[toolName] = entry;
    }
  };
  for (const [toolName, entry] of Object.entries(policy.tools)) {
    contribute(entry, toolName);
  }
  for (const rolePolicy of Object.values(policy.roles)) {
    for (const [toolName, entry] of Object.entries(rolePolicy.tools)) {
      contribute(entry, toolName);
    }
  }
  return merged;
}

export function buildAgentView(agent: AgentRead): AgentView | null {
  const parsedAgent = parseAgent(agent.agent_yaml, agent.policy_yaml);
  const parsedPolicy = parsePolicy(agent.policy_yaml);
  if (!parsedAgent || !parsedPolicy) return null;
  // Display tool list = agent.yaml declaration ONLY. Role-only tool
  // entries in policy don't create callable tools — the runtime
  // registers tools from agent.tools (the SDK-decorated functions);
  // policy just gates them. Including role-only tools here would draw
  // phantom capability edges on the graph.
  const tools = [...parsedAgent.tools];
  const merged = mergedTools(parsedPolicy);
  const missingInPolicy = tools.filter((t) => !(t in merged));
  return {
    name: parsedAgent.name || agent.name,
    model: parsedAgent.model,
    tools,
    policy: parsedPolicy,
    missingInPolicy,
  };
}

/**
 * The mode the overview graph should color the ``(agent, tool)`` edge.
 *
 * Semantics: worst case across every voice that has an opinion.
 *   * If a flat top-level entry exists, its mode is one voice.
 *   * Each role contributes: the role's own entry for the tool, or,
 *     when the role doesn't list the tool, that role's ``default_policy``
 *     mode (or the global default if the role didn't set one).
 *   * When there are no roles and no flat entry, the global
 *     ``default_policy`` mode wins by default.
 *
 * The strongest mode across all those voices is returned. This mirrors
 * runtime behavior: any role that would deny the call at runtime shows
 * as deny on the overview.
 */
export function effectiveMode(view: AgentView, toolName: string): Mode {
  const voices: Mode[] = [];
  const flatEntry = view.policy.tools[toolName];
  if (flatEntry) voices.push(flatEntry.mode);
  const roleNames = Object.keys(view.policy.roles);
  for (const roleName of roleNames) {
    const role = view.policy.roles[roleName];
    const roleEntry = role.tools[toolName];
    if (roleEntry) {
      voices.push(roleEntry.mode);
    } else {
      voices.push(role.default_policy?.mode ?? view.policy.default_policy.mode);
    }
  }
  if (voices.length === 0) return view.policy.default_policy.mode;
  return worstMode(voices) ?? view.policy.default_policy.mode;
}

export const MODE_COLOR: Record<Mode, string> = {
  allow: "hsl(var(--semantic-allow))",
  deny: "hsl(var(--semantic-deny))",
  approval_required: "hsl(var(--semantic-approval))",
};

/**
 * Extract the selectable role names from an inline-roles ``policy.yaml``.
 *
 * The wire format is one canonical document per agent. When the document
 * declares a top-level ``roles:`` map, this function returns the names of
 * the concrete roles (mixin entries filtered out via ``isMixinSpec``,
 * ``default`` first). When the document is a flat single-policy YAML,
 * returns an empty list — the caller (the Playground role picker) treats
 * that as "this agent has no per-role differentiation, run it as-is."
 *
 * Pure parse — no validation of the policy's correctness; that's the
 * server's /validate endpoint.
 */
export function parseRolesFromPolicy(policyYaml: string): string[] {
  let parsed: unknown;
  try {
    parsed = yaml.load(policyYaml);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const roles = (parsed as { roles?: unknown }).roles;
  if (!roles || typeof roles !== "object" || Array.isArray(roles)) return [];

  const concrete: string[] = [];
  for (const [name, spec] of Object.entries(roles as Record<string, unknown>)) {
    if (isMixinSpec(spec)) continue;
    concrete.push(name);
  }
  concrete.sort();
  if (concrete.includes("default")) {
    return ["default", ...concrete.filter((r) => r !== "default")];
  }
  return concrete;
}
