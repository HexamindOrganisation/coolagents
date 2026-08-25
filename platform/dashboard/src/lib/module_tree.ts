/**
 * Pure helpers backing the module tree — the left pane renders the DB rows
 * (`policy_module`) as the SDK's on-disk layout: `boundaries/`, `capabilities/`
 * (nestable), and a synthetic `roles.yaml` at the root. Folders are derived
 * from module paths; there is no folder entity.
 */

import type { PolicyLint, PolicyModuleRead, PolicyTier } from "./api";

/** Which node the editor has open. `roles` is the synthetic roles.yaml. */
export type Selection =
  | { kind: "module"; tier: PolicyTier; path: string }
  | { kind: "roles" };

export interface FileLeaf {
  type: "file";
  /** Last path segment — the display name. */
  name: string;
  tier: PolicyTier;
  /** Full module path (may contain slashes). */
  path: string;
}

export interface FolderNode {
  type: "folder";
  name: string;
  /** Path prefix this folder represents, "" at a tier root. */
  prefix: string;
  tier: PolicyTier;
  children: TreeNode[];
}

export type TreeNode = FolderNode | FileLeaf;

const TIER_FOLDER: Record<PolicyTier, string> = {
  boundary: "boundaries",
  capability: "capabilities",
};

/** Insert one module into a tier's child list, creating folders as needed. */
function insert(children: TreeNode[], mod: PolicyModuleRead): void {
  const segments = mod.path.split("/").filter(Boolean);
  let level = children;
  let prefix = "";
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    const last = i === segments.length - 1;
    if (last) {
      level.push({ type: "file", name: seg, tier: mod.tier, path: mod.path });
      return;
    }
    prefix = prefix ? `${prefix}/${seg}` : seg;
    let folder = level.find(
      (n): n is FolderNode => n.type === "folder" && n.name === seg,
    );
    if (!folder) {
      folder = {
        type: "folder",
        name: seg,
        prefix,
        tier: mod.tier,
        children: [],
      };
      level.push(folder);
    }
    level = folder.children;
  }
}

/** Sort folders before files, each group alphabetically, recursively. */
function sortTree(nodes: TreeNode[]): void {
  nodes.sort((a, b) => {
    if (a.type !== b.type) return a.type === "folder" ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  for (const n of nodes) if (n.type === "folder") sortTree(n.children);
}

/** Ensure the folder chain for `prefix` exists in `children`, creating empty
 * FolderNodes as needed. Used to render UI-only empty subfolders (the store has
 * no folder entity — folders are otherwise derived from module paths). */
function ensureFolderChain(
  children: TreeNode[],
  prefix: string,
  tier: PolicyTier,
): void {
  let level = children;
  let p = "";
  for (const seg of prefix.split("/").filter(Boolean)) {
    p = p ? `${p}/${seg}` : seg;
    let folder = level.find(
      (n): n is FolderNode => n.type === "folder" && n.name === seg,
    );
    if (!folder) {
      folder = { type: "folder", name: seg, prefix: p, tier, children: [] };
      level.push(folder);
    }
    level = folder.children;
  }
}

/** A UI-only empty subfolder to render even though no module lives in it yet. */
export interface EmptyFolder {
  tier: PolicyTier;
  prefix: string;
}

/**
 * Build the two tier roots (always present, even when empty) from the flat
 * module list. Each root is a folder whose children are the modules of that
 * tier, nested by their path segments. `emptyFolders` injects UI-only empty
 * subfolders (client-side; they vanish on reload until a module lands in them).
 */
export function buildModuleTree(
  modules: PolicyModuleRead[],
  emptyFolders: EmptyFolder[] = [],
): FolderNode[] {
  const roots: Record<PolicyTier, FolderNode> = {
    boundary: {
      type: "folder",
      name: TIER_FOLDER.boundary,
      prefix: "",
      tier: "boundary",
      children: [],
    },
    capability: {
      type: "folder",
      name: TIER_FOLDER.capability,
      prefix: "",
      tier: "capability",
      children: [],
    },
  };
  for (const mod of modules) insert(roots[mod.tier].children, mod);
  for (const f of emptyFolders) {
    ensureFolderChain(roots[f.tier].children, f.prefix, f.tier);
  }
  sortTree(roots.boundary.children);
  sortTree(roots.capability.children);
  return [roots.boundary, roots.capability];
}

/**
 * The path a module takes when reparented under `folderPrefix` (drag-to-move
 * keeps the basename, swaps the parent). `folderPrefix` is "" at a tier root,
 * which moves the module back to the top level.
 */
export function reparent(folderPrefix: string, path: string): string {
  const base = path.split("/").pop() as string;
  return folderPrefix ? `${folderPrefix}/${base}` : base;
}

/**
 * 1-based line of a lint within the open module, or null. The loader doesn't
 * track exact positions yet, so anchor a tool-scoped lint to the line where
 * that tool key is declared (a `  <tool>:` entry under `tools:`). Whole-module
 * lints (no tool) stay unanchored and surface in the list instead.
 */
export function lintToLine(content: string, lint: PolicyLint): number | null {
  if (!lint.tool) return null;
  const lines = content.split("\n");
  const key = `${lint.tool}:`;
  for (let i = 0; i < lines.length; i++) {
    // Tool entries are always nested under `tools:`, so they're indented —
    // require leading whitespace to avoid matching a same-named top-level key.
    if (/^\s/.test(lines[i]) && lines[i].trim().startsWith(key)) return i + 1;
  }
  return null;
}
