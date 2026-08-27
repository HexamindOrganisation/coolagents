import { useMemo, useState } from "react";
import { toast } from "sonner";
import {
  ChevronDown,
  ChevronRight,
  FilePlus,
  FileText,
  Folder,
  FolderPlus,
  Pencil,
  ScrollText,
  Trash2,
} from "lucide-react";

import { ApiError, type PolicyModuleRead, type PolicyTier } from "@/lib/api";
import {
  useCreateFolder,
  useDeleteFolder,
  useDeleteModule,
  useMoveModule,
  usePolicyFolders,
  useUpsertModule,
} from "@/lib/policy_modules";
import {
  buildModuleTree,
  reparent,
  type EmptyFolder,
  type FolderNode,
  type Selection,
  type TreeNode,
} from "@/lib/module_tree";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

// Starter content for a freshly-created module — a VALID minimal policy (empty
// tool map), so upsert doesn't reject it. `tools:` with only a comment parses
// to null, which AgentPolicy rejects ("tools must be a dictionary").
const TEMPLATE: Record<PolicyTier, string> = {
  boundary:
    "# Boundary: ceilings + hard denies (applies to every role).\n" +
    "# e.g.  delete_database: { mode: deny }\n" +
    "default_policy: { mode: allow }\n" +
    "tools: {}\n",
  capability:
    "# Capability: grants a role imports (grants only).\n" +
    "# e.g.  refund_order: { mode: allow }\n" +
    "tools: {}\n",
};

/** Normalize a typed module path: trim whitespace and strip leading/trailing
 * slashes so " team_a/payments/ " -> "team_a/payments". */
function normalizePath(raw: string): string {
  return raw.trim().replace(/^\/+|\/+$/g, "");
}

function isSelected(sel: Selection, leaf: { tier: PolicyTier; path: string }) {
  return (
    sel.kind === "module" && sel.tier === leaf.tier && sel.path === leaf.path
  );
}

export function ModuleTree({
  modules,
  selection,
  onSelect,
  projectId,
  canManage,
}: {
  modules: PolicyModuleRead[];
  selection: Selection;
  onSelect: (sel: Selection) => void;
  projectId: string;
  canManage: boolean;
}) {
  const upsert = useUpsertModule(projectId);
  const move = useMoveModule(projectId);
  const del = useDeleteModule(projectId);
  const folders = usePolicyFolders(projectId);
  const createFolder = useCreateFolder(projectId);
  const deleteFolder = useDeleteFolder(projectId);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  // Drag-to-move: the leaf being dragged + the folder key currently hovered.
  // Drops are same-tier only (the PATCH move endpoint is same-tier), so a
  // capability can't land in boundaries/ and vice versa.
  const [dragged, setDragged] = useState<{
    tier: PolicyTier;
    path: string;
  } | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  // Open state for the path dialog (null = closed): create a module/subfolder,
  // or rename/move an existing one. Both share ModulePathDialog.
  const [dialog, setDialog] = useState<
    | { kind: "new"; tier: PolicyTier; prefix: string; subfolder: boolean }
    | { kind: "rename"; tier: PolicyTier; path: string }
    | null
  >(null);
  // Bumped on every open so the dialog remounts fresh — otherwise it reopens
  // showing the previously-typed value.
  const [dialogSeq, setDialogSeq] = useState(0);
  function openDialog(next: NonNullable<typeof dialog>) {
    setDialog(next);
    setDialogSeq((s) => s + 1);
  }

  // Persisted empty folders (from the store), mapped to the tree builder's
  // {tier, prefix} shape. A folder with modules renders from those paths; these
  // rows only keep an EMPTY folder visible.
  const emptyFolders = useMemo<EmptyFolder[]>(
    () => (folders.data ?? []).map((f) => ({ tier: f.tier, prefix: f.path })),
    [folders.data],
  );

  const roots = useMemo(
    () => buildModuleTree(modules, emptyFolders),
    [modules, emptyFolders],
  );
  // Full-path keys for the module duplicate check.
  const existingPaths = useMemo(
    () => new Set(modules.map((m) => `${m.tier}:${m.path}`)),
    [modules],
  );
  // Folder prefixes (from module paths + UI-only folders) for the folder dup check.
  const existingFolders = useMemo(() => {
    const s = new Set<string>();
    for (const m of modules) {
      const segs = m.path.split("/").filter(Boolean);
      let p = "";
      for (let i = 0; i < segs.length - 1; i++) {
        p = p ? `${p}/${segs[i]}` : segs[i];
        s.add(`${m.tier}:${p}`);
      }
    }
    for (const f of emptyFolders) s.add(`${f.tier}:${f.prefix}`);
    return s;
  }, [modules, emptyFolders]);

  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  // Persist an empty subfolder so it renders before any module lives in it.
  function addEmptyFolder(tier: PolicyTier, prefix: string) {
    createFolder.mutate(
      { tier, path: prefix },
      {
        onSuccess: () => {
          setCollapsed((prev) => {
            const n = new Set(prev);
            n.delete(`${tier}:${prefix}`); // keep it expanded
            return n;
          });
          toast.success(`Created folder ${tier}/${prefix}`);
        },
        onError: (e) =>
          toast.error(
            e instanceof ApiError
              ? e.message
              : `Could not create folder ${prefix}`,
          ),
      },
    );
  }

  // Delete an empty folder marker (only offered for folders with no children).
  function handleDeleteFolder(tier: PolicyTier, prefix: string) {
    deleteFolder.mutate(
      { tier, path: prefix },
      {
        onSuccess: () => toast.success(`Deleted folder ${tier}/${prefix}`),
        onError: (e) =>
          toast.error(
            e instanceof ApiError
              ? e.message
              : `Could not delete folder ${prefix}`,
          ),
      },
    );
  }

  // Create a module from the dialog's validated (trimmed, non-duplicate) path.
  function createModule(tier: PolicyTier, path: string) {
    upsert.mutate(
      { tier, path, content: TEMPLATE[tier] },
      {
        onSuccess: () => {
          onSelect({ kind: "module", tier, path });
          toast.success(`Created ${tier}/${path}`);
        },
        onError: (e) =>
          toast.error(
            e instanceof ApiError ? e.message : `Could not create ${path}`,
          ),
      },
    );
  }

  // Shared by Rename (type a path) and drag-to-move (drop into a folder).
  // No-ops when the path is unchanged so an accidental drop-in-place is free.
  function moveTo(leaf: { tier: PolicyTier; path: string }, newPath: string) {
    if (!newPath || newPath === leaf.path) return;
    move.mutate(
      { tier: leaf.tier, path: leaf.path, newPath },
      {
        onSuccess: () => {
          if (isSelected(selection, leaf)) {
            onSelect({ kind: "module", tier: leaf.tier, path: newPath });
          }
          toast.success(`Moved to ${newPath}`, {
            action: {
              label: "Undo",
              onClick: () =>
                move.mutate({
                  tier: leaf.tier,
                  path: newPath,
                  newPath: leaf.path,
                }),
            },
          });
        },
        onError: (e) =>
          toast.error(
            e instanceof ApiError && e.status === 409
              ? `A ${leaf.tier} already exists at ${newPath}`
              : e instanceof ApiError
                ? e.message
                : `Could not move ${leaf.path}`,
          ),
      },
    );
  }

  function handleRename(leaf: { tier: PolicyTier; path: string }) {
    openDialog({ kind: "rename", tier: leaf.tier, path: leaf.path });
  }

  function handleDelete(leaf: { tier: PolicyTier; path: string }) {
    const saved = modules.find(
      (m) => m.tier === leaf.tier && m.path === leaf.path,
    );
    del.mutate(
      { tier: leaf.tier, path: leaf.path },
      {
        onSuccess: () => {
          if (isSelected(selection, leaf)) onSelect({ kind: "roles" });
          toast.success(`Deleted ${leaf.tier}/${leaf.path}`, {
            action: saved
              ? {
                  label: "Undo",
                  onClick: () =>
                    upsert.mutate({
                      tier: saved.tier,
                      path: saved.path,
                      content: saved.content,
                    }),
                }
              : undefined,
          });
        },
        onError: (e) =>
          toast.error(
            e instanceof ApiError ? e.message : `Could not delete ${leaf.path}`,
          ),
      },
    );
  }

  const renderNode = (node: TreeNode, depth: number) => {
    if (node.type === "folder") {
      const folderKey = `${node.tier}:${node.prefix}`;
      const isOpen = !collapsed.has(folderKey);
      const canDrop = !!dragged && dragged.tier === node.tier;
      return (
        <div key={`${node.tier}:${node.prefix || node.name}`}>
          <div
            className={cn(
              "group flex items-center gap-1 rounded px-1.5 py-1 text-xs text-muted-foreground hover:bg-accent",
              dropTarget === folderKey && "ring-1 ring-primary bg-primary/10",
            )}
            style={{ paddingLeft: `${depth * 12 + 6}px` }}
            onDragOver={(e) => {
              if (!canDrop) return;
              e.preventDefault();
              setDropTarget(folderKey);
            }}
            onDragLeave={() =>
              setDropTarget((k) => (k === folderKey ? null : k))
            }
            onDrop={(e) => {
              e.preventDefault();
              setDropTarget(null);
              if (canDrop && dragged) {
                moveTo(
                  { tier: dragged.tier, path: dragged.path },
                  reparent(node.prefix, dragged.path),
                );
              }
              setDragged(null);
            }}
          >
            <button
              onClick={() => toggle(`${node.tier}:${node.prefix}`)}
              className="flex items-center gap-1 flex-1 min-w-0"
            >
              {isOpen ? (
                <ChevronDown className="size-3 shrink-0" />
              ) : (
                <ChevronRight className="size-3 shrink-0" />
              )}
              <Folder className="size-3.5 shrink-0" />
              <span className="truncate font-medium">{node.name}</span>
            </button>
            {canManage && (
              <span className="flex items-center gap-1.5 opacity-0 group-hover:opacity-100">
                <button
                  title="New module"
                  onClick={() =>
                    openDialog({
                      kind: "new",
                      tier: node.tier,
                      prefix: node.prefix,
                      subfolder: false,
                    })
                  }
                  className="hover:text-foreground"
                >
                  <FilePlus className="size-3.5" />
                </button>
                <button
                  title="New subfolder"
                  onClick={() =>
                    openDialog({
                      kind: "new",
                      tier: node.tier,
                      prefix: node.prefix,
                      subfolder: true,
                    })
                  }
                  className="hover:text-foreground"
                >
                  <FolderPlus className="size-3.5" />
                </button>
                {node.prefix !== "" && node.children.length === 0 && (
                  <button
                    title="Delete empty folder"
                    onClick={() => handleDeleteFolder(node.tier, node.prefix)}
                    className="hover:text-deny"
                  >
                    <Trash2 className="size-3.5" />
                  </button>
                )}
              </span>
            )}
          </div>
          {isOpen &&
            (node.children.length ? (
              node.children.map((c) => renderNode(c, depth + 1))
            ) : (
              <div
                className="text-[11px] italic text-muted-foreground/60 py-0.5"
                style={{ paddingLeft: `${(depth + 1) * 12 + 24}px` }}
              >
                empty
              </div>
            ))}
        </div>
      );
    }

    const active = isSelected(selection, node);
    const dragging = dragged?.tier === node.tier && dragged?.path === node.path;
    return (
      <div
        key={`${node.tier}:${node.path}`}
        draggable={canManage}
        onDragStart={(e) => {
          setDragged({ tier: node.tier, path: node.path });
          e.dataTransfer.effectAllowed = "move";
        }}
        onDragEnd={() => {
          setDragged(null);
          setDropTarget(null);
        }}
        className={cn(
          "group flex items-center gap-1 rounded px-1.5 py-1 text-xs cursor-pointer",
          active
            ? "bg-primary/15 text-primary font-medium"
            : "text-foreground hover:bg-accent",
          dragging && "opacity-50",
        )}
        style={{ paddingLeft: `${depth * 12 + 22}px` }}
        onClick={() =>
          onSelect({ kind: "module", tier: node.tier, path: node.path })
        }
      >
        <FileText className="size-3.5 shrink-0 text-muted-foreground" />
        <span className="truncate flex-1">{node.name}</span>
        {canManage && (
          <span className="flex items-center gap-1 opacity-0 group-hover:opacity-100">
            <button
              title="Move / rename"
              onClick={(e) => {
                e.stopPropagation();
                handleRename(node);
              }}
              className="hover:text-foreground text-muted-foreground"
            >
              <Pencil className="size-3" />
            </button>
            <button
              title="Delete"
              onClick={(e) => {
                e.stopPropagation();
                handleDelete(node);
              }}
              className="hover:text-deny text-muted-foreground"
            >
              <Trash2 className="size-3" />
            </button>
          </span>
        )}
      </div>
    );
  };

  return (
    <div className="h-full flex flex-col text-sm">
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          Files
        </span>
      </div>
      <div className="flex-1 overflow-y-auto p-1.5 scrollbar-thin space-y-0.5">
        {/* roles.yaml is a synthetic, always-present node at the root. */}
        <div
          className={cn(
            "flex items-center gap-1.5 rounded px-1.5 py-1 text-xs cursor-pointer",
            selection.kind === "roles"
              ? "bg-primary/15 text-primary font-medium"
              : "text-foreground hover:bg-accent",
          )}
          onClick={() => onSelect({ kind: "roles" })}
        >
          <ScrollText className="size-3.5 shrink-0 text-muted-foreground" />
          <span>roles.yaml</span>
        </div>
        {roots.map((root: FolderNode) => renderNode(root, 0))}
      </div>
      {dialog?.kind === "new" && (
        <ModulePathDialog
          key={dialogSeq}
          tier={dialog.tier}
          title={
            dialog.subfolder
              ? `New ${dialog.tier} folder`
              : `New ${dialog.tier}`
          }
          description={
            dialog.subfolder
              ? "Create an empty subfolder here; add modules to it afterward."
              : "Name the module. Use / to nest further, e.g. payments or team_b/payments."
          }
          fixedPrefix={dialog.prefix}
          initial=""
          existingPaths={dialog.subfolder ? existingFolders : existingPaths}
          confirmLabel={dialog.subfolder ? "Create folder" : "Create"}
          onClose={() => setDialog(null)}
          onSubmit={(path) => {
            if (dialog.subfolder) addEmptyFolder(dialog.tier, path);
            else createModule(dialog.tier, path);
            setDialog(null);
          }}
        />
      )}
      {dialog?.kind === "rename" && (
        <ModulePathDialog
          key={dialogSeq}
          tier={dialog.tier}
          title={`Move / rename ${dialog.tier}`}
          description="Rename in place, or move it by changing the folder path (use / to nest). Renaming a capability updates the roles that import it."
          initial={dialog.path}
          existingPaths={existingPaths}
          selfPath={dialog.path}
          confirmLabel="Save"
          onClose={() => setDialog(null)}
          onSubmit={(path) => {
            moveTo({ tier: dialog.tier, path: dialog.path }, path);
            setDialog(null);
          }}
        />
      )}
    </div>
  );
}

/** Modal for a module path — used to create (module / folder) and to
 * rename/move. `fixedPrefix` (create mode) is the immutable parent folder shown
 * as a label, so the typed value is only the name *within* it — the parent
 * can't be accidentally cleared, and nesting works at any depth. Rename passes
 * no `fixedPrefix`, so the input is the full path. Trims the input (whitespace
 * + edge slashes) and blocks duplicates against the full tier+path; `selfPath`
 * excludes the entry's own path (so an unchanged rename is a no-op). */
function ModulePathDialog({
  tier,
  title,
  description,
  fixedPrefix,
  initial,
  existingPaths,
  selfPath,
  confirmLabel,
  onClose,
  onSubmit,
}: {
  tier: PolicyTier;
  title: string;
  description: string;
  fixedPrefix?: string;
  initial: string;
  existingPaths: Set<string>;
  selfPath?: string;
  confirmLabel: string;
  onClose: () => void;
  onSubmit: (path: string) => void;
}) {
  const [value, setValue] = useState(initial);
  const rel = normalizePath(value);
  // Combine the fixed parent (if any) with the typed name into the full path.
  const path = fixedPrefix ? (rel ? `${fixedPrefix}/${rel}` : "") : rel;
  const isSelf = selfPath !== undefined && path === selfPath;
  const error = !rel
    ? "Enter a name."
    : existingPaths.has(`${tier}:${path}`) && !isSelf
      ? `A ${tier} already exists at ${path}.`
      : null;
  // isSelf = an unchanged rename: valid input, but nothing to do -> disabled.
  const disabled = !!error || isSelf;

  const submit = () => {
    if (!disabled) onSubmit(path);
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <Label htmlFor="module-path">{fixedPrefix ? "Name" : "Path"}</Label>
          <div className="flex items-center gap-1">
            {fixedPrefix && (
              <span className="shrink-0 font-mono text-xs text-muted-foreground">
                {fixedPrefix}/
              </span>
            )}
            <Input
              id="module-path"
              autoFocus
              value={value}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
              placeholder={tier === "capability" ? "payments" : "org_core"}
              className="flex-1"
            />
          </div>
          {error && value.trim() !== "" && (
            <p className="text-xs text-deny">{error}</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={disabled} onClick={submit}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
