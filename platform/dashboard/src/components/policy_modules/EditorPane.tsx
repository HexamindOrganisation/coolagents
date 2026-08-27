import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { dump, load, YAMLException } from "js-yaml";
import { FileText, RotateCcw, Save, ScrollText } from "lucide-react";

import {
  ApiError,
  type PolicyDraft,
  type PolicyLint,
  type PolicyModuleRead,
  type PolicyValidationError,
  type RoleBindings,
} from "@/lib/api";
import { useSetRoles, useUpsertModule } from "@/lib/policy_modules";
import { lintToLine, type Selection } from "@/lib/module_tree";
import { PolicyEditor } from "@/components/PolicyEditor";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/** Serialize role bindings as the SDK's on-disk `roles.yaml` (version + map). */
function dumpRoles(roles: RoleBindings): string {
  return dump({ version: 1, roles }, { flowLevel: 2, lineWidth: 100 });
}

/** Parse the roles.yaml buffer back to bindings. Accepts the SDK shape
 * (`{version, roles: {...}}`) or a bare `role: [caps]` map. Throws on a
 * non-mapping or a non-string-list value so Save can block. */
function parseRoles(text: string): RoleBindings {
  const doc = load(text);
  if (doc === null || doc === undefined) return {};
  if (typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("roles.yaml must be a mapping of role -> capabilities");
  }
  // The SDK wrapper is `{version, roles: {...}}`; a bare map is `{role: [...]}`.
  // Detect the wrapper by whether `.roles` is itself a mapping — so a bare map
  // that legitimately has a role literally named `roles` (value is a list) is
  // not misread as the wrapper.
  const maybeRoles = (doc as Record<string, unknown>).roles;
  const wrapped =
    typeof maybeRoles === "object" &&
    maybeRoles !== null &&
    !Array.isArray(maybeRoles);
  const raw = wrapped ? maybeRoles : doc;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("`roles` must be a mapping of role -> capabilities");
  }
  const out: RoleBindings = {};
  for (const [role, caps] of Object.entries(raw as Record<string, unknown>)) {
    if (!Array.isArray(caps) || caps.some((c) => typeof c !== "string")) {
      throw new Error(`role ${role}: capabilities must be a list of names`);
    }
    out[role] = caps as string[];
  }
  return out;
}

const selKey = (sel: Selection) =>
  sel.kind === "roles" ? "roles" : `${sel.tier}:${sel.path}`;

interface ClientParse {
  ok: boolean;
  /** 1-based line of the parse error, when the exception carries a mark. */
  error: { line: number | null; message: string } | null;
}

function clientParse(text: string): ClientParse {
  try {
    load(text);
    return { ok: true, error: null };
  } catch (e) {
    if (e instanceof YAMLException) {
      const line = e.mark ? e.mark.line + 1 : null;
      return { ok: false, error: { line, message: e.reason || e.message } };
    }
    return { ok: false, error: { line: null, message: String(e) } };
  }
}

export function EditorPane({
  projectId,
  selection,
  modules,
  roles,
  lints,
  canManage,
  onDraftChange,
}: {
  projectId: string;
  selection: Selection;
  modules: PolicyModuleRead[];
  roles: RoleBindings;
  lints: PolicyLint[];
  canManage: boolean;
  onDraftChange: (draft: PolicyDraft | null, parses: boolean) => void;
}) {
  const upsert = useUpsertModule(projectId);
  const setRoles = useSetRoles(projectId);

  // Authoritative stored text for the open node.
  const saved = useMemo(() => {
    if (selection.kind === "roles") return dumpRoles(roles);
    const mod = modules.find(
      (m) => m.tier === selection.tier && m.path === selection.path,
    );
    return mod?.content ?? "";
  }, [selection, modules, roles]);

  const [draft, setDraft] = useState(saved);

  // Re-sync the buffer via the render-phase "adjust state when a prop changes"
  // pattern (no effect, so the reset lands in the same render as the switch).
  // On a file switch, always load the newly-selected file's stored text. On a
  // background refetch of the SAME file (React Query focus/invalidation), only
  // adopt the new server copy when the buffer is clean — never clobber unsaved
  // edits out from under the user. A dirty buffer keeps its edits and the
  // 'unsaved' badge; Save then resolves it last-write-wins.
  const nodeKey = selKey(selection);
  const [syncKey, setSyncKey] = useState(nodeKey);
  const [syncSaved, setSyncSaved] = useState(saved);
  if (nodeKey !== syncKey) {
    setSyncKey(nodeKey);
    setSyncSaved(saved);
    setDraft(saved);
  } else if (saved !== syncSaved) {
    const wasClean = draft === syncSaved;
    setSyncSaved(saved);
    if (wasClean) setDraft(saved);
  }

  const dirty = draft !== saved;
  const parse = useMemo(() => clientParse(draft), [draft]);

  // Publish the live overlay up so the inspector previews the unsaved edit.
  // Clean or unparseable → no overlay (the inspector shows stored state; the
  // parse error renders inline here). Parseable roles must extract to a map.
  useEffect(() => {
    if (!dirty || !parse.ok) {
      onDraftChange(null, parse.ok);
      return;
    }
    if (selection.kind === "roles") {
      try {
        onDraftChange({ roles: parseRoles(draft) }, true);
      } catch {
        onDraftChange(null, false);
      }
    } else {
      onDraftChange(
        {
          module: {
            tier: selection.tier,
            path: selection.path,
            content: draft,
          },
        },
        true,
      );
    }
  }, [draft, dirty, parse.ok, selection, onDraftChange]);

  const handleChange = useCallback((next: string) => setDraft(next), []);

  // Semantic lints for THIS module, anchored to the tool's line. Whole-module
  // and cross-role lints have no line and surface in the inspector's Lints tab.
  const fileLints = useMemo<PolicyLint[]>(() => {
    if (selection.kind !== "module") return [];
    return lints.filter(
      (l) =>
        l.source === selection.path ||
        l.source === `${selection.tier}/${selection.path}`,
    );
  }, [lints, selection]);

  const diagnostics = useMemo<PolicyValidationError[]>(() => {
    const out: PolicyValidationError[] = [];
    if (parse.error) {
      out.push({
        role: null,
        line: parse.error.line,
        message: parse.error.message,
      });
    }
    for (const l of fileLints) {
      const line = lintToLine(draft, l);
      if (line) out.push({ role: l.role, line, message: l.message });
    }
    return out;
  }, [parse.error, fileLints, draft]);

  // Everything to list in the inline banner: the client parse error plus ALL
  // this-file lints — including semantic ones that can't be pinned to a line
  // (shown without a line number), so a file-level error is visible next to the
  // code, not only in the inspector's Lints tab. The gutter still underlines
  // only the line-anchored `diagnostics` above.
  const bannerItems = useMemo(() => {
    const out: { line: number | null; message: string }[] = [];
    if (parse.error) {
      out.push({ line: parse.error.line, message: parse.error.message });
    }
    for (const l of fileLints) {
      out.push({ line: lintToLine(draft, l), message: l.message });
    }
    return out;
  }, [parse.error, fileLints, draft]);

  const hasError = !parse.ok || fileLints.some((l) => l.severity === "error");

  function handleSave() {
    if (selection.kind === "roles") {
      let parsed: RoleBindings;
      try {
        parsed = parseRoles(draft);
      } catch (e) {
        toast.error(e instanceof Error ? e.message : "roles.yaml is invalid");
        return;
      }
      setRoles.mutate(parsed, {
        onSuccess: () => {
          // Re-sync the buffer to the canonical dump the server now echoes, so
          // a bare/reordered roles.yaml doesn't read as perpetually "unsaved"
          // (dumpRoles rarely equals the user's typed text byte-for-byte).
          setDraft(dumpRoles(parsed));
          toast.success("Saved roles.yaml");
        },
        onError: (e) =>
          toast.error(
            e instanceof ApiError ? e.message : "Could not save roles",
          ),
      });
      return;
    }
    upsert.mutate(
      { tier: selection.tier, path: selection.path, content: draft },
      {
        onSuccess: () => toast.success(`Saved ${selection.path}`),
        onError: (e) =>
          toast.error(e instanceof ApiError ? e.message : "Could not save"),
      },
    );
  }

  const saving = upsert.isPending || setRoles.isPending;
  const title =
    selection.kind === "roles"
      ? "roles.yaml"
      : `${selection.tier === "boundary" ? "boundaries" : "capabilities"}/${selection.path}`;
  const Icon = selection.kind === "roles" ? ScrollText : FileText;

  return (
    <div className="h-full flex flex-col">
      <header className="flex items-center justify-between gap-2 px-4 py-2 border-b border-border">
        <div className="flex items-center gap-2 text-sm min-w-0">
          <Icon className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="font-mono truncate">{title}</span>
          {dirty && <Badge variant="approval">unsaved</Badge>}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setDraft(saved)}
            disabled={!dirty || saving}
            className="gap-1.5 h-8"
            title="Discard unsaved changes"
          >
            <RotateCcw className="size-3.5" />
            Discard
          </Button>
          {canManage && (
            <Button
              size="sm"
              onClick={handleSave}
              disabled={!dirty || saving}
              className="gap-1.5 h-8"
            >
              <Save className="size-3.5" />
              {saving ? "Saving…" : "Save"}
            </Button>
          )}
        </div>
      </header>
      <PolicyEditor
        value={draft}
        onChange={handleChange}
        diagnostics={diagnostics}
        readOnly={!canManage}
        className="flex-1 overflow-hidden"
      />
      {/* Diagnostics as a bottom status bar (VSCode "problems"), so appearing/
          clearing them never shifts the editor content down from the top. */}
      {bannerItems.length > 0 && (
        <div
          className={cn(
            "shrink-0 max-h-28 overflow-y-auto scrollbar-thin px-4 py-1.5 text-xs border-t font-mono space-y-0.5",
            hasError
              ? "bg-deny/5 border-deny/30 text-deny"
              : "bg-approval/5 border-approval/30 text-approval",
          )}
        >
          {bannerItems.map((d, i) => (
            <div key={i}>
              {d.line ? `L${d.line} — ` : ""}
              {d.message}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
