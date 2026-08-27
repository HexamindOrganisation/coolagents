import { useCallback, useMemo, useState } from "react";
import { Boxes } from "lucide-react";

import type { PolicyDraft } from "@/lib/api";
import { useProjectScoped } from "@/lib/active";
import {
  useCanManagePolicy,
  useDebouncedValue,
  usePolicyCheck,
  usePolicyModules,
  usePolicyPreview,
  usePolicyRoles,
  useResolvedPolicy,
} from "@/lib/policy_modules";
import type { Selection } from "@/lib/module_tree";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { DocsLink } from "@/components/DocsLink";
import { DOC_PATHS } from "@/lib/docs";
import { ModularBanner } from "@/components/policy_modules/ModularBanner";
import { ModuleTree } from "@/components/policy_modules/ModuleTree";
import { EditorPane } from "@/components/policy_modules/EditorPane";
import { InspectorTabs } from "@/components/policy_modules/InspectorTabs";

/**
 * Multi-module policy editor. Three panes: the module tree (a rendering of the
 * `policy_module` rows as the SDK's on-disk layout), a CodeMirror editor for
 * the open module or `roles.yaml`, and an inspector showing the composed policy
 * per role, lints, and a decision tester. The resolved + lints panes reflect
 * the unsaved edit live (debounced `POST /policy/preview`); Save is explicit.
 */
export function PolicyModulesPage() {
  const scope = useProjectScoped();
  const projectId = scope.projectId;
  const canManage = useCanManagePolicy();

  const modules = usePolicyModules(projectId);
  const roles = usePolicyRoles(projectId);

  const [selection, setSelection] = useState<Selection>({ kind: "roles" });
  // The editor's unsaved overlay (null = clean or unparseable) + whether the
  // current buffer parses client-side (gates the server preview round-trip).
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [draftParses, setDraftParses] = useState(true);

  const onDraftChange = useCallback(
    (next: PolicyDraft | null, parses: boolean) => {
      setDraft(next);
      setDraftParses(parses);
    },
    [],
  );

  // Debounce the overlay so the preview fires on pause, not per keystroke, and
  // skip it entirely while the draft doesn't parse (no point sending broken
  // YAML). Latest-wins is handled by the query key on the debounced draft.
  const debouncedDraft = useDebouncedValue(draft, 600);
  const draftActive = draft !== null;
  const previewEnabled = draftParses && debouncedDraft !== null;
  const preview = usePolicyPreview(projectId, debouncedDraft, previewEnabled);

  const storedResolve = useResolvedPolicy(projectId);
  const check = usePolicyCheck(projectId);

  const usePreviewData = draftActive && !!preview.data;
  const resolved = usePreviewData ? preview.data?.resolved : storedResolve.data;
  const lints = useMemo(
    () =>
      usePreviewData ? (preview.data?.lints ?? []) : (check.data?.lints ?? []),
    [usePreviewData, preview.data, check.data],
  );
  // Clean resolution iff nothing is an error lint (a 422 on stored resolve
  // surfaces as an error lint on check, so this covers both sources).
  const resolves = lints.every((l) => l.severity !== "error");
  const roleBindings = roles.data ?? {};
  const modular = Object.keys(roleBindings).length > 0;

  if (scope.status === "no-project") {
    return <NoProjectEmptyState resource="policies" />;
  }

  const loading = modules.isLoading || roles.isLoading;

  return (
    <div className="-mx-8 -my-6 h-[calc(100vh-56px)] flex flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-4 px-6 py-3 border-b border-border bg-card">
        <div className="flex items-center gap-2">
          <Boxes className="size-4 text-muted-foreground" />
          <span className="text-sm font-medium">Policy modules</span>
        </div>
        <DocsLink path={DOC_PATHS.policies} label="Policy docs" />
      </header>

      {!loading && <ModularBanner modular={modular} />}

      {loading || !projectId ? (
        <div className="flex-1 grid place-items-center text-sm text-muted-foreground">
          {scope.status === "loading" || loading
            ? "Loading policy…"
            : "No project selected."}
        </div>
      ) : (
        <div className="flex-1 grid grid-cols-[240px_minmax(0,1fr)_minmax(320px,380px)] overflow-hidden">
          <div className="border-r border-border overflow-hidden">
            <ModuleTree
              modules={modules.data ?? []}
              selection={selection}
              onSelect={setSelection}
              projectId={projectId}
              canManage={canManage}
            />
          </div>
          <div className="overflow-hidden border-r border-border">
            <EditorPane
              projectId={projectId}
              selection={selection}
              modules={modules.data ?? []}
              roles={roleBindings}
              lints={lints}
              canManage={canManage}
              onDraftChange={onDraftChange}
            />
          </div>
          <div className="overflow-hidden">
            <InspectorTabs
              projectId={projectId}
              resolved={resolved}
              lints={lints}
              roles={roleBindings}
              draft={draftActive ? draft : null}
              resolves={resolves}
              modular={modular}
              previewing={draftActive && preview.isFetching}
            />
          </div>
        </div>
      )}
    </div>
  );
}
