import { useMemo, useState } from "react";
import { dump } from "js-yaml";
import { AlertTriangle, FlaskConical, Info, ListChecks } from "lucide-react";

import type {
  PolicyDraft,
  PolicyLint,
  ResolvedPolicy,
  RoleBindings,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { TestPanel } from "./TestPanel";
import { cn } from "@/lib/utils";

type Tab = "resolved" | "lints" | "test";

function modeBadge(mode: string | undefined) {
  if (mode === "allow") return "allow" as const;
  if (mode === "deny") return "deny" as const;
  if (mode === "approval_required") return "approval" as const;
  return "default" as const;
}

/**
 * Right pane: the composed policy (Resolved), analyzer lints (Lints), and the
 * decision tester (Test). Resolved + Lints reflect the unsaved draft when one
 * is active (the page feeds preview results through); otherwise stored state.
 */
export function InspectorTabs({
  projectId,
  resolved,
  lints,
  roles,
  draft,
  resolves,
  previewing,
}: {
  projectId: string;
  resolved: ResolvedPolicy | undefined;
  lints: PolicyLint[];
  roles: RoleBindings;
  draft: PolicyDraft | null;
  resolves: boolean;
  previewing: boolean;
}) {
  const [tab, setTab] = useState<Tab>("resolved");
  const errorCount = lints.filter((l) => l.severity === "error").length;

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-1 px-2 py-2 border-b border-border">
        <TabButton
          active={tab === "resolved"}
          onClick={() => setTab("resolved")}
          Icon={ListChecks}
          label="Resolved"
        />
        <TabButton
          active={tab === "lints"}
          onClick={() => setTab("lints")}
          Icon={AlertTriangle}
          label="Lints"
          count={lints.length}
          danger={errorCount > 0}
        />
        <TabButton
          active={tab === "test"}
          onClick={() => setTab("test")}
          Icon={FlaskConical}
          label="Test"
        />
        {previewing && (
          <span className="ml-auto text-[10px] text-muted-foreground animate-pulse">
            previewing…
          </span>
        )}
      </div>
      <div className="flex-1 overflow-hidden">
        {tab === "resolved" && (
          <ResolvedTab resolved={resolved} resolves={resolves} />
        )}
        {tab === "lints" && <LintsTab lints={lints} />}
        {tab === "test" && (
          <TestPanel
            projectId={projectId}
            roles={roles}
            draft={draft}
            resolves={resolves}
          />
        )}
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  Icon,
  label,
  count,
  danger,
}: {
  active: boolean;
  onClick: () => void;
  Icon: typeof Info;
  label: string;
  count?: number;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors",
        active
          ? "bg-primary text-primary-foreground"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      <Icon className="size-3" />
      {label}
      {count !== undefined && count > 0 && (
        <span
          className={cn(
            "rounded-full px-1.5 text-[10px]",
            danger ? "bg-deny/20 text-deny" : "bg-muted text-muted-foreground",
          )}
        >
          {count}
        </span>
      )}
    </button>
  );
}

function ResolvedTab({
  resolved,
  resolves,
}: {
  resolved: ResolvedPolicy | undefined;
  resolves: boolean;
}) {
  const roleNames = useMemo(
    () => (resolved ? Object.keys(resolved).sort() : []),
    [resolved],
  );
  const [role, setRole] = useState<string>("");
  const [view, setView] = useState<"table" | "yaml">("table");
  const active = roleNames.includes(role) ? role : (roleNames[0] ?? "");

  if (!resolves || !resolved || roleNames.length === 0) {
    return (
      <div className="h-full grid place-items-center px-6 text-center">
        <p className="text-xs text-muted-foreground">
          {resolves
            ? "No roles bound yet — bind one in roles.yaml to see the composed policy."
            : "The modules don't compose. See the Lints tab."}
        </p>
      </div>
    );
  }

  const policy = resolved[active];
  const tools = policy?.tools ?? {};
  const toolNames = Object.keys(tools).sort();
  const defaultMode = policy?.default_policy?.mode;

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between gap-2 px-3 py-2 border-b border-border">
        <div className="flex flex-wrap items-center gap-1 min-w-0">
          {roleNames.map((r) => (
            <button
              key={r}
              onClick={() => setRole(r)}
              className={cn(
                "rounded px-2 py-0.5 text-xs font-mono",
                r === active
                  ? "bg-primary/15 text-primary font-medium"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {r}
            </button>
          ))}
        </div>
        <div className="flex items-center rounded-md border border-border p-0.5 shrink-0">
          {(["table", "yaml"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={cn(
                "rounded px-2 py-0.5 text-[11px] font-medium capitalize transition-colors",
                view === v
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {v}
            </button>
          ))}
        </div>
      </div>
      {view === "yaml" ? (
        <div className="flex-1 overflow-auto scrollbar-thin p-3">
          {/* The composed / "compiled" policy for this role as one document —
              boundaries + the role's capabilities merged (hexgate policy
              resolve). Read-only; edits happen in the module files. */}
          <pre className="text-[11px] font-mono leading-relaxed whitespace-pre">
            {dumpPolicy(policy)}
          </pre>
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto scrollbar-thin p-3 space-y-1">
          {defaultMode && (
            <div className="flex items-center justify-between gap-2 py-1 text-xs border-b border-border/50">
              <span className="text-muted-foreground italic">default</span>
              <Badge variant={modeBadge(defaultMode)}>{defaultMode}</Badge>
            </div>
          )}
          {toolNames.length === 0 ? (
            <p className="text-xs text-muted-foreground pt-2">
              No tools granted for this role.
            </p>
          ) : (
            toolNames.map((t) => {
              const tp = tools[t];
              const constraints = tp?.constraints ?? [];
              return (
                <div
                  key={t}
                  className="flex items-start justify-between gap-2 py-1 text-xs border-b border-border/50"
                >
                  <div className="min-w-0">
                    <span className="font-mono">{t}</span>
                    {constraints.length > 0 && (
                      <ul className="mt-0.5 text-[11px] text-muted-foreground font-mono space-y-0.5">
                        {constraints.map((c, i) => (
                          <li key={i}>{c}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <Badge variant={modeBadge(tp?.mode)}>{tp?.mode ?? "—"}</Badge>
                </div>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}

/** The resolved policy for one role, as a single YAML document. Drops the
 * catch-all `[key: string]` passthrough so only the real policy fields show. */
function dumpPolicy(policy: ResolvedPolicy[string] | undefined): string {
  if (!policy) return "# no policy for this role\n";
  const { default_policy, tools } = policy;
  const doc: Record<string, unknown> = {};
  if (default_policy) doc.default_policy = default_policy;
  doc.tools = tools ?? {};
  return dump(doc, { sortKeys: false, lineWidth: 100 });
}

function LintsTab({ lints }: { lints: PolicyLint[] }) {
  if (lints.length === 0) {
    return (
      <div className="h-full grid place-items-center px-6 text-center">
        <p className="text-xs text-muted-foreground">
          No lints — the policy composes cleanly.
        </p>
      </div>
    );
  }
  return (
    <div className="h-full overflow-y-auto scrollbar-thin p-3 space-y-1.5">
      {lints.map((l, i) => (
        <div
          key={i}
          className={cn(
            "rounded border p-2 text-xs",
            l.severity === "error"
              ? "border-deny/30 bg-deny/5"
              : l.severity === "warning"
                ? "border-approval/30 bg-approval/5"
                : "border-border bg-muted/30",
          )}
        >
          <div className="flex items-center gap-1.5">
            <span
              className={cn(
                "font-mono text-[10px] uppercase",
                l.severity === "error"
                  ? "text-deny"
                  : l.severity === "warning"
                    ? "text-approval"
                    : "text-muted-foreground",
              )}
            >
              {l.severity}
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              {l.code}
            </span>
          </div>
          <p className="mt-0.5 text-foreground/90">{l.message}</p>
          {(l.source || l.role || l.tool) && (
            <p className="mt-0.5 text-[10px] text-muted-foreground font-mono">
              {[
                l.role && `role:${l.role}`,
                l.source,
                l.tool && `tool:${l.tool}`,
              ]
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
