import { useEffect, useMemo, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Activity,
  Check,
  CircleDashed,
  Filter,
  Lightbulb,
  X,
} from "lucide-react";
import { endOfDay, format, startOfDay } from "date-fns";
import { useNavigate } from "react-router-dom";
import { api, type AuditDecisionRow, type AuditOutcome } from "@/lib/api";
import { useActive, useProjectScoped } from "@/lib/active";
import { useCanManageBans } from "@/lib/bans";
import { useProjects } from "@/lib/projects";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { AreaChart, type ChartBucket, Donut } from "@/components/ui/charts";
import { type Counts, DecisionBadge } from "@/components/audit/charts";
import {
  displayNoValue,
  OUT_LABEL,
  OUTCOME_SERIES,
  scopeNoValue,
} from "@/components/audit/chart-tokens";
import {
  RANGE_DAYS,
  type AuditFilters as Filters,
  useAuditFilters,
} from "@/lib/audit-filters";
import { rangeDays } from "@/lib/date-range";
import { fmtTs } from "@/components/audit/fmt";
import {
  ActiveChips,
  AnomaliesCard,
  BreakdownCard,
  EventsTable,
  FilterBar,
  KpiCard,
} from "@/components/audit/pieces";

const DATE_FMT = "MMM d, yyyy";

function impliedRangeLabel(range: Filters["range"]): string {
  const now = new Date();
  const start = new Date(now.getTime() - RANGE_DAYS[range] * 86_400_000);
  return `${format(start, DATE_FMT)} → ${format(now, DATE_FMT)}`;
}

const ZERO_COUNTS: Counts = { allow: 0, deny: 0, needs_approval: 0, total: 0 };

const fmtFull = (d: Date) =>
  d.toISOString().replace("T", " ").replace("Z", " UTC");

// ————————————————————————————————————————————— Detail drawer
function KV({
  k,
  children,
  mono,
  muted,
}: {
  k: string;
  children: React.ReactNode;
  mono?: boolean;
  muted?: boolean;
}) {
  return (
    <div className="grid grid-cols-[116px_1fr] items-baseline gap-2.5 py-[5px] text-[12.5px]">
      <div className="text-muted-foreground">{k}</div>
      <div
        className={`break-words ${mono ? "font-mono text-xs" : ""} ${muted ? "text-muted-foreground" : "text-foreground"}`}
      >
        {children}
      </div>
    </div>
  );
}
function DrawerSection({
  label,
  children,
  accent,
}: {
  label: string;
  children: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="mt-[22px]">
      <div
        className={`mb-2 text-[11px] font-medium uppercase tracking-wider ${accent || "text-muted-foreground"}`}
      >
        {label}
      </div>
      {children}
    </div>
  );
}

// Per-outcome drawer accents (reason box + error text).
const TONE: Record<AuditOutcome, { text: string; box: string }> = {
  allow: { text: "text-allow", box: "border-allow/25 bg-allow/10" },
  deny: { text: "text-deny", box: "border-deny/25 bg-deny/10" },
  needs_approval: {
    text: "text-approval",
    box: "border-approval/25 bg-approval/10",
  },
};

function DetailDrawer({
  event,
  related,
  onClose,
  onSelect,
  setF,
}: {
  event: AuditDecisionRow | null;
  related: AuditDecisionRow[];
  onClose: () => void;
  onSelect: (e: AuditDecisionRow) => void;
  setF: (u: (p: Filters) => Filters) => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  if (!event) return null;
  const e = event;
  const argStr =
    e.arguments == null ? "—" : JSON.stringify(e.arguments, null, 2);
  const hintStr =
    typeof e.hint === "string"
      ? e.hint
      : e.hint == null
        ? ""
        : JSON.stringify(e.hint);
  const tone = TONE[e.outcome];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        onClick={onClose}
        className="absolute inset-0 bg-black/55 backdrop-blur-[1px]"
      />
      <aside className="relative flex h-full w-[472px] max-w-[92vw] flex-col border-l border-border bg-card shadow-2xl">
        <div className="flex items-center gap-2.5 border-b border-border px-5 py-4">
          <DecisionBadge d={e.outcome} />
          <span className="flex-1 truncate font-mono text-xs text-muted-foreground">
            {e.event_id}
          </span>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
            title="Close (Esc)"
          >
            <X className="size-4" />
          </Button>
        </div>

        <div className="flex-1 overflow-auto px-5 pb-6 pt-1 scrollbar-thin">
          <div className="mt-[18px] flex flex-wrap items-baseline gap-2">
            <span className="font-mono text-[17px] font-semibold text-foreground">
              {e.tool_name}
            </span>
            <span className="text-[13px] text-muted-foreground">by</span>
            <span className="font-mono text-sm text-foreground">
              {e.agent_name}
            </span>
          </div>
          <div
            className={`mt-2 rounded-lg border px-3 py-2.5 text-[13px] leading-relaxed text-foreground ${tone.box}`}
          >
            {e.reason ||
              (e.outcome === "allow"
                ? "Allowed — no rule violated."
                : "No reason recorded.")}
            {e.error_type && (
              <span
                className={`mt-1.5 block font-mono text-[11.5px] ${tone.text}`}
              >
                error_type: {e.error_type}
              </span>
            )}
          </div>

          {e.violations.length > 0 && (
            <DrawerSection label="Violations" accent="text-deny">
              <div className="flex flex-wrap gap-1.5">
                {e.violations.map((v) => (
                  <span
                    key={v}
                    className="rounded-md bg-deny/15 px-2 py-[3px] font-mono text-[11.5px] text-deny"
                  >
                    {v}
                  </span>
                ))}
              </div>
            </DrawerSection>
          )}

          {hintStr && (
            <DrawerSection label="Policy hint">
              <div className="flex items-center gap-2 rounded-md border border-border bg-muted px-3 py-2.5 font-mono text-xs">
                <Lightbulb className="size-3.5 shrink-0 text-approval" />
                <span className="text-foreground">{hintStr}</span>
              </div>
            </DrawerSection>
          )}

          <DrawerSection label="Decision">
            <KV k="outcome">{OUT_LABEL[e.outcome]}</KV>
            <KV k="tool_name" mono>
              {e.tool_name}
            </KV>
            <KV k="role">
              {e.role || <span className="text-muted-foreground">∅ none</span>}
            </KV>
            {e.error_type && (
              <KV k="error_type" mono>
                {e.error_type}
              </KV>
            )}
          </DrawerSection>

          <DrawerSection label="Arguments">
            <pre className="m-0 whitespace-pre-wrap rounded-lg border border-border bg-muted p-3 font-mono text-[11.5px] leading-relaxed text-foreground">
              {argStr}
            </pre>
          </DrawerSection>

          <DrawerSection label="Envelope">
            <KV k="occurred_at" mono>
              {fmtFull(new Date(e.occurred_at))}
            </KV>
            <KV k="received_at" mono muted>
              {fmtFull(new Date(e.received_at))}
            </KV>
            <KV k="agent_name" mono>
              {e.agent_name}
            </KV>
            <KV k="session_id" mono muted>
              {e.session_id || "∅"}
            </KV>
            <KV k="user_id" mono muted>
              {e.user_id || "∅"}
            </KV>
          </DrawerSection>

          <DrawerSection label={`Same session · ${related.length}`}>
            {related.length ? (
              <div className="overflow-hidden rounded-lg border border-border">
                {related.map((r, i) => (
                  <div
                    key={r.event_id}
                    onClick={() => onSelect(r)}
                    className={`flex cursor-pointer items-center gap-2 px-2.5 py-2 text-xs hover:bg-accent ${i < related.length - 1 ? "border-b border-border" : ""}`}
                  >
                    <DecisionBadge d={r.outcome} />
                    <span className="flex-1 truncate font-mono">
                      {r.tool_name}
                    </span>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {fmtTs(new Date(r.occurred_at))}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-muted-foreground">
                No other events in this session.
              </div>
            )}
          </DrawerSection>
        </div>

        <div className="flex gap-2 border-t border-border px-5 py-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setF((p) => ({ ...p, agent: e.agent_name }));
              onClose();
            }}
          >
            <Filter className="size-3" />
            Filter to agent
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              setF((p) => ({ ...p, tool: e.tool_name }));
              onClose();
            }}
          >
            <Filter className="size-3" />
            Filter to tool
          </Button>
        </div>
      </aside>
    </div>
  );
}

// ————————————————————————————————————————————— Root
export function AuditPage() {
  const projectScope = useProjectScoped();
  const projectId = projectScope.projectId;
  const activeOrgId = useActive((s) => s.activeOrgId);
  const navigate = useNavigate();
  const canManageBans = useCanManageBans();
  // Resolve the active project's display name for the page subtitle
  // (already cached by the AppShell bootstrap; falls back to the id).
  const projectsQ = useProjects(activeOrgId);
  const projectName =
    projectsQ.data?.find((p) => p.id === projectId)?.name ?? projectId;
  // Filter + paging state lives in a zustand store (see lib/audit-filters)
  // so the dialled-in slice survives route switches; drawer selection is
  // ephemeral and stays local.
  const f = useAuditFilters((s) => s.filters);
  const setF = useAuditFilters((s) => s.setFilters);
  const tableLimit = useAuditFilters((s) => s.tableLimit);
  const loadMore = useAuditFilters((s) => s.loadMore);
  const [sel, setSel] = useState<AuditDecisionRow | null>(null);
  const showDateRow = f.customMode;

  // UI state → wire: '' = "all" locally, so unset filters are omitted
  // (undefined). The "(none)" label (role/user) maps back to '' — the
  // wire's no-value bucket; no sentinel string leaves the dashboard.
  const scope = {
    window: f.range,
    agent: f.agent || undefined,
    role: scopeNoValue(f.role),
    tool: f.tool || undefined,
    start_date: f.start_date ? f.start_date.toISOString() : undefined,
    end_date: f.end_date ? f.end_date.toISOString() : undefined,
    user: scopeNoValue(f.user),
  };

  // Range-only (unscoped) summary: filter dropdown options + the "X of Y"
  // total. Shares the summaryQ key shape on purpose: React Query's key hash
  // drops undefined values, so when no filter is set this key hashes equal
  // to summaryQ's and both dedupe into ONE fetch + cache entry; with a
  // filter active the keys diverge and the second request is real.
  const optionsScope = {
    window: f.range,
    start_date: scope.start_date,
    end_date: scope.end_date,
  };
  const optionsQ = useQuery({
    queryKey: ["audit", "summary", projectId, optionsScope],
    enabled: !!projectId,
    queryFn: () => api.getAuditSummary(optionsScope, projectId as string),
  });
  // Scoped summary/timeseries: KPIs, donut, area, breakdown.
  const summaryQ = useQuery({
    queryKey: ["audit", "summary", projectId, scope],
    enabled: !!projectId,
    queryFn: () => api.getAuditSummary(scope, projectId as string),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const tsQ = useQuery({
    queryKey: ["audit", "ts", projectId, scope],
    enabled: !!projectId,
    queryFn: () => api.getAuditTimeseries(scope, projectId as string),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const listFilters = {
    ...scope,
    outcome: f.outcome || undefined,
    limit: tableLimit,
  };
  const listQ = useQuery({
    queryKey: ["audit", "list", projectId, listFilters],
    enabled: !!projectId,
    queryFn: () => api.listAuditDecisions(listFilters, projectId as string),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });
  const relatedQ = useQuery({
    queryKey: ["audit", "session", projectId, f.range, sel?.session_id],
    enabled: !!sel?.session_id && !!projectId,
    queryFn: () =>
      api.listAuditDecisions(
        { window: f.range, session_id: sel!.session_id, limit: 12 },
        projectId as string,
      ),
  });
  // Intentionally excludes user/agent/role/tool: the anomaly endpoint ranks
  // all users and must not be pre-filtered to a single one.
  const anomalyScope = {
    window: scope.window,
    start_date: scope.start_date,
    end_date: scope.end_date,
  };
  const anomaliesQ = useQuery({
    queryKey: ["audit", "anomalies", projectId, anomalyScope],
    enabled: !!projectId,
    queryFn: () => api.getAuditAnomalies(anomalyScope, projectId as string),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });

  const summary = summaryQ.data;
  const counts: Counts = summary
    ? {
        allow: summary.totals.allow,
        deny: summary.totals.deny,
        needs_approval: summary.totals.needs_approval,
        total: summary.totals.all,
      }
    : ZERO_COUNTS;

  const days: ChartBucket[] = useMemo(
    () =>
      (tsQ.data ?? []).map((p) => ({
        label: new Date(p.bucket),
        mode: f.range === "24h" ? "hour" : "day",
        values: {
          allow: p.allow,
          deny: p.deny,
          needs_approval: p.needs_approval,
        },
        total: p.allow + p.deny + p.needs_approval,
      })),
    [tsQ.data, f.range],
  );
  const spark = useMemo(
    () => ({
      total: days.map((d) => d.total),
      allow: days.map((d) => d.values.allow),
      deny: days.map((d) => d.values.deny),
      needs_approval: days.map((d) => d.values.needs_approval),
    }),
    [days],
  );

  const denyRate = counts.total
    ? ((counts.deny / counts.total) * 100).toFixed(1)
    : "0.0";
  const allowPct = counts.total
    ? Math.round((counts.allow / counts.total) * 100)
    : 0;
  const apprPct = counts.total
    ? Math.round((counts.needs_approval / counts.total) * 100)
    : 0;
  const nDays = rangeDays(f.range, f.start_date, f.end_date);
  const avgLabel =
    !f.start_date && f.range === "24h"
      ? `${(counts.total / 24).toFixed(1)}/hr avg`
      : `${(counts.total / nDays).toFixed(0)}/day avg`;
  const setOutcome = (o: AuditOutcome) =>
    setF((p) => ({ ...p, outcome: p.outcome === o ? "" : o }));

  const options = optionsQ.data;
  const rangeTotal = options?.totals.all ?? 0;
  const related = (relatedQ.data?.rows ?? [])
    .filter((r) => r.event_id !== sel?.event_id)
    .slice(0, 6);

  // Exports the LOADED page only (up to tableLimit ≤ 200 rows), not every
  // row matching the filters — "export everything" would need a streaming
  // server-side endpoint, not a client-side blob.
  const exportJsonl = () => {
    const rows = listQ.data?.rows ?? [];
    if (!rows.length) return;
    const blob = new Blob([rows.map((r) => JSON.stringify(r)).join("\n")], {
      type: "application/x-ndjson",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "decisions.jsonl";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (projectScope.status === "no-project") {
    return <NoProjectEmptyState resource="audit events" />;
  }

  return (
    <>
      <div className="mx-auto max-w-[1400px]">
        <header className="mb-6 flex items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Audit</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Every policy decision for project{" "}
              <span className="font-mono text-foreground">{projectName}</span>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <ToggleGroup
              type="single"
              value={f.customMode ? "custom" : f.range}
              onValueChange={(v) => {
                if (!v) return;
                if (v === "custom") {
                  setF((p) => ({ ...p, customMode: true }));
                } else {
                  setF((p) => ({
                    ...p,
                    range: v as Filters["range"],
                    customMode: false,
                    start_date: null,
                    end_date: null,
                  }));
                }
              }}
            >
              {(["24h", "7d", "30d", "90d"] as const).map((r) => (
                <ToggleGroupItem key={r} value={r}>
                  {r}
                </ToggleGroupItem>
              ))}
              <ToggleGroupItem value="custom">Custom</ToggleGroupItem>
            </ToggleGroup>
            {showDateRow && (
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className="h-8 text-[13px] font-normal"
                  >
                    {f.start_date && f.end_date
                      ? `${format(f.start_date, DATE_FMT)} → ${format(f.end_date, DATE_FMT)}`
                      : f.start_date
                        ? `${format(f.start_date, DATE_FMT)} → …`
                        : impliedRangeLabel(f.range)}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-0" align="end">
                  <Calendar
                    mode="range"
                    selected={{
                      from: f.start_date ?? undefined,
                      to: f.end_date ?? undefined,
                    }}
                    onSelect={(range) =>
                      setF((p) => ({
                        ...p,
                        start_date: range?.from ?? null,
                        end_date: range?.to ? endOfDay(range.to) : null,
                      }))
                    }
                  />
                </PopoverContent>
              </Popover>
            )}
          </div>
        </header>

        <FilterBar
          f={f}
          setF={setF}
          shown={listQ.data?.total ?? 0}
          total={rangeTotal}
          agents={options?.by_agent.map((r) => r.key) ?? []}
          roles={options?.by_role.map((r) => displayNoValue(r).key) ?? []}
          tools={options?.by_tool.map((r) => r.key) ?? []}
        />
        <ActiveChips f={f} setF={setF} />

        <div className="mb-4 grid grid-cols-4 gap-4">
          <KpiCard
            label="Decisions"
            icon={Activity}
            value={counts.total.toLocaleString()}
            sub={avgLabel}
            spark={spark.total}
            sparkColor="hsl(var(--primary))"
            showSpark
          />
          <KpiCard
            label="Allowed"
            icon={Check}
            value={counts.allow.toLocaleString()}
            color="allow"
            sub={`${allowPct}% of decisions`}
            spark={spark.allow}
            sparkColor="hsl(var(--semantic-allow))"
            showSpark
            onClick={() => setOutcome("allow")}
            active={f.outcome === "allow"}
          />
          <KpiCard
            label="Denied"
            icon={X}
            value={counts.deny.toLocaleString()}
            color="deny"
            sub={`${denyRate}% deny rate`}
            spark={spark.deny}
            sparkColor="hsl(var(--semantic-deny))"
            showSpark
            onClick={() => setOutcome("deny")}
            active={f.outcome === "deny"}
          />
          <KpiCard
            label="Needs approval"
            icon={CircleDashed}
            value={counts.needs_approval.toLocaleString()}
            color="approval"
            sub={`${apprPct}% of decisions`}
            spark={spark.needs_approval}
            sparkColor="hsl(var(--semantic-approval))"
            showSpark
            onClick={() => setOutcome("needs_approval")}
            active={f.outcome === "needs_approval"}
          />
        </div>

        <div className="mb-4 grid grid-cols-[1.55fr_1fr] gap-4">
          <Card className="p-6">
            <div className="mb-3.5 flex items-center justify-between">
              <div className="text-[13px] font-medium text-muted-foreground">
                Decisions over time
              </div>
              <div className="flex gap-3.5 text-[11px] text-muted-foreground">
                {OUTCOME_SERIES.map((s) => (
                  <span key={s.key} className="flex items-center gap-1.5">
                    <span className={`size-2 rounded-sm ${s.swatchClass}`} />
                    {s.label}
                  </span>
                ))}
              </div>
            </div>
            {days.length ? (
              <AreaChart buckets={days} series={OUTCOME_SERIES} />
            ) : (
              <div className="flex h-60 items-center justify-center text-[13px] text-muted-foreground">
                No decisions in this range.
              </div>
            )}
          </Card>
          <Card className="p-6">
            <div className="mb-4 text-[13px] font-medium text-muted-foreground">
              Outcome breakdown
            </div>
            <Donut
              values={{ ...counts }}
              total={counts.total}
              series={OUTCOME_SERIES}
              caption="decisions"
            />
          </Card>
        </div>

        {!!anomaliesQ.data?.length && (
          <div className="mb-4">
            <AnomaliesCard
              rows={anomaliesQ.data}
              onRowClick={(from, to, userId) =>
                setF((p) => ({
                  ...p,
                  customMode: true,
                  start_date: startOfDay(from),
                  end_date: endOfDay(to),
                  user: userId,
                }))
              }
              onBanUser={
                canManageBans
                  ? (userId) =>
                      navigate(`/bans?ban_user=${encodeURIComponent(userId)}`)
                  : undefined
              }
            />
          </div>
        )}

        <div className="mb-4">
          <BreakdownCard
            byTool={summary?.by_tool ?? []}
            byAgent={summary?.by_agent ?? []}
            byRole={summary?.by_role.map(displayNoValue) ?? []}
            f={f}
            setF={setF}
          />
        </div>

        <EventsTable
          rows={listQ.data?.rows ?? []}
          total={listQ.data?.total ?? 0}
          onSelect={setSel}
          selectedId={sel?.event_id}
          onLoadMore={loadMore}
          loadingMore={listQ.isFetching}
          onExport={exportJsonl}
        />
      </div>

      <DetailDrawer
        event={sel}
        related={related}
        onClose={() => setSel(null)}
        onSelect={setSel}
        setF={setF}
      />
    </>
  );
}
