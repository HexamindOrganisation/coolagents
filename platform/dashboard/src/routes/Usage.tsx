import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownToLine,
  ArrowUpFromLine,
  Sigma,
} from "lucide-react";
import { endOfDay, format } from "date-fns";
import { api } from "@/lib/api";
import { useActive, useProjectScoped } from "@/lib/active";
import { useProjects } from "@/lib/projects";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { KpiCard } from "@/components/audit/pieces";
import { displayNoValue, scopeNoValue } from "@/components/audit/chart-tokens";
import { RANGE_DAYS, rangeDays } from "@/lib/date-range";
import {
  UsageActiveChips,
  UsageBreakdownCard,
  UsageFilterBar,
} from "@/components/usage/pieces";
import {
  type UsageFilters as Filters,
  useUsageFilters,
} from "@/lib/usage-filters";

const DATE_FMT = "MMM d, yyyy";

function impliedRangeLabel(range: Filters["range"]): string {
  const now = new Date();
  const start = new Date(now.getTime() - RANGE_DAYS[range] * 86_400_000);
  return `${format(start, DATE_FMT)} → ${format(now, DATE_FMT)}`;
}

// Compact token counts (1.2M / 84.6K) — KpiCard values elsewhere use
// toLocaleString() directly, but raw token counts run into the millions
// and read poorly uncompacted at this tile size.
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function UsagePage() {
  const projectScope = useProjectScoped();
  const projectId = projectScope.projectId;
  const activeOrgId = useActive((s) => s.activeOrgId);
  const projectsQ = useProjects(activeOrgId);
  const projectName =
    projectsQ.data?.find((p) => p.id === projectId)?.name ?? projectId;

  const f = useUsageFilters((s) => s.filters);
  const setF = useUsageFilters((s) => s.setFilters);
  const showDateRow = f.customMode;

  const scope = {
    window: f.range,
    agent: f.agent || undefined,
    model: f.model || undefined,
    user: scopeNoValue(f.user),
    start_date: f.start_date ? f.start_date.toISOString() : undefined,
    end_date: f.end_date ? f.end_date.toISOString() : undefined,
  };
  // Range-only (unscoped) summary: filter dropdown options + the "X of Y"
  // total — same dedup-via-matching-query-key trick as Audit's optionsQ.
  const optionsScope = {
    window: f.range,
    start_date: scope.start_date,
    end_date: scope.end_date,
  };
  const optionsQ = useQuery({
    queryKey: ["usage", "summary", projectId, optionsScope],
    enabled: !!projectId,
    queryFn: () => api.getLlmUsageSummary(optionsScope, projectId as string),
  });
  const summaryQ = useQuery({
    queryKey: ["usage", "summary", projectId, scope],
    enabled: !!projectId,
    queryFn: () => api.getLlmUsageSummary(scope, projectId as string),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });

  const totals = summaryQ.data?.totals ?? {
    calls: 0,
    input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
  };
  const options = optionsQ.data;
  const rangeTotal = options?.totals.calls ?? 0;

  const nDays = rangeDays(f.range, f.start_date, f.end_date);
  const avgLabel =
    !f.start_date && f.range === "24h"
      ? `${(totals.calls / 24).toFixed(1)}/hr avg`
      : `${(totals.calls / nDays).toFixed(0)}/day avg`;
  const inputPct = totals.total_tokens
    ? Math.round((totals.input_tokens / totals.total_tokens) * 100)
    : 0;
  const outputPct = totals.total_tokens
    ? Math.round((totals.output_tokens / totals.total_tokens) * 100)
    : 0;

  if (projectScope.status === "no-project") {
    return <NoProjectEmptyState resource="LLM usage" />;
  }

  return (
    <div className="mx-auto max-w-[1400px]">
      <header className="mb-6 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Usage</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            LLM token usage for project{" "}
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

      <UsageFilterBar
        f={f}
        setF={setF}
        shown={totals.calls}
        total={rangeTotal}
        agents={options?.by_agent.map((r) => r.key) ?? []}
        models={options?.by_model.map((r) => r.key) ?? []}
        users={options?.by_user.map((r) => displayNoValue(r).key) ?? []}
      />
      <UsageActiveChips f={f} setF={setF} />

      <div className="mb-4 grid grid-cols-4 gap-4">
        <KpiCard
          label="Calls"
          icon={Activity}
          value={totals.calls.toLocaleString()}
          sub={avgLabel}
        />
        <KpiCard
          label="Input tokens"
          icon={ArrowDownToLine}
          value={fmtTokens(totals.input_tokens)}
          sub={`${inputPct}% of total`}
        />
        <KpiCard
          label="Output tokens"
          icon={ArrowUpFromLine}
          value={fmtTokens(totals.output_tokens)}
          sub={`${outputPct}% of total`}
        />
        <KpiCard
          label="Total tokens"
          icon={Sigma}
          value={fmtTokens(totals.total_tokens)}
          sub={`${(totals.total_tokens / nDays).toFixed(0)}/day avg`}
        />
      </div>

      <UsageBreakdownCard
        byModel={summaryQ.data?.by_model ?? []}
        byAgent={summaryQ.data?.by_agent ?? []}
        byUser={summaryQ.data?.by_user.map(displayNoValue) ?? []}
        f={f}
        setF={setF}
      />
    </div>
  );
}
