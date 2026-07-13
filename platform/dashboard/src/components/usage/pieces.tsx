import { useMemo, useState } from "react";
import { X } from "lucide-react";
import type { LlmInvocationBreakdownRow } from "@/lib/api";
import type {
  SetUsageFilters as SetFilters,
  UsageFilters as Filters,
} from "@/lib/usage-filters";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { BarRow, BreakdownCardShell } from "@/components/ui/breakdown-card";
import { FilterSelect } from "@/components/ui/filter-select";

// ————————————————————————————————————————————— Filter bar
export function UsageFilterBar({
  f,
  setF,
  shown,
  total,
  agents,
  models,
  users,
}: {
  f: Filters;
  setF: SetFilters;
  shown: number;
  total: number;
  agents: string[];
  models: string[];
  users: string[];
}) {
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) =>
    setF((p) => ({ ...p, [k]: v }));
  return (
    <div className="mb-3.5 flex flex-wrap items-center gap-2">
      <FilterSelect
        value={f.agent}
        all="All agents"
        opts={agents}
        onChange={(v) => set("agent", v)}
      />
      <FilterSelect
        value={f.model}
        all="All models"
        opts={models}
        onChange={(v) => set("model", v)}
      />
      <FilterSelect
        value={f.user}
        all="All users"
        opts={users}
        onChange={(v) => set("user", v)}
      />
      <span className="ml-auto whitespace-nowrap text-xs text-muted-foreground">
        <span className="text-foreground">{shown.toLocaleString()}</span> of{" "}
        <span className="font-mono">{total.toLocaleString()}</span> LLM calls
      </span>
    </div>
  );
}

export function UsageActiveChips({
  f,
  setF,
}: {
  f: Filters;
  setF: SetFilters;
}) {
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) =>
    setF((p) => ({ ...p, [k]: v }));
  const lbl: Record<string, string> = {
    agent: "agent",
    model: "model",
    user: "user",
  };
  const chips = (["agent", "model", "user"] as const).filter((k) => f[k]);
  if (!chips.length) return null;
  return (
    <div className="mb-4 flex flex-wrap items-center gap-1.5">
      <span className="text-[11.5px] text-muted-foreground">Filters</span>
      {chips.map((k) => (
        <Badge key={k} className="gap-1 pr-1 text-muted-foreground">
          {lbl[k]}: <span className="font-mono text-foreground">{f[k]}</span>
          <button
            onClick={() => set(k, "")}
            className="inline-flex cursor-pointer text-muted-foreground hover:text-foreground"
          >
            <X className="size-3" />
          </button>
        </Badge>
      ))}
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-2 text-xs"
        onClick={() =>
          setF((p) => ({
            ...p,
            agent: "",
            model: "",
            user: "",
            customMode: false,
            start_date: null,
            end_date: null,
          }))
        }
      >
        Clear all
      </Button>
    </div>
  );
}

// ————————————————————————————————————————————— Breakdown bar (single
// volume metric, no outcome mix — unlike audit/charts.tsx's BreakdownBar)
function UsageBar({
  row,
  max,
  metric,
  active,
  onClick,
}: {
  row: LlmInvocationBreakdownRow;
  max: number;
  metric: "total_tokens" | "calls";
  active?: boolean;
  onClick?: () => void;
}) {
  const value = row[metric];
  const widthPct = max ? (value / max) * 100 : 0;
  return (
    <BarRow
      onClick={onClick}
      active={active}
      widthPct={widthPct}
      header={
        <>
          <span className="truncate font-mono">{row.key}</span>
          <span className="shrink-0 text-foreground">
            {value.toLocaleString()}
          </span>
        </>
      }
      segments={[{ className: "bg-primary", widthPct: 100 }]}
    />
  );
}

// ————————————————————————————————————————————— Breakdown card
const DIMS = [
  { id: "model" as const, label: "Models" },
  { id: "agent" as const, label: "Agents" },
  { id: "user" as const, label: "Users" },
];

export function UsageBreakdownCard({
  byModel,
  byAgent,
  byUser,
  f,
  setF,
}: {
  byModel: LlmInvocationBreakdownRow[];
  byAgent: LlmInvocationBreakdownRow[];
  byUser: LlmInvocationBreakdownRow[];
  f: Filters;
  setF: SetFilters;
}) {
  const [dim, setDim] = useState<"model" | "agent" | "user">("model");
  const [metric, setMetric] = useState<"total_tokens" | "calls">(
    "total_tokens",
  );
  const source = dim === "model" ? byModel : dim === "agent" ? byAgent : byUser;
  const data = useMemo(() => {
    return source
      .slice()
      .sort((a, b) => b[metric] - a[metric])
      .slice(0, 10);
  }, [source, metric]);
  const max = Math.max(...data.map((d) => d[metric]), 1);
  const fkey = dim;

  return (
    <BreakdownCardShell
      dims={DIMS}
      dim={dim}
      onDimChange={setDim}
      metric={metric}
      metricOptions={[
        { value: "total_tokens", label: "by tokens" },
        { value: "calls", label: "by calls" },
      ]}
      onMetricChange={setMetric}
      emptyMessage="No LLM calls match."
      legend={
        <span className="flex items-center gap-1.5">
          <span className="size-2 rounded-sm bg-primary" />
          {metric === "total_tokens" ? "total tokens" : "calls"}
        </span>
      }
      rows={data.map((row) => (
        <UsageBar
          key={row.key}
          row={row}
          max={max}
          metric={metric}
          active={!f[fkey] || f[fkey] === row.key}
          onClick={() =>
            setF((p) => ({
              ...p,
              [fkey]: p[fkey] === row.key ? "" : row.key,
            }))
          }
        />
      ))}
    />
  );
}
