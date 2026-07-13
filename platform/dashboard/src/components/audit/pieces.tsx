import { useMemo, useState, type ComponentType } from "react";
import {
  Ban,
  Check,
  ChevronRight,
  CircleDashed,
  Download,
  List,
  TriangleAlert,
  X,
} from "lucide-react";
import type {
  AnomalySeverity,
  AuditAnomaly,
  AuditBreakdownRow,
  AuditDecisionRow,
  AuditOutcome,
} from "@/lib/api";
import type {
  AuditFilters as Filters,
  SetAuditFilters as SetFilters,
} from "@/lib/audit-filters";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Sparkline } from "@/components/ui/charts";
import { BreakdownCardShell } from "@/components/ui/breakdown-card";
import { BreakdownBar, type BreakdownDatum, DecisionBadge } from "./charts";
import { OUTCOME_SERIES } from "./chart-tokens";
import { fmtTs } from "./fmt";

// Map a server breakdown row ({key, all, ...}) to the chart datum ({total, ...}).
const toDatum = (r: AuditBreakdownRow): BreakdownDatum => ({
  key: r.key,
  total: r.all,
  allow: r.allow,
  deny: r.deny,
  needs_approval: r.needs_approval,
});

// Radix Select items can't carry value="" — UI-local stand-in for "all".
const ALL = "__all__";

// Module-level (not re-created per render). Exported — reused by the
// Usage page's filter bar (components/usage/pieces.tsx), which needs the
// same "select with an all-option" shape for agent/model/user.
export function FilterSelect({
  value,
  all,
  opts,
  onChange,
}: {
  value: string;
  all: string;
  opts: string[];
  onChange: (v: string) => void;
}) {
  return (
    <Select
      value={value || ALL}
      onValueChange={(v) => onChange(v === ALL ? "" : v)}
    >
      <SelectTrigger className="h-8 w-auto min-w-32 gap-1.5 text-[13px]">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{all}</SelectItem>
        {opts.map((o) => (
          <SelectItem key={o} value={o} className="font-mono text-xs">
            {o}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ————————————————————————————————————————————— Filter bar
export function FilterBar({
  f,
  setF,
  shown,
  total,
  agents,
  roles,
  tools,
}: {
  f: Filters;
  setF: SetFilters;
  shown: number;
  total: number;
  agents: string[];
  roles: string[];
  tools: string[];
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
        value={f.role}
        all="All roles"
        opts={roles}
        onChange={(v) => set("role", v)}
      />
      <FilterSelect
        value={f.tool}
        all="All tools"
        opts={tools}
        onChange={(v) => set("tool", v)}
      />
      <span className="ml-1 text-xs text-muted-foreground">Outcome</span>
      <ToggleGroup
        type="single"
        value={f.outcome || ALL}
        onValueChange={(v) =>
          set("outcome", !v || v === ALL ? "" : (v as AuditOutcome))
        }
      >
        <ToggleGroupItem value={ALL}>
          <List className="size-3" />
          All
        </ToggleGroupItem>
        <ToggleGroupItem
          value="allow"
          className="text-allow data-[state=on]:bg-allow/15 data-[state=on]:text-allow"
        >
          <Check className="size-3" strokeWidth={2} />
          allow
        </ToggleGroupItem>
        <ToggleGroupItem
          value="deny"
          className="text-deny data-[state=on]:bg-deny/15 data-[state=on]:text-deny"
        >
          <X className="size-3" strokeWidth={2} />
          deny
        </ToggleGroupItem>
        <ToggleGroupItem
          value="needs_approval"
          className="text-approval data-[state=on]:bg-approval/15 data-[state=on]:text-approval"
        >
          <CircleDashed className="size-3" strokeWidth={2} />
          approval
        </ToggleGroupItem>
      </ToggleGroup>
      <span className="ml-auto whitespace-nowrap text-xs text-muted-foreground">
        <span className="text-foreground">{shown.toLocaleString()}</span> of{" "}
        <span className="font-mono">{total.toLocaleString()}</span> decisions
      </span>
    </div>
  );
}

export function ActiveChips({ f, setF }: { f: Filters; setF: SetFilters }) {
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) =>
    setF((p) => ({ ...p, [k]: v }));
  const lbl: Record<string, string> = {
    agent: "agent",
    role: "role",
    tool: "tool",
    user: "user",
    outcome: "outcome",
  };
  const chips = (["agent", "role", "tool", "user", "outcome"] as const).filter(
    (k) => f[k],
  );
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
            role: "",
            tool: "",
            outcome: "",
            customMode: false,
            start_date: null,
            end_date: null,
            user: "",
          }))
        }
      >
        Clear all
      </Button>
    </div>
  );
}

// ————————————————————————————————————————————— KPI tile
export function KpiCard({
  label,
  icon: KpiIcon,
  value,
  sub,
  color,
  spark,
  sparkColor,
  showSpark,
  onClick,
  active,
}: {
  label: string;
  icon: ComponentType<{ className?: string }>;
  value: string;
  sub: string;
  color?: "allow" | "deny" | "approval";
  spark?: number[];
  sparkColor?: string;
  showSpark?: boolean;
  onClick?: () => void;
  active?: boolean;
}) {
  // Static map — Tailwind's scanner can't see interpolated class names.
  const valColor = {
    allow: "text-allow",
    deny: "text-deny",
    approval: "text-approval",
  };
  return (
    <Card
      onClick={onClick}
      className={`p-5 transition-colors ${onClick ? "cursor-pointer" : ""} ${active ? "border-primary/50" : ""}`}
    >
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <KpiIcon className="size-3.5" />
          <span>{label}</span>
        </div>
        <div
          className={`text-[28px] font-semibold leading-tight tracking-tight ${color ? valColor[color] : ""}`}
        >
          {value}
        </div>
        <div className="text-[11.5px] text-muted-foreground">{sub}</div>
        {showSpark && spark && (
          <div className="mt-1.5">
            <Sparkline data={spark} color={sparkColor} width={170} />
          </div>
        )}
      </div>
    </Card>
  );
}

// ————————————————————————————————————————————— Breakdown card
const DIMS = [
  { id: "tool" as const, label: "Tools", fkey: "tool" as const },
  { id: "agent" as const, label: "Agents", fkey: "agent" as const },
  { id: "role" as const, label: "Roles", fkey: "role" as const },
];

export function BreakdownCard({
  byTool,
  byAgent,
  byRole,
  f,
  setF,
}: {
  byTool: AuditBreakdownRow[];
  byAgent: AuditBreakdownRow[];
  byRole: AuditBreakdownRow[];
  f: Filters;
  setF: SetFilters;
}) {
  const [dim, setDim] = useState<"tool" | "agent" | "role">("tool");
  const [sort, setSort] = useState<"volume" | "denials">("volume");
  const source = dim === "tool" ? byTool : dim === "agent" ? byAgent : byRole;
  const data = useMemo(() => {
    let d = source.map(toDatum);
    if (sort === "denials")
      d = d.slice().sort((a, b) => b.deny - a.deny || b.total - a.total);
    return d.slice(0, 10);
  }, [source, sort]);
  const max = Math.max(...data.map((d) => d.total), 1);
  const fkey = dim;

  return (
    <BreakdownCardShell
      dims={DIMS}
      dim={dim}
      onDimChange={setDim}
      metric={sort}
      metricOptions={[
        { value: "volume", label: "by volume" },
        { value: "denials", label: "by denials" },
      ]}
      onMetricChange={setSort}
      emptyMessage="No decisions match."
      legend={
        <>
          {OUTCOME_SERIES.map((s) => (
            <span key={s.key} className="flex items-center gap-1.5">
              <span className={`size-2 rounded-sm ${s.swatchClass}`} />
              {s.label}
            </span>
          ))}
        </>
      }
      rows={data.map((row) => (
        <BreakdownBar
          key={row.key}
          label={row.key}
          row={row}
          max={max}
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

// ————————————————————————————————————————————— Events table
export function EventsTable({
  rows,
  total,
  onSelect,
  selectedId,
  onLoadMore,
  loadingMore,
  onExport,
}: {
  rows: AuditDecisionRow[];
  total: number;
  onSelect: (e: AuditDecisionRow) => void;
  selectedId?: string | null;
  onLoadMore: () => void;
  loadingMore?: boolean;
  onExport?: () => void;
}) {
  return (
    <Card className="overflow-hidden p-0">
      <div className="flex items-center justify-between border-b border-border px-5 py-4">
        <div>
          <div className="text-[15px] font-semibold">Decisions</div>
          <div className="mt-0.5 text-xs text-muted-foreground">
            Newest first · ordered by{" "}
            <span className="font-mono">occurred_at</span>. Click a row to
            inspect.
          </div>
        </div>
        <Button variant="ghost" onClick={onExport} disabled={!onExport}>
          <Download className="size-3.5" />
          Export JSONL
        </Button>
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[168px]">Time</TableHead>
              <TableHead>Agent</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Tool</TableHead>
              <TableHead className="w-[110px]">Outcome</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead className="w-[30px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((e) => (
              <TableRow
                key={e.event_id}
                onClick={() => onSelect(e)}
                className={`cursor-pointer ${selectedId === e.event_id ? "bg-primary/10 hover:bg-primary/10" : ""}`}
              >
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {fmtTs(new Date(e.occurred_at))}
                </TableCell>
                <TableCell className="font-mono text-[12.5px]">
                  {e.agent_name}
                </TableCell>
                <TableCell className={e.role ? "" : "text-muted-foreground"}>
                  {e.role || "—"}
                </TableCell>
                <TableCell className="font-mono text-[12.5px]">
                  {e.tool_name}
                </TableCell>
                <TableCell>
                  <DecisionBadge d={e.outcome} />
                </TableCell>
                <TableCell className="max-w-80 overflow-hidden text-ellipsis whitespace-nowrap text-[12.5px] text-muted-foreground">
                  {e.reason || "—"}
                </TableCell>
                <TableCell>
                  <ChevronRight className="size-3.5 text-muted-foreground" />
                </TableCell>
              </TableRow>
            ))}
            {!rows.length && (
              <TableRow>
                <TableCell
                  colSpan={7}
                  className="py-8 text-center text-muted-foreground"
                >
                  No decisions match the current filters.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {rows.length < total && (
        <div className="border-t border-border px-5 py-3 text-center">
          <Button
            variant="secondary"
            size="sm"
            onClick={onLoadMore}
            disabled={loadingMore}
          >
            {loadingMore
              ? "Loading…"
              : `Load 40 more · ${(total - rows.length).toLocaleString()} remaining`}
          </Button>
        </div>
      )}
    </Card>
  );
}

// ————————————————————————————————————————————— Anomalies card

function fmtBurst(first: string, last: string): string {
  const f = new Date(first);
  const l = new Date(last);
  const date = (d: Date) =>
    d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  const time = (d: Date) =>
    d.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  return date(f) === date(l)
    ? `${date(f)}, ${time(f)} → ${time(l)}`
    : `${date(f)}, ${time(f)} → ${date(l)}, ${time(l)}`;
}

function SeverityBadge({ severity }: { severity: AnomalySeverity }) {
  return severity === "high" ? (
    <Badge className="bg-deny/15 text-deny hover:bg-deny/15">High</Badge>
  ) : (
    <Badge className="bg-approval/15 text-approval hover:bg-approval/15">
      Medium
    </Badge>
  );
}

export function AnomaliesCard({
  rows,
  onRowClick,
  onBanUser,
}: {
  rows: AuditAnomaly[];
  onRowClick: (from: Date, to: Date, userId: string) => void;
  /** When set, each row gets a "Ban user" action (admins only — the caller
   * gates on role). Undefined hides the column entirely. */
  onBanUser?: (userId: string) => void;
}) {
  return (
    <Card className="overflow-hidden p-0">
      <div className="flex items-center gap-2 border-b border-border px-5 py-4">
        <TriangleAlert className="size-4 text-approval" />
        <div className="text-[15px] font-semibold">
          Anomalies · {rows.length} detected
        </div>
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[90px]">Severity</TableHead>
              <TableHead>User</TableHead>
              <TableHead className="w-[80px]">Denies</TableHead>
              <TableHead className="w-[90px]">Deny rate</TableHead>
              <TableHead>When</TableHead>
              {onBanUser && <TableHead className="w-[110px]" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow
                key={`${row.user_id}-${row.first_seen}`}
                className="cursor-pointer"
                onClick={() =>
                  onRowClick(
                    new Date(row.first_seen),
                    new Date(row.last_seen),
                    row.user_id,
                  )
                }
              >
                <TableCell>
                  <SeverityBadge severity={row.severity} />
                </TableCell>
                <TableCell className="font-mono text-[12.5px]">
                  {row.user_id}
                </TableCell>
                <TableCell>
                  {row.deny}
                  <span className="ml-1 text-xs text-muted-foreground">
                    / {row.all}
                  </span>
                </TableCell>
                <TableCell>{(row.deny_rate * 100).toFixed(0)}%</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {fmtBurst(row.first_seen, row.last_seen)}
                </TableCell>
                {onBanUser && (
                  <TableCell className="text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="gap-1.5 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                      onClick={(e) => {
                        e.stopPropagation();
                        onBanUser(row.user_id);
                      }}
                    >
                      <Ban className="size-3.5" />
                      Ban user
                    </Button>
                  </TableCell>
                )}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
}
