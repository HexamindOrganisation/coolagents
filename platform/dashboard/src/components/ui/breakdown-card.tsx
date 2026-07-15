/**
 * Generic "ranked bar breakdown" card — a dimension-switching Tabs strip, a
 * metric/sort Select, a two-column grid of bar rows, an empty state, and a
 * footer legend. Shared by Audit's outcome-stacked breakdown and Usage's
 * single-metric breakdown; each caller supplies its own row markup via
 * `renderRow`, while the shell owns the filter-toggle click semantics so
 * it isn't reimplemented (and can't drift) per caller.
 */

import { Fragment, type ReactNode } from "react";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";

// ——— Bar row: label/value header + a track of one or more colored segments
export function BarRow({
  header,
  segments,
  widthPct,
  onClick,
  active,
}: {
  header: ReactNode;
  segments: { className: string; widthPct: number }[];
  widthPct: number;
  onClick?: () => void;
  active?: boolean;
}) {
  return (
    <div
      onClick={onClick}
      className={`mb-[11px] transition-opacity ${onClick ? "cursor-pointer" : ""} ${active === false ? "opacity-45" : ""}`}
    >
      <div className="mb-1 flex justify-between gap-2 text-[12.5px]">
        {header}
      </div>
      <div
        className="flex h-1.5 min-w-6 overflow-hidden rounded-[3px] bg-secondary"
        style={{ width: `${Math.max(widthPct, 4)}%` }}
      >
        {segments.map((s, i) => (
          <div
            key={i}
            className={s.className}
            style={{ width: `${s.widthPct}%` }}
          />
        ))}
      </div>
    </div>
  );
}

export function BreakdownCardShell<
  Dim extends string,
  Metric extends string,
  Row extends { key: string },
>({
  dims,
  dim,
  onDimChange,
  metric,
  metricOptions,
  onMetricChange,
  rows,
  renderRow,
  activeFilterValue,
  onFilterChange,
  emptyMessage,
  legend,
}: {
  dims: { id: Dim; label: string }[];
  dim: Dim;
  onDimChange: (d: Dim) => void;
  metric: Metric;
  metricOptions: { value: Metric; label: string }[];
  onMetricChange: (m: Metric) => void;
  rows: Row[];
  renderRow: (
    row: Row,
    opts: { active: boolean; onClick: () => void },
  ) => ReactNode;
  activeFilterValue: string;
  onFilterChange: (next: string) => void;
  emptyMessage: string;
  legend: ReactNode;
}) {
  return (
    <Card className="flex flex-col p-6">
      <div className="mb-4 flex items-center justify-between">
        <Tabs value={dim} onValueChange={(v) => onDimChange(v as Dim)}>
          <TabsList>
            {dims.map((d) => (
              <TabsTrigger key={d.id} value={d.id}>
                {d.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
        <Select
          value={metric}
          onValueChange={(v) => onMetricChange(v as Metric)}
        >
          <SelectTrigger className="h-7 w-auto gap-1.5 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {metricOptions.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="grid flex-1 grid-cols-2 gap-x-8">
        {rows.length ? (
          rows.map((row) => {
            const active = !activeFilterValue || activeFilterValue === row.key;
            const onClick = () =>
              onFilterChange(activeFilterValue === row.key ? "" : row.key);
            return (
              <Fragment key={row.key}>
                {renderRow(row, { active, onClick })}
              </Fragment>
            );
          })
        ) : (
          <div className="py-2 text-[12.5px] text-muted-foreground">
            {emptyMessage}
          </div>
        )}
      </div>
      <div className="mt-1 flex gap-3.5 border-t border-border pt-3 text-[11px] text-muted-foreground">
        {legend}
        <span className="ml-auto">click a bar to filter →</span>
      </div>
    </Card>
  );
}
