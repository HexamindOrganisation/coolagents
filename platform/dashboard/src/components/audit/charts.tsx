/**
 * Audit-specific chart pieces. The reusable SVG primitives (AreaChart,
 * Donut, Sparkline) live in ``components/ui/charts.tsx``; what stays here
 * is bound to the allow/deny/needs_approval outcome domain.
 */

import { Check, CircleDashed, X } from "lucide-react";
import type { AuditOutcome } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { BarRow } from "@/components/ui/breakdown-card";
import { OUT_LABEL } from "./chart-tokens";

export interface Counts {
  allow: number;
  deny: number;
  needs_approval: number;
  total: number;
}

export interface BreakdownDatum extends Counts {
  key: string;
}

export function DecisionBadge({ d }: { d: AuditOutcome }) {
  const OutcomeIcon = d === "allow" ? Check : d === "deny" ? X : CircleDashed;
  return (
    <Badge variant={d === "needs_approval" ? "approval" : d}>
      <OutcomeIcon className="size-3" strokeWidth={2} />
      {OUT_LABEL[d]}
    </Badge>
  );
}

// ——— Stacked breakdown bar row (allow/approval/deny, deny emphasised) ———
export function BreakdownBar({
  label,
  row,
  max,
  onClick,
  active,
}: {
  label: string;
  row: BreakdownDatum;
  max: number;
  onClick?: () => void;
  active?: boolean;
}) {
  const seg = (k: AuditOutcome) => (row.total ? (row[k] / row.total) * 100 : 0);
  const widthPct = max ? (row.total / max) * 100 : 0;
  return (
    <BarRow
      onClick={onClick}
      active={active}
      widthPct={widthPct}
      header={
        <>
          <span className="truncate font-mono">{label}</span>
          <span className="shrink-0 text-muted-foreground">
            {row.deny > 0 && (
              <span className="mr-2 text-deny">{row.deny} denied</span>
            )}
            <span className="text-foreground">
              {row.total.toLocaleString()}
            </span>
          </span>
        </>
      }
      segments={[
        { className: "bg-allow", widthPct: seg("allow") },
        { className: "bg-approval", widthPct: seg("needs_approval") },
        { className: "bg-deny", widthPct: seg("deny") },
      ]}
    />
  );
}
