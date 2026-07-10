import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api, type AuditWindow, type BanEnforcementRow } from "@/lib/api";
import { BanTypeBadge } from "./BanTypeBadge";
import { BlockedAttemptDrawer } from "./BlockedAttemptDrawer";
import { PAGE_SIZE, WINDOWS } from "./constants";
import { formatAbsolute, formatRelative } from "./format";

/**
 * Region C (§9.3) — the secondary panel. A feed of runs refused by a
 * ban, before the model ran. Sourced from the dedicated
 * `ban_enforcement` ClickHouse table (§4.9), NOT the tool-decision
 * Audit log — hence the caption disambiguating the two.
 *
 * Window selector (24h / 7d / 30d / 90d) on the right; paged with a
 * "Load more" that grows `limit`. Both the window and the limit are in
 * the React Query key so each view caches independently.
 */
export function BlockedAttemptsPanel({ projectId }: { projectId: string }) {
  const [timeWindow, setTimeWindow] = useState<AuditWindow>("24h");
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [selected, setSelected] = useState<BanEnforcementRow | null>(null);

  const feedQuery = useQuery({
    queryKey: ["ban-enforcements", projectId, timeWindow, limit],
    queryFn: () =>
      api.listBanEnforcements(
        { window: timeWindow, limit, offset: 0 },
        projectId,
      ),
  });

  const rows: BanEnforcementRow[] = feedQuery.data?.rows ?? [];
  const total = feedQuery.data?.total ?? 0;
  const remaining = Math.max(total - rows.length, 0);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
        <div>
          <div className="text-sm font-medium">Blocked attempts</div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">
            Runs refused by a ban, before the model ran. Separate from the Audit
            log.
          </div>
        </div>
        <ToggleGroup
          type="single"
          value={timeWindow}
          onValueChange={(v) => v && setTimeWindow(v as AuditWindow)}
        >
          {WINDOWS.map((w) => (
            <ToggleGroupItem key={w} value={w} className="text-xs">
              {w}
            </ToggleGroupItem>
          ))}
        </ToggleGroup>
      </div>

      {feedQuery.isLoading ? (
        <div className="p-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : rows.length === 0 ? (
        <div className="py-14 text-center text-sm text-muted-foreground">
          No blocked attempts in this window.
        </div>
      ) : (
        <>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-5 py-2.5 text-left font-medium">Time</th>
                <th className="px-5 py-2.5 text-left font-medium">Type</th>
                <th className="px-5 py-2.5 text-left font-medium">Target</th>
                <th className="px-5 py-2.5 text-left font-medium">Reason</th>
                <th className="px-5 py-2.5 text-left font-medium">Ban id</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.event_id}
                  onClick={() => setSelected(r)}
                  className="cursor-pointer border-b border-border/50 last:border-0 hover:bg-accent/40"
                >
                  <td
                    className="px-5 py-3 text-[13px] text-muted-foreground"
                    title={formatAbsolute(r.occurred_at)}
                  >
                    {formatRelative(r.occurred_at)}
                  </td>
                  <td className="px-5 py-3">
                    <BanTypeBadge type={r.ban_type} />
                  </td>
                  <td className="px-5 py-3 font-mono text-xs">
                    {r.ban_type === "agent" ? r.agent_name : r.user_id}
                  </td>
                  <td
                    className="max-w-[300px] truncate px-5 py-3 text-muted-foreground"
                    title={r.reason || undefined}
                  >
                    {r.reason || "—"}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-muted-foreground">
                    {r.ban_id}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length < total && (
            <div className="border-t border-border px-5 py-3 text-center">
              <Button
                variant="secondary"
                size="sm"
                disabled={feedQuery.isFetching}
                onClick={() => setLimit((l) => l + PAGE_SIZE)}
              >
                {feedQuery.isFetching
                  ? "Loading…"
                  : `Load ${PAGE_SIZE} more · ${remaining.toLocaleString()} remaining`}
              </Button>
            </div>
          )}
        </>
      )}

      <BlockedAttemptDrawer
        event={selected}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}
