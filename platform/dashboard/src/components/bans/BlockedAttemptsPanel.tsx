import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";

import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { api, type AuditWindow, type BanEnforcementRow } from "@/lib/api";
import { BanTypeBadge } from "./BanTypeBadge";
import { BlockedAttemptDrawer } from "./BlockedAttemptDrawer";
import { PAGE_SIZE, WINDOWS } from "./constants";
import { formatAbsolute, formatRelative } from "./format";

/** Keep the first occurrence of each event_id, preserving order. */
function dedupById(rows: BanEnforcementRow[]): BanEnforcementRow[] {
  const seen = new Set<string>();
  return rows.filter((r) =>
    seen.has(r.event_id) ? false : (seen.add(r.event_id), true),
  );
}

/**
 * Region C (§9.3) — the secondary panel. A feed of runs refused by a
 * ban, before the model ran, from the dedicated `ban_enforcement` table.
 *
 * Paged by OFFSET (not a growing limit): the endpoint hard-caps limit at
 * 200, so growing it would strand rows past 200 and spin a stuck "Load
 * more". `useInfiniteQuery` fetches successive PAGE_SIZE offsets and
 * accumulates them, so every row is reachable and the button disappears
 * once all are loaded. The window is in the query key, so switching it
 * starts a fresh paged view.
 */
export function BlockedAttemptsPanel({ projectId }: { projectId: string }) {
  const [timeWindow, setTimeWindow] = useState<AuditWindow>("24h");
  const [selected, setSelected] = useState<BanEnforcementRow | null>(null);

  const feed = useInfiniteQuery({
    queryKey: ["ban-enforcements", projectId, timeWindow],
    initialPageParam: 0,
    queryFn: ({ pageParam }) =>
      api.listBanEnforcements(
        { window: timeWindow, limit: PAGE_SIZE, offset: pageParam },
        projectId,
      ),
    // Next offset = rows loaded so far, until we've caught up to `total`.
    // Stops on an empty page too, so a stale total can't loop.
    getNextPageParam: (lastPage, allPages) => {
      const loaded = allPages.reduce((n, p) => n + p.rows.length, 0);
      if (lastPage.rows.length === 0 || loaded >= lastPage.total) {
        return undefined;
      }
      return loaded;
    },
  });

  // Dedup by event_id when flattening pages: this is a live feed ordered
  // newest-first, so a new row landing between "Load more" clicks shifts every
  // later offset by one and re-serves a boundary row. Without the dedup that
  // surfaces as duplicate React keys / a row shown twice on a burst.
  const rows: BanEnforcementRow[] = dedupById(
    feed.data?.pages.flatMap((p) => p.rows) ?? [],
  );
  const total = feed.data?.pages[0]?.total ?? 0;
  const remaining = Math.max(total - rows.length, 0);

  return (
    <div className="overflow-hidden rounded-lg border border-border bg-card">
      <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-3.5">
        <div>
          <div className="text-sm font-medium">Blocked attempts</div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">
            Runs refused by a ban, before the model ran.
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

      {feed.isLoading ? (
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
                    className="truncate px-5 py-3 text-muted-foreground"
                    title={r.reason || undefined}
                  >
                    {r.reason || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {feed.hasNextPage && (
            <div className="border-t border-border px-5 py-3 text-center">
              <Button
                variant="secondary"
                size="sm"
                disabled={feed.isFetchingNextPage}
                onClick={() => feed.fetchNextPage()}
              >
                {feed.isFetchingNextPage
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
