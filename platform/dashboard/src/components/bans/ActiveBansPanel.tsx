import { useState } from "react";
import { Plus, ShieldAlert, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { useBans, useRevokeBan, type BanRead } from "@/lib/bans";
import { BanTypeBadge } from "./BanTypeBadge";
import { PROPAGATION_HINT } from "./constants";
import { formatAbsolute, formatRelative } from "./format";

/**
 * Region B (§9.3) — the primary panel. Lists the project's active bans.
 *
 * Reads a danger surface: a subtle destructive left border + a shield
 * header, without being alarming when the table is empty. Revoke is
 * admin-only (`canManage`) and destructively styled; the confirm step
 * uses the shared ConfirmDialog (§9.5).
 */
export function ActiveBansPanel({
  projectId,
  canManage,
  onCreate,
}: {
  projectId: string;
  canManage: boolean;
  onCreate: () => void;
}) {
  const bansQuery = useBans(projectId);
  const revokeBan = useRevokeBan();
  const [confirmRevoke, setConfirmRevoke] = useState<BanRead | null>(null);

  const bans = bansQuery.data ?? [];

  async function revoke() {
    if (!confirmRevoke) return;
    const target =
      confirmRevoke.target_agent_name ?? confirmRevoke.target_user_id ?? "";
    try {
      await revokeBan.mutateAsync({ projectId, banId: confirmRevoke.id });
      toast.success(`Ban revoked for ${target}`);
      setConfirmRevoke(null);
    } catch {
      toast.error(`Could not revoke the ban for ${target}.`);
    }
  }

  return (
    <div className="overflow-hidden rounded-lg border border-border border-l-2 border-l-destructive/50 bg-card">
      <div className="flex items-center gap-2 border-b border-border px-5 py-3.5">
        <ShieldAlert className="size-4 text-destructive" />
        <span className="text-sm font-medium">Active bans</span>
        <span className="text-sm text-muted-foreground">· {bans.length}</span>
        <span className="ml-2 text-[11px] text-muted-foreground">
          Runs are refused before the model executes.
        </span>
      </div>

      {bansQuery.isLoading ? (
        <div className="p-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : bans.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
          <ShieldAlert className="size-12 text-muted-foreground/40" />
          <div className="text-sm font-medium">No active bans</div>
          <div className="max-w-xs text-xs text-muted-foreground">
            Nothing is currently blocked. Create a ban to immediately stop an
            agent or user from running across this project.
          </div>
          {canManage && (
            <Button
              className="mt-1 gap-2"
              variant="destructive"
              onClick={onCreate}
            >
              <Plus className="size-4" />
              Create ban
            </Button>
          )}
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-5 py-2.5 text-left font-medium">Type</th>
              <th className="px-5 py-2.5 text-left font-medium">Target</th>
              <th className="px-5 py-2.5 text-left font-medium">Reason</th>
              <th className="px-5 py-2.5 text-left font-medium">Created by</th>
              <th className="px-5 py-2.5 text-left font-medium">Created</th>
              {canManage && <th className="w-24 px-5 py-2.5" />}
            </tr>
          </thead>
          <tbody>
            {bans.map((b) => (
              <tr
                key={b.id}
                className="border-b border-border/50 last:border-0 hover:bg-accent/40"
              >
                <td className="px-5 py-3">
                  <BanTypeBadge type={b.ban_type} />
                </td>
                <td className="px-5 py-3 font-mono text-xs">
                  {b.target_agent_name ?? b.target_user_id}
                </td>
                <td
                  className="max-w-[280px] truncate px-5 py-3 text-muted-foreground"
                  title={b.reason ?? undefined}
                >
                  {b.reason || "—"}
                </td>
                <td className="px-5 py-3 text-[13px] text-muted-foreground">
                  {b.created_by_user_id}
                </td>
                <td
                  className="px-5 py-3 text-[13px] text-muted-foreground"
                  title={formatAbsolute(b.created_at)}
                >
                  {formatRelative(b.created_at)}
                </td>
                {canManage && (
                  <td className="px-5 py-3 text-right">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="gap-1.5 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
                      onClick={() => setConfirmRevoke(b)}
                    >
                      <Trash2 className="size-3.5" />
                      Revoke
                    </Button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <ConfirmDialog
        open={!!confirmRevoke}
        onOpenChange={(o) => !o && setConfirmRevoke(null)}
        title="Revoke ban?"
        description={
          confirmRevoke
            ? `${confirmRevoke.target_agent_name ?? confirmRevoke.target_user_id} will be able to run again on ${PROPAGATION_HINT}.`
            : ""
        }
        confirmLabel="Revoke"
        onConfirm={revoke}
        pending={revokeBan.isPending}
      />
    </div>
  );
}
