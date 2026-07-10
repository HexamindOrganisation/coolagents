import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Ban, Plus, ShieldAlert, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/ConfirmDialog";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useActive, useProjectScoped } from "@/lib/active";
import {
  ApiError,
  api,
  type AuditWindow,
  type BanEnforcementRow,
} from "@/lib/api";
import {
  useBans,
  useCreateBan,
  useRevokeBan,
  type BanRead,
  type BanType,
} from "@/lib/bans";
import { useOrgs } from "@/lib/orgs";

// The internal SDK refresh window a ban propagates within — surfaced in copy
// so operators know a create/revoke isn't instantaneous. Placeholder value;
// align with the SDK's actual ban-feed poll cadence before shipping.
const PROPAGATION_HINT = "a few seconds";

const WINDOWS: AuditWindow[] = ["24h", "7d", "30d", "90d"];
const PAGE_SIZE = 25;

function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function formatAbsolute(iso: string): string {
  return new Date(iso).toLocaleString();
}

/** Turn a create-ban failure into copy safe to show verbatim. 409 = an
 * active ban already exists; 400/422 = the target didn't match ban_type. */
function createErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 409) {
      return "An active ban already exists for this target.";
    }
    const detail = err.detail;
    if (detail && typeof detail === "object" && "detail" in detail) {
      const message = (detail as { detail: unknown }).detail;
      if (typeof message === "string") return message;
    }
    if (err.status === 400 || err.status === 422) {
      return "Invalid ban — check the target matches the ban type.";
    }
  }
  return "Could not create the ban.";
}

function BanTypeBadge({ type }: { type: BanType }) {
  return (
    <Badge variant={type === "agent" ? "primary" : "approval"}>
      {type === "agent" ? "Agent" : "User"}
    </Badge>
  );
}

/** Prefill contract (§9.8) — the cross-page tie-ins (step 7) open the dialog
 * pre-set to a type + target. Undefined = a blank "Create ban". */
export interface CreateBanInitial {
  ban_type: BanType;
  target?: string;
  reason?: string;
}

function CreateBanDialog({
  open,
  onOpenChange,
  projectId,
  initial,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  initial?: CreateBanInitial;
}) {
  const [banType, setBanType] = useState<BanType>("agent");
  const [agentName, setAgentName] = useState("");
  const [userId, setUserId] = useState("");
  const [reason, setReason] = useState("");
  const createBan = useCreateBan();

  // Reset the form whenever the dialog (re)opens, seeding from any prefill.
  useEffect(() => {
    if (!open) return;
    setBanType(initial?.ban_type ?? "agent");
    setAgentName(initial?.ban_type === "agent" ? (initial.target ?? "") : "");
    setUserId(initial?.ban_type === "user" ? (initial.target ?? "") : "");
    setReason(initial?.reason ?? "");
  }, [open, initial]);

  const agentsQuery = useQuery({
    queryKey: ["agents", projectId],
    queryFn: () => api.listAgents(projectId),
    enabled: open && banType === "agent",
  });

  const target = banType === "agent" ? agentName : userId.trim();
  const canSubmit = target.length > 0 && !createBan.isPending;

  async function submit() {
    try {
      await createBan.mutateAsync({
        projectId,
        ban_type: banType,
        target_agent_name: banType === "agent" ? agentName : undefined,
        target_user_id: banType === "user" ? userId.trim() : undefined,
        reason: reason.trim() || undefined,
      });
      toast.success(`Ban created for ${target}`);
      onOpenChange(false);
    } catch (err) {
      toast.error(createErrorMessage(err));
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create ban</DialogTitle>
          <DialogDescription>
            Immediately stops the target from running — this overrides every
            policy and takes effect within {PROPAGATION_HINT}.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <ToggleGroup
            type="single"
            value={banType}
            onValueChange={(v) => v && setBanType(v as BanType)}
            className="justify-start"
          >
            <ToggleGroupItem value="agent">Agent</ToggleGroupItem>
            <ToggleGroupItem value="user">User</ToggleGroupItem>
          </ToggleGroup>

          {banType === "agent" ? (
            <div className="space-y-1.5">
              <Label>Agent to ban</Label>
              <Select value={agentName} onValueChange={setAgentName}>
                <SelectTrigger>
                  <SelectValue placeholder="Select an agent" />
                </SelectTrigger>
                <SelectContent>
                  {(agentsQuery.data ?? []).map((a) => (
                    <SelectItem key={a.name} value={a.name}>
                      {a.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Blocks this agent for all users in the project.
              </p>
            </div>
          ) : (
            <div className="space-y-1.5">
              <Label htmlFor="ban-user-id">User ID</Label>
              <Input
                id="ban-user-id"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="user-123"
              />
              <p className="text-xs text-muted-foreground">
                The user id your backend passes to Hexgate (the SDK{" "}
                <code>User(...)</code> scope). Blocks them across every agent in
                the project.
              </p>
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="ban-reason">Reason (optional)</Label>
            <Input
              id="ban-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why is this being banned?"
            />
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={!canSubmit} onClick={submit}>
            {createBan.isPending ? "Creating…" : "Create ban"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ActiveBansPanel({
  projectId,
  onCreate,
}: {
  projectId: string;
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
      await revokeBan.mutateAsync({
        projectId,
        banId: confirmRevoke.id,
      });
      toast.success(`Ban revoked for ${target}`);
      setConfirmRevoke(null);
    } catch {
      toast.error(`Could not revoke the ban for ${target}.`);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div className="text-sm">
          Active bans{" "}
          <span className="text-muted-foreground">· {bans.length}</span>
        </div>
      </div>

      {bansQuery.isLoading ? (
        <div className="p-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : bans.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
          <ShieldAlert className="size-12 text-muted-foreground/50" />
          <div className="text-sm font-medium">No active bans</div>
          <div className="max-w-xs text-xs text-muted-foreground">
            Nothing is currently blocked. Create a ban to immediately stop an
            agent or user from running.
          </div>
          <Button className="mt-1 gap-2" onClick={onCreate}>
            <Plus className="size-4" />
            Create ban
          </Button>
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-5 py-2.5 text-left font-medium">Type</th>
              <th className="px-5 py-2.5 text-left font-medium">Target</th>
              <th className="px-5 py-2.5 text-left font-medium">Reason</th>
              <th className="px-5 py-2.5 text-left font-medium">Created</th>
              <th className="w-24 px-5 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {bans.map((b) => (
              <tr key={b.id} className="border-b border-border last:border-0">
                <td className="px-5 py-3">
                  <BanTypeBadge type={b.ban_type} />
                </td>
                <td className="px-5 py-3 font-mono text-xs">
                  {b.target_agent_name ?? b.target_user_id}
                </td>
                <td className="px-5 py-3 text-muted-foreground">
                  {b.reason || "—"}
                </td>
                <td
                  className="px-5 py-3 text-muted-foreground"
                  title={formatAbsolute(b.created_at)}
                >
                  {formatRelative(b.created_at)}
                </td>
                <td className="px-5 py-3 text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="gap-1.5 text-xs"
                    onClick={() => setConfirmRevoke(b)}
                  >
                    <Trash2 className="size-3.5" />
                    Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <ConfirmDialog
        open={!!confirmRevoke}
        onOpenChange={(o) => !o && setConfirmRevoke(null)}
        title="Revoke ban?"
        description={`The target will be able to run again within ${PROPAGATION_HINT}.`}
        confirmLabel="Revoke"
        onConfirm={revoke}
        pending={revokeBan.isPending}
      />
    </div>
  );
}

function BlockedAttemptsPanel({ projectId }: { projectId: string }) {
  const [timeWindow, setTimeWindow] = useState<AuditWindow>("24h");
  const [limit, setLimit] = useState(PAGE_SIZE);

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

  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="flex items-center justify-between border-b border-border px-5 py-3">
        <div>
          <div className="text-sm">Blocked attempts</div>
          <div className="text-xs text-muted-foreground">
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
        <div className="py-16 text-center text-sm text-muted-foreground">
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
                <th className="px-5 py-2.5 text-left font-medium">Ban</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.event_id}
                  className="border-b border-border last:border-0"
                >
                  <td
                    className="px-5 py-3 text-muted-foreground"
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
                  <td className="px-5 py-3 text-muted-foreground">
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
                variant="ghost"
                size="sm"
                disabled={feedQuery.isFetching}
                onClick={() => setLimit((l) => l + PAGE_SIZE)}
              >
                {feedQuery.isFetching ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function AdminRequiredNotice() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border bg-card py-16 text-center">
      <ShieldAlert className="size-10 text-muted-foreground/50" />
      <div className="text-sm font-medium">Admins only</div>
      <div className="max-w-sm text-xs text-muted-foreground">
        Bans are managed by organization admins and owners. Ask an admin to
        grant access or to create a ban on your behalf.
      </div>
    </div>
  );
}

/**
 * Bans page ("kill switch" internally) — org-admins list, create, and
 * revoke bans that stop an agent or user from running at all, plus a
 * feed of recently blocked attempts.
 *
 * Placeholder markup uses the shared UI kit; the Claude Design output
 * replaces the visual layer while the hooks/state below stay put.
 */
export function BansPage() {
  const scope = useProjectScoped();
  const activeOrgId = useActive((s) => s.activeOrgId);
  const orgsQuery = useOrgs();
  const org = orgsQuery.data?.find((o) => o.id === activeOrgId) ?? null;
  const canManage = org?.role === "owner" || org?.role === "admin";

  const [createOpen, setCreateOpen] = useState(false);

  if (scope.status === "no-project") {
    return (
      <div className="mx-auto max-w-[1400px]">
        <h1 className="text-2xl font-semibold tracking-tight">Bans</h1>
        <NoProjectEmptyState resource="bans" />
      </div>
    );
  }

  const projectId = scope.projectId;

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
            <Ban className="size-6 text-destructive" />
            Bans
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Immediately stop an agent or a user from running — overrides every
            policy. Takes effect within {PROPAGATION_HINT}.
          </p>
        </div>
        {canManage && projectId && (
          <Button className="gap-2" onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" />
            Create ban
          </Button>
        )}
      </div>

      {!projectId ? (
        <div className="p-12 text-center text-sm text-muted-foreground">
          Loading…
        </div>
      ) : !canManage ? (
        <AdminRequiredNotice />
      ) : (
        <>
          <ActiveBansPanel
            projectId={projectId}
            onCreate={() => setCreateOpen(true)}
          />
          <BlockedAttemptsPanel projectId={projectId} />
          <CreateBanDialog
            open={createOpen}
            onOpenChange={setCreateOpen}
            projectId={projectId}
          />
        </>
      )}
    </div>
  );
}
