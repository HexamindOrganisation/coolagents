import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Info } from "lucide-react";
import { toast } from "sonner";

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
import { ApiError, api } from "@/lib/api";
import { useCreateBan, type BanType } from "@/lib/bans";
import { PROPAGATION_HINT } from "./constants";

/**
 * Prefill contract (§9.8) — the cross-page tie-ins open the dialog
 * pre-set to a type + target (and optionally a seeded reason).
 * Undefined `initial` = a blank "Create ban".
 */
export interface CreateBanInitial {
  ban_type: BanType;
  target?: string;
  reason?: string;
}

/** Turn a create-ban failure into copy safe to show verbatim (§9.4).
 * 409 = an active ban already exists; 400/422 = target/type mismatch. */
function createErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 409) {
      return "An active ban already exists for this target.";
    }
    if (err.status === 403) {
      return "You don't have permission to manage bans in this project.";
    }
    if (err.status === 400 || err.status === 422) {
      return "Invalid ban — check the target matches the ban type.";
    }
  }
  return "Could not create the ban.";
}

export function CreateBanDialog({
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

  // Seed the form from `initial` only on the closed→open transition — NOT on
  // every `initial` identity change. The parent re-derives `initial` when URL
  // params change, so keying the reset on `initial` would wipe whatever the
  // user has typed mid-edit. The ref tracks the previous open state.
  const wasOpen = useRef(false);
  useEffect(() => {
    if (open && !wasOpen.current) {
      setBanType(initial?.ban_type ?? "agent");
      setAgentName(initial?.ban_type === "agent" ? (initial.target ?? "") : "");
      setUserId(initial?.ban_type === "user" ? (initial.target ?? "") : "");
      setReason(initial?.reason ?? "");
    }
    wasOpen.current = open;
  }, [open, initial]);

  const agentsQuery = useQuery({
    queryKey: ["agents", projectId],
    queryFn: () => api.listAgents(projectId),
    enabled: open && banType === "agent",
  });

  const target = banType === "agent" ? agentName : userId.trim();
  const canSubmit = target.length > 0 && !createBan.isPending;

  // §9.4 — emphasise scope per ban type in the warning banner.
  const warning = useMemo(
    () =>
      banType === "user"
        ? "This immediately blocks all execution for this user across every agent in this project. It overrides policies."
        : "This immediately blocks all execution for this agent, for all users. It overrides policies.",
    [banType],
  );

  async function submit() {
    try {
      await createBan.mutateAsync({
        projectId,
        ban_type: banType,
        target_agent_name: banType === "agent" ? agentName : undefined,
        target_user_id: banType === "user" ? userId.trim() : undefined,
        reason: reason.trim() || undefined,
      });
      toast.success("Ban created");
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
            Stops the target from running — this overrides every policy and
            takes effect on {PROPAGATION_HINT}.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-1">
          {initial?.target && (
            <div className="flex items-start gap-2 rounded-md border border-border bg-muted px-3 py-2 text-xs text-muted-foreground">
              <Info className="mt-px size-3.5 shrink-0" />
              <span>
                Target prefilled from a link — confirm it's the one you mean
                before creating the ban.
              </span>
            </div>
          )}

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
                autoFocus
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
            <textarea
              id="ban-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Why is this being banned? (shown in the blocked-attempts feed)"
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
            />
            <p className="text-xs text-muted-foreground">
              Sent to the SDK with the refusal, so the banned user may see it —
              keep internal notes out.
            </p>
          </div>

          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/5 p-3 text-xs text-destructive">
            <AlertTriangle className="mt-px size-3.5 shrink-0" />
            <span>{warning}</span>
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
