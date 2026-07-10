import { useState } from "react";
import { Ban, BookOpen, Plus, ShieldAlert } from "lucide-react";

import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Button } from "@/components/ui/button";
import { useActive, useProjectScoped } from "@/lib/active";
import { useOrgs } from "@/lib/orgs";
import { ActiveBansPanel } from "@/components/bans/ActiveBansPanel";
import { BlockedAttemptsPanel } from "@/components/bans/BlockedAttemptsPanel";
import {
  CreateBanDialog,
  type CreateBanInitial,
} from "@/components/bans/CreateBanDialog";
import { PROPAGATION_HINT } from "@/components/bans/constants";

/** Non-admin block. Both ban reads (`GET …/bans` and the ban-enforcement
 * feed) are `require_project_admin` server-side, so members can't list at
 * all — we hard-block rather than render tables that would 403. */
function AdminRequiredNotice() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border bg-card py-16 text-center">
      <ShieldAlert className="size-10 text-muted-foreground/40" />
      <div className="text-sm font-medium">Admins only</div>
      <div className="max-w-sm text-xs text-muted-foreground">
        Bans are managed by organization admins and owners. Ask an admin to
        grant access or to create a ban on your behalf.
      </div>
    </div>
  );
}

/**
 * Bans page ("kill switch" internally — never surfaced to users, §9.1).
 * Org-admins list, create, and revoke bans that stop an agent or user
 * from running at all, plus a feed of recently blocked attempts.
 *
 * States (§9.2): no-project → NoProjectEmptyState; loading + empty +
 * populated are handled inside each panel. Non-admins are hard-blocked
 * (both ban reads are admin-only server-side).
 */
export function BansPage() {
  const scope = useProjectScoped();
  const activeOrgId = useActive((s) => s.activeOrgId);
  const orgsQuery = useOrgs();
  const org = orgsQuery.data?.find((o) => o.id === activeOrgId) ?? null;
  const canManage = org?.role === "owner" || org?.role === "admin";

  const [createOpen, setCreateOpen] = useState(false);
  // Prefill for the create dialog, driven by the cross-page tie-ins /
  // `?ban_user=` / `?ban_agent=` (§9.8). Left undefined for a blank form.
  const [initial] = useState<CreateBanInitial | undefined>(undefined);

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
    <div className="mx-auto max-w-[1400px] space-y-5">
      {/* Region A — header (§9.3) */}
      <div className="flex items-start justify-between gap-6">
        <div>
          <h1 className="flex items-center gap-2.5 text-2xl font-semibold tracking-tight">
            <Ban className="size-6 text-destructive" />
            Bans
          </h1>
          <p className="mt-2 max-w-[620px] text-sm text-muted-foreground">
            Immediately stop an agent or a user from running — overrides every
            policy. Takes effect within {PROPAGATION_HINT}.
          </p>
        </div>
        <div className="flex flex-shrink-0 items-center gap-2">
          <Button variant="ghost" className="gap-2 text-muted-foreground">
            <BookOpen className="size-4" />
            Ban docs
          </Button>
          {canManage && projectId && (
            <Button
              variant="destructive"
              className="gap-2"
              onClick={() => setCreateOpen(true)}
            >
              <Plus className="size-4" />
              Create ban
            </Button>
          )}
        </div>
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
            canManage
            onCreate={() => setCreateOpen(true)}
          />
          <BlockedAttemptsPanel projectId={projectId} />
          <CreateBanDialog
            open={createOpen}
            onOpenChange={setCreateOpen}
            projectId={projectId}
            initial={initial}
          />
        </>
      )}
    </div>
  );
}
