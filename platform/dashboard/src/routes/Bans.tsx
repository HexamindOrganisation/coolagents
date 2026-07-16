import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Ban, BookOpen, Plus, ShieldAlert } from "lucide-react";

import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Button } from "@/components/ui/button";
import { useProjectScoped } from "@/lib/active";
import { useCanManageBans } from "@/lib/bans";
import { ActiveBansPanel } from "@/components/bans/ActiveBansPanel";
import { BlockedAttemptsPanel } from "@/components/bans/BlockedAttemptsPanel";
import {
  CreateBanDialog,
  type CreateBanInitial,
} from "@/components/bans/CreateBanDialog";
import { BAN_DOCS_URL, PROPAGATION_HINT } from "@/components/bans/constants";

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
  const canManage = useCanManageBans();

  const [createOpen, setCreateOpen] = useState(false);
  const [initial, setInitial] = useState<CreateBanInitial | undefined>(
    undefined,
  );

  // Cross-page tie-ins (§9.6) deep-link with `?ban_user=` / `?ban_agent=`:
  // seed the create dialog and open it. Params are cleared on close so a
  // refresh doesn't reopen the dialog.
  const [searchParams, setSearchParams] = useSearchParams();
  const prefillUser = searchParams.get("ban_user");
  const prefillAgent = searchParams.get("ban_agent");

  function clearPrefillParams() {
    searchParams.delete("ban_user");
    searchParams.delete("ban_agent");
    setSearchParams(searchParams, { replace: true });
  }

  useEffect(() => {
    // Wait until the scope (and thus the org role) is resolved so we don't
    // act on a still-loading `canManage`, then: admins get the prefilled
    // dialog; a non-admin who followed the link sees AdminRequiredNotice, so
    // just strip the stale params rather than dangling `createOpen` on a
    // dialog that never mounts.
    if (scope.status !== "ready" || (!prefillUser && !prefillAgent)) return;
    if (!canManage) {
      clearPrefillParams();
      return;
    }
    setInitial(
      prefillUser
        ? { ban_type: "user", target: prefillUser }
        : { ban_type: "agent", target: prefillAgent as string },
    );
    setCreateOpen(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scope.status, canManage, prefillUser, prefillAgent]);

  function openCreate() {
    setInitial(undefined);
    setCreateOpen(true);
  }

  function handleCreateOpenChange(open: boolean) {
    setCreateOpen(open);
    if (!open && (prefillUser || prefillAgent)) {
      clearPrefillParams();
    }
  }

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
            Stop an agent or a user from running — overrides every policy. Takes
            effect on {PROPAGATION_HINT}; a run already in progress isn't
            interrupted.
          </p>
        </div>
        <div className="flex flex-shrink-0 items-center gap-2">
          <Button
            asChild
            variant="ghost"
            className="gap-2 text-muted-foreground"
          >
            <a href={BAN_DOCS_URL} target="_blank" rel="noreferrer">
              <BookOpen className="size-4" />
              Ban docs
            </a>
          </Button>
          {canManage && projectId && (
            <Button
              variant="destructive"
              className="gap-2"
              onClick={openCreate}
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
            onCreate={openCreate}
          />
          <BlockedAttemptsPanel projectId={projectId} />
          <CreateBanDialog
            open={createOpen}
            onOpenChange={handleCreateOpenChange}
            projectId={projectId}
            initial={initial}
          />
        </>
      )}
    </div>
  );
}
