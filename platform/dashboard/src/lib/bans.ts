/**
 * Ban hooks. React Query reads + mutations wrapping the ``api.*`` ban
 * calls (which go through the shared ``request()`` helper — so a 401 on
 * this page bounces to /sign-in like everywhere else, and error detail
 * is extracted centrally).
 *
 * A ban overrides all policies and stops an agent or a user from
 * running at all. Creating one can 409 (an active ban already exists
 * for that target) or 422 (target doesn't match ban_type); both surface
 * as ApiError instances the create form translates to a sonner toast.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useActive } from "./active";
import { api, type BanCreateBody, type BanRead, type BanType } from "./api";
import { useOrgs } from "./orgs";

// Re-export the wire types so existing component imports (`@/lib/bans`)
// keep resolving; the definitions now live with the api client.
export type { BanRead, BanType };

/** ``includeRevoked`` is part of the key so the active-only and
 * full-history views cache separately. */
function bansKey(projectId: string | null, includeRevoked: boolean) {
  return ["bans", projectId, includeRevoked] as const;
}

interface UseBansOptions {
  includeRevoked?: boolean;
}

/** Bans for a project. Disabled while ``projectId`` is null so pages
 * can pass the resolved scope id directly without a null guard. */
export function useBans(projectId: string | null, options?: UseBansOptions) {
  const includeRevoked = options?.includeRevoked ?? false;
  return useQuery({
    queryKey: bansKey(projectId, includeRevoked),
    queryFn: () => api.listBans(projectId as string, includeRevoked),
    enabled: !!projectId,
    staleTime: 30_000,
  });
}

export interface CreateBanInput {
  projectId: string;
  ban_type: BanType;
  /** Set for an agent ban. */
  target_agent_name?: string;
  /** Set for a user ban. */
  target_user_id?: string;
  reason?: string;
}

/** Build the minimal POST body — only the target field matching ``ban_type``,
 * since the server rejects a body that also sets the other target. */
function createBanBody(input: CreateBanInput): BanCreateBody {
  const body: BanCreateBody = { ban_type: input.ban_type };
  if (input.ban_type === "agent") {
    body.target_agent_name = input.target_agent_name;
  } else {
    body.target_user_id = input.target_user_id;
  }
  if (input.reason) body.reason = input.reason;
  return body;
}

export function useCreateBan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateBanInput) =>
      api.createBan(createBanBody(input), input.projectId),
    onSuccess: (ban) => {
      // Bust every cached view of this project's bans (active-only and
      // include-revoked) so the new row shows regardless of the toggle.
      qc.invalidateQueries({ queryKey: ["bans", ban.project_id] });
    },
  });
}

interface RevokeBanInput {
  projectId: string;
  banId: string;
}

export function useRevokeBan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: RevokeBanInput) =>
      api.revokeBan(input.banId, input.projectId),
    onSuccess: (_data, input) => {
      qc.invalidateQueries({ queryKey: ["bans", input.projectId] });
    },
  });
}

/** Whether the caller may manage bans in the active org — the ban endpoints
 * are `require_project_admin` server-side, so this gates the create/revoke
 * affordances and the cross-page "Ban user"/"Ban agent" tie-ins. Reads the
 * active org's role from the same source as the org switcher (no extra
 * fetch). False while orgs are still loading. */
export function useCanManageBans(): boolean {
  const activeOrgId = useActive((s) => s.activeOrgId);
  const orgsQuery = useOrgs();
  const org = orgsQuery.data?.find((o) => o.id === activeOrgId) ?? null;
  return org?.role === "owner" || org?.role === "admin";
}
