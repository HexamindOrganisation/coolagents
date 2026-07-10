/**
 * Kill-switch ban hooks. React Query reads + mutations for the
 * /v1/projects/{project_id}/bans CRUD surface (cookie auth,
 * admin/owner only server-side — non-admins get 403).
 *
 * A ban overrides all policies and stops an agent or a user from
 * running at all. Creating one can 409 (an active ban already exists
 * for that target) or 400 (target doesn't match ban_type); both
 * surface as ApiError instances the create form translates to a
 * sonner toast.
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ApiError } from "./api";

export type BanType = "agent" | "user";

/** Mirror of platform/api/schemas.py:BanRead. ``active`` is the
 * server-computed ``revoked_at is None``. */
export interface BanRead {
  id: string;
  project_id: string;
  ban_type: BanType;
  target_agent_name: string | null;
  target_user_id: string | null;
  reason: string | null;
  created_by_user_id: string;
  created_at: string;
  revoked_at: string | null;
  active: boolean;
}

/** ``includeRevoked`` is part of the key so the active-only and
 * full-history views cache separately. */
function bansKey(projectId: string | null, includeRevoked: boolean) {
  return ["bans", projectId, includeRevoked] as const;
}

async function fetchBans(
  projectId: string,
  includeRevoked: boolean,
): Promise<BanRead[]> {
  const q = includeRevoked ? "?include_revoked=true" : "";
  const res = await fetch(`/v1/projects/${projectId}/bans${q}`, {
    credentials: "include",
  });
  if (!res.ok) {
    throw new ApiError(res.status, null, `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as BanRead[];
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
    queryFn: () => fetchBans(projectId as string, includeRevoked),
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

async function createBanRequest(input: CreateBanInput): Promise<BanRead> {
  // Send only the target field matching ban_type — the server rejects a
  // body that sets the other target (BanCreate._check_target → 422/400).
  const body: Record<string, unknown> = { ban_type: input.ban_type };
  if (input.ban_type === "agent") {
    body.target_agent_name = input.target_agent_name;
  } else {
    body.target_user_id = input.target_user_id;
  }
  if (input.reason) body.reason = input.reason;

  const res = await fetch(`/v1/projects/${input.projectId}/bans`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail: unknown;
    try {
      detail = await res.json();
    } catch {
      detail = null;
    }
    throw new ApiError(res.status, detail, `${res.status} ${res.statusText}`);
  }
  return (await res.json()) as BanRead;
}

export function useCreateBan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createBanRequest,
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

async function revokeBanRequest(input: RevokeBanInput): Promise<void> {
  const res = await fetch(
    `/v1/projects/${input.projectId}/bans/${input.banId}`,
    { method: "DELETE", credentials: "include" },
  );
  if (res.status === 204) return;
  let detail: unknown;
  try {
    detail = await res.json();
  } catch {
    detail = null;
  }
  throw new ApiError(res.status, detail, `${res.status} ${res.statusText}`);
}

export function useRevokeBan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: revokeBanRequest,
    onSuccess: (_data, input) => {
      qc.invalidateQueries({ queryKey: ["bans", input.projectId] });
    },
  });
}
