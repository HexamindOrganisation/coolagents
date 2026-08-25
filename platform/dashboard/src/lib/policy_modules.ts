/**
 * Policy-module editor hooks. React Query reads + mutations over the
 * `api.*PolicyModule*` / `api.*PolicyRoles` / `api.resolvePolicy` calls (all
 * through the shared `request()` helper, so a 401 bounces to /sign-in and
 * error detail is extracted centrally).
 *
 * The store is the source of truth; the resolved policy + lints are derived.
 * Every write invalidates the resolve + check reads so the inspector reconciles
 * to stored state after a Save. The live preview (`usePolicyPreview`) is a
 * separate, debounced read of an unsaved draft — it never writes.
 */

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useActive } from "./active";
import {
  api,
  type PolicyDraft,
  type PolicyTier,
  type RoleBindings,
} from "./api";
import { useOrgs } from "./orgs";

// Re-export the wire types so component imports (`@/lib/policy_modules`)
// resolve without also reaching into `@/lib/api`.
export type { PolicyLint, PolicyTier, RoleBindings } from "./api";

const modulesKey = (pid: string) => ["policy-modules", pid] as const;
const rolesKey = (pid: string) => ["policy-roles", pid] as const;
const resolveKey = (pid: string, role: string | null) =>
  ["policy-resolve", pid, role] as const;
const checkKey = (pid: string) => ["policy-check", pid] as const;

/** Bust every derived read for a project after a write. The store row is
 * authoritative; resolve/check/preview all recompute from it. */
function invalidateDerived(qc: ReturnType<typeof useQueryClient>, pid: string) {
  qc.invalidateQueries({ queryKey: ["policy-resolve", pid] });
  qc.invalidateQueries({ queryKey: checkKey(pid) });
  qc.invalidateQueries({ queryKey: ["policy-preview", pid] });
}

/** Every boundary + capability module in the project's library. Disabled
 * while `projectId` is null so pages pass the resolved scope id directly. */
export function usePolicyModules(projectId: string | null) {
  return useQuery({
    queryKey: modulesKey(projectId as string),
    queryFn: () => api.listPolicyModules(projectId as string),
    enabled: !!projectId,
    staleTime: 30_000,
  });
}

/** The project's role bindings (role -> imported capability names). */
export function usePolicyRoles(projectId: string | null) {
  return useQuery({
    queryKey: rolesKey(projectId as string),
    queryFn: () => api.getPolicyRoles(projectId as string),
    enabled: !!projectId,
    staleTime: 30_000,
  });
}

/** The composed effective policy, per role (all roles, or just `role`). */
export function useResolvedPolicy(projectId: string | null, role?: string) {
  return useQuery({
    queryKey: resolveKey(projectId as string, role ?? null),
    queryFn: () => api.resolvePolicy(projectId as string, role),
    enabled: !!projectId,
    // 422 when the modules don't compose — surfaced via `useCheck`; don't
    // hammer the endpoint retrying an unresolvable set.
    retry: false,
    staleTime: 15_000,
  });
}

/** Lints over the composed project (diagnostics-as-data, always 200). */
export function usePolicyCheck(projectId: string | null) {
  return useQuery({
    queryKey: checkKey(projectId as string),
    queryFn: () => api.checkPolicy(projectId as string),
    enabled: !!projectId,
    staleTime: 15_000,
  });
}

interface UpsertInput {
  tier: PolicyTier;
  path: string;
  content: string;
}

export function useUpsertModule(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: UpsertInput) =>
      api.upsertPolicyModule(projectId, input.tier, input.path, input.content),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: modulesKey(projectId) });
      invalidateDerived(qc, projectId);
    },
  });
}

interface DeleteInput {
  tier: PolicyTier;
  path: string;
}

export function useDeleteModule(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: DeleteInput) =>
      api.deletePolicyModule(projectId, input.tier, input.path),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: modulesKey(projectId) });
      invalidateDerived(qc, projectId);
    },
  });
}

interface MoveInput {
  tier: PolicyTier;
  path: string;
  newPath: string;
}

export function useMoveModule(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: MoveInput) =>
      api.movePolicyModule(projectId, input.tier, input.path, input.newPath),
    onSuccess: () => {
      // A capability move cascades to role bindings server-side, so refresh
      // roles too — not just the module list.
      qc.invalidateQueries({ queryKey: modulesKey(projectId) });
      qc.invalidateQueries({ queryKey: rolesKey(projectId) });
      invalidateDerived(qc, projectId);
    },
  });
}

export function useSetRoles(projectId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (roles: RoleBindings) => api.setPolicyRoles(projectId, roles),
    onSuccess: (roles) => {
      qc.setQueryData(rolesKey(projectId), roles);
      invalidateDerived(qc, projectId);
    },
  });
}

/** Evaluate one tool call against the whole resolved policy. A mutation, not
 * a query: it's fired on demand by the tester's Check button. */
export function useTestPolicy(projectId: string) {
  return useMutation({
    mutationFn: (body: Parameters<typeof api.testPolicy>[1]) =>
      api.testPolicy(projectId, body),
  });
}

/**
 * Debounced live preview: resolve + lint the project with `draft` overlaid,
 * without writing. Keyed on the (already debounced) draft so a new keystroke
 * supersedes an in-flight request; `enabled` lets the caller skip the round
 * trip while the draft doesn't parse client-side. `placeholderData` keeps the
 * previous result on screen during a refetch so lints don't flicker.
 */
export function usePolicyPreview(
  projectId: string | null,
  draft: PolicyDraft | null,
  enabled: boolean,
) {
  return useQuery({
    queryKey: ["policy-preview", projectId, JSON.stringify(draft ?? null)],
    queryFn: () => api.previewPolicy(projectId as string, draft),
    enabled: !!projectId && enabled,
    retry: false,
    placeholderData: (prev) => prev,
    staleTime: 5_000,
  });
}

/**
 * Value that lags `value` by `ms`, resetting the timer on every change. Only
 * the debounced value should be a query dependency, so the expensive preview
 * round-trip fires after the user pauses, not per keystroke.
 */
export function useDebouncedValue<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

/** Whether the caller may edit policy in the active org — the module write
 * endpoints are `require_project_admin` server-side, so this gates the Save /
 * tree-edit affordances. Mirrors `useCanManageBans`; false while orgs load. */
export function useCanManagePolicy(): boolean {
  const activeOrgId = useActive((s) => s.activeOrgId);
  const orgsQuery = useOrgs();
  const org = orgsQuery.data?.find((o) => o.id === activeOrgId) ?? null;
  return org?.role === "owner" || org?.role === "admin";
}
