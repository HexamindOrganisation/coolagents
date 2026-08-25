/** Routes that are reachable without a session cookie — never redirect
 * away from these on a 401, otherwise we'd bounce the sign-in form itself
 * back to /sign-in in a loop when the user has bad credentials. */
const PUBLIC_AUTH_PATHS = [
  "/sign-in",
  "/sign-up",
  "/forgot-password",
  "/reset-password",
  "/verify-email",
];

/** Thrown by ``request`` when the backend returns 401, after the global
 * "redirect to /sign-in" side-effect has fired. Tests assert against the
 * error type; production code rarely catches it (the redirect already
 * happened). */
export class UnauthenticatedError extends Error {
  constructor(message = "not authenticated") {
    super(message);
    this.name = "UnauthenticatedError";
  }
}

/** Thrown for any non-2xx response other than 401 — carries the parsed
 * detail when the backend returns one (FastAPI Users speaks JSON with
 * a ``detail`` field). Fields are declared explicitly (not via TS
 * constructor parameter properties) because the project's tsconfig
 * enables ``erasableSyntaxOnly``. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(status: number, detail: unknown, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** Human-readable message from a FastAPI error body. Handles the two shapes:
 * a string `detail` (HTTPException) and the validation-error array
 * `detail: [{loc, msg, type}, ...]` (422) — the latter would otherwise
 * `String()` to "[object Object]". Returns null when neither applies. */
function messageFromDetail(detail: unknown): string | null {
  if (typeof detail !== "object" || detail === null || !("detail" in detail)) {
    return null;
  }
  const d = (detail as { detail: unknown }).detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    const msgs = d
      .map((e) =>
        e && typeof e === "object" && "msg" in e
          ? String((e as { msg: unknown }).msg)
          : null,
      )
      .filter((m): m is string => !!m);
    if (msgs.length) return msgs.join("; ");
  }
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    // ``include`` so the hexgate_session cookie rides on cross-origin
    // dev (vite on 5173 → api on 8000) and on prod where the dashboard
    // and API may live on different subdomains.
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 401) {
    // Single global redirect — every component that does a request gets
    // sent to sign-in if their session expired. Public auth routes are
    // exempt: a 401 there is just "wrong password", surface it normally.
    const onAuthPage = PUBLIC_AUTH_PATHS.some((p) =>
      window.location.pathname.startsWith(p),
    );
    if (!onAuthPage) {
      window.location.href = "/sign-in";
    }
    throw new UnauthenticatedError();
  }
  if (!res.ok) {
    let detail: unknown;
    let bodyText = "";
    try {
      bodyText = await res.text();
      detail = bodyText ? JSON.parse(bodyText) : null;
    } catch {
      detail = bodyText;
    }
    const message =
      messageFromDetail(detail) ?? `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, detail, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface TokenListItem {
  id: string;
  name: string;
  masked: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
}

export interface TokenMintResponse extends TokenListItem {
  full: string;
}

export interface TokenMintRequest {
  name: string;
  scopes?: string[];
  env?: "test" | "live";
}

export interface AgentRead {
  id: string;
  name: string;
  agent_yaml: string;
  /**
   * Canonical policy document. Flat single-policy YAML or — when the agent
   * declares per-role behaviour — an inline-roles YAML with a top-level
   * ``roles:`` map. See ``parseRolesFromPolicy`` in lib/policy.ts for the
   * client-side helper that extracts the role list (for the Playground
   * picker, etc).
   */
  policy_yaml: string;
  system_md: string;
  updated_at: string;
}

export interface AgentUpdate {
  agent_yaml?: string;
  policy_yaml?: string;
  system_md?: string;
}

/**
 * Tool input parameter, mirroring InputProperty in platform/api/schemas.py.
 */
export interface InputProperty {
  title: string;
  type: string;
}

/**
 * Tool input schema, mirroring InputSchema in platform/api/schemas.py.
 */
export interface InputSchema {
  properties: Record<string, InputProperty>;
  required: string[];
}

/**
 * Tool definition as stored in the registered manifest. ``description`` is
 * nullable on read-back to match the platform-side schema.
 */
export interface ToolDefinition {
  name: string;
  description: string | null;
  input_schema: InputSchema;
}

/**
 * Registered manifest body, mirroring AgentManifest in platform/api/schemas.py.
 */
export interface AgentManifest {
  name: string;
  description: string | null;
  framework: string;
  model: string | null;
  system_prompt: string | null;
  tools: ToolDefinition[];
}

/**
 * Dashboard-facing envelope for the latest registered manifest of an agent.
 *
 * ``manifest`` / ``version`` / ``content_hash`` are null when the agent
 * exists but has never been registered via ``POST /v1/agents``. ``name``
 * always reflects the Agent row's name (the picker uses it directly).
 */
export interface AgentManifestView {
  name: string;
  manifest: AgentManifest | null;
  version: number | null;
  content_hash: string | null;
  updated_at: string;
}

export interface PolicyValidationError {
  /** Role name when the failure was inside an inline-roles entry; null otherwise. */
  role: string | null;
  /** Tool the lint is about (`permissive-default`); null otherwise. Separate
   * from `role` because both render as a bare name in the same slot. */
  tool: string | null;
  line: number | null;
  message: string;
}

export interface ValidatePolicyResponse {
  ok: boolean;
  errors: PolicyValidationError[];
  /** Authoring lints. Never affect `ok`, so they can't block a save. */
  warnings: PolicyValidationError[];
}

// --- Policy modules (multi-module editor; mirrors platform/api/schemas.py) ---

export type PolicyTier = "boundary" | "capability";

/** One stored module — a boundary (ceiling/deny) or capability (grant). The
 * `path` may contain slashes for subfolders (e.g. `team_a/payments`). */
export interface PolicyModuleRead {
  tier: PolicyTier;
  path: string;
  content: string;
  content_hash: string;
  updated_at: string;
}

/** Role -> the capability names it imports. Boundaries always apply, so they
 * carry no binding. An empty map means the project is still classic. */
export type RoleBindings = Record<string, string[]>;

/** One analyzer lint over the composed project. `source`/`tier`/`tool`/`role`
 * locate it; a null `role` is a project-wide concern. */
export interface PolicyLint {
  code: string;
  severity: "error" | "warning" | "info";
  message: string;
  source: string | null;
  tier: string | null;
  tool: string | null;
  role: string | null;
}

/** The effective policy for one role: a tool map plus the catch-all default.
 * Loosely typed — it's an AgentPolicy dump the editor only renders. */
export interface ResolvedRolePolicy {
  default_policy?: { mode?: string } | null;
  tools?: Record<
    string,
    { mode?: string; constraints?: string[] | null } | null
  >;
  [key: string]: unknown;
}

export type ResolvedPolicy = Record<string, ResolvedRolePolicy>;

/** The editor's unsaved edit, overlaid before resolve/test. One module OR the
 * roles map, never both (matches PolicyDraft server-side). */
export interface PolicyDraft {
  module?: { tier: PolicyTier; path: string; content: string };
  roles?: RoleBindings;
}

export interface PolicyPreviewResponse {
  resolved: ResolvedPolicy;
  lints: PolicyLint[];
}

export type PolicyTestOutcome = "allow" | "deny" | "approval_required";

export interface PolicyTestRequest {
  role: string;
  tool: string;
  args?: Record<string, unknown>;
  attributes?: Record<string, unknown> | null;
  draft?: PolicyDraft | null;
}

export interface PolicyTestResponse {
  outcome: PolicyTestOutcome;
  reason: string | null;
  violations: string[];
  hint: string | null;
}

// --- Audit dashboard (mirrors platform/api/schemas.py) ----------------------

export type AuditWindow = "24h" | "7d" | "30d" | "90d";
export type AuditOutcome = "allow" | "deny" | "needs_approval";

export interface OutcomeCounts {
  all: number;
  allow: number;
  deny: number;
  needs_approval: number;
}

/** One agent/role/tool bucket; an empty role keeps its raw `""` key —
 * the dashboard maps it to the "(none)" display label locally.
 *
 * `by_role` counts membership — a caller carrying `["billing", "support"]`
 * lands in both — so it can sum to more than `totals`. Every other breakdown
 * stays one row per decision. */
export interface AuditBreakdownRow extends OutcomeCounts {
  key: string;
}

export interface AuditSummary {
  totals: OutcomeCounts;
  by_agent: AuditBreakdownRow[];
  by_role: AuditBreakdownRow[];
  by_tool: AuditBreakdownRow[];
  by_user: AuditBreakdownRow[];
}

/** One time bucket; `bucket` is an ISO string. */
export interface AuditTimeseriesPoint {
  bucket: string;
  allow: number;
  deny: number;
  needs_approval: number;
}

/** One events-table row; `hint`/`arguments`/`attributes` are decoded JSON. */
export interface AuditDecisionRow {
  event_id: string;
  occurred_at: string;
  received_at: string;
  agent_name: string;
  agent_version_id: string;
  session_id: string;
  user_id: string;
  tool_name: string;
  /** Distinct roles the caller carried, in order. Always the full set: an
   * SDK that sends the legacy scalar has it folded in at ingest. */
  user_roles: string[];
  /** Role whose policy granted or gated the call; `""` on a deny. */
  deciding_role: string;
  outcome: AuditOutcome;
  error_type: string;
  reason: string;
  violations: string[];
  hint: unknown;
  arguments: unknown;
  attributes: unknown;
}

export interface AuditDecisionPage {
  rows: AuditDecisionRow[];
  total: number;
  limit: number;
  offset: number;
}

/** Scope filters shared by summary/timeseries/list. `undefined` = no
 * filter; `role: ''` = the no-role bucket (sent as `role=`). A non-empty
 * `role` matches membership, so a multi-role call is returned under each. */
export interface AuditScope {
  window?: AuditWindow;
  agent?: string;
  role?: string;
  tool?: string;
  start_date?: string;
  end_date?: string;
  user?: string;
}

/** Narrow scope accepted by the anomalies endpoint (cross-user by design). */
export type AnomalyScope = Pick<
  AuditScope,
  "window" | "start_date" | "end_date"
>;

/** List filters: scope + table-only outcome/session_id + paging. */
export interface AuditDecisionFilters extends AuditScope {
  outcome?: AuditOutcome;
  session_id?: string;
  limit?: number;
  offset?: number;
}

export type BanType = "agent" | "user";

/** Mirror of platform/api/schemas.py:BanRead. ``active`` is the
 * server-computed ``revoked_at is None``; ``created_by_email`` is resolved
 * server-side for display (null when the account no longer exists). */
export interface BanRead {
  id: string;
  project_id: string;
  ban_type: BanType;
  target_agent_name: string | null;
  target_user_id: string | null;
  reason: string | null;
  created_by_user_id: string;
  created_by_email: string | null;
  created_at: string;
  revoked_at: string | null;
  active: boolean;
}

/** POST body for a ban. Only the target field matching ``ban_type`` is set —
 * the server's cross-validator rejects a body that sets the other target. */
export interface BanCreateBody {
  ban_type: BanType;
  target_agent_name?: string;
  target_user_id?: string;
  reason?: string;
}

/** One blocked-attempt row from GET …/audit/ban-enforcements. A ban is
 * refused before any tool call, so there's no tool/role/outcome —
 * mirrors platform/api/schemas.py:BanEnforcementRow. */
export interface BanEnforcementRow {
  event_id: string;
  occurred_at: string;
  received_at: string;
  agent_name: string;
  session_id: string;
  user_id: string;
  ban_type: "agent" | "user";
  ban_id: string;
  reason: string;
}

export interface BanEnforcementPage {
  rows: BanEnforcementRow[];
  total: number;
  limit: number;
  offset: number;
}

/** Filters for the blocked-attempts feed: window (or explicit range) +
 * paging. No agent/role/tool scope — the ban table carries none. */
export interface BanEnforcementFilters {
  window?: AuditWindow;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
}

export type AnomalySeverity = "high" | "medium";

/** One per-user anomaly burst from GET /audit/anomalies. */
export interface AuditAnomaly {
  user_id: string;
  severity: AnomalySeverity;
  deny: number;
  all: number;
  deny_rate: number;
  first_seen: string;
  last_seen: string;
}

// --- Usage dashboard (mirrors platform/api/schemas.py LlmInvocation*) -------

/** Totals for a slice: call volume + token counts. */
export interface LlmInvocationTotals {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
}

/** One model/agent/user bucket. */
export interface LlmInvocationBreakdownRow extends LlmInvocationTotals {
  key: string;
}

export interface LlmInvocationSummary {
  totals: LlmInvocationTotals;
  by_model: LlmInvocationBreakdownRow[];
  by_agent: LlmInvocationBreakdownRow[];
  by_user: LlmInvocationBreakdownRow[];
}

/** Scope filters for the usage summary. `undefined` = no filter. */
export interface LlmUsageScope {
  window?: AuditWindow;
  agent?: string;
  model?: string;
  user?: string;
  start_date?: string;
  end_date?: string;
}

/** Encode a module path for a URL while preserving the `/` separators the
 * `{path:path}` route depends on: each segment is percent-encoded, slashes
 * kept. A path typed into a prompt may hold `?`, `#`, `%`, or spaces, which
 * would otherwise be parsed as query/fragment/escape and hit the wrong route. */
function encodePath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
}

function qs(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    // undefined = omit. '' is kept: `role=` (empty value) is meaningful —
    // it selects the no-role bucket server-side.
    if (value !== undefined) search.set(key, String(value));
  }
  const str = search.toString();
  return str ? `?${str}` : "";
}

/**
 * Project-scoped API surface. ``projectId`` is required on every method
 * — there's no fallback constant. Callers read it from
 * :func:`useProjectScoped` and the page only mounts these calls once
 * the scope resolves to ``ready``.
 */
export const api = {
  listTokens: (projectId: string) =>
    request<TokenListItem[]>(`/v1/projects/${projectId}/tokens`),

  mintToken: (body: TokenMintRequest, projectId: string) =>
    request<TokenMintResponse>(`/v1/projects/${projectId}/tokens`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  revokeToken: (tokenId: string, projectId: string) =>
    request<void>(`/v1/projects/${projectId}/tokens/${tokenId}`, {
      method: "DELETE",
    }),

  listAgents: (projectId: string) =>
    request<AgentRead[]>(`/v1/projects/${projectId}/agents`),

  listAgentManifests: (projectId: string) =>
    request<AgentManifestView[]>(`/v1/projects/${projectId}/agents/manifest`),

  getAgent: (name: string, projectId: string) =>
    request<AgentRead>(`/v1/projects/${projectId}/agents/${name}`),

  updateAgent: (name: string, body: AgentUpdate, projectId: string) =>
    request<AgentRead>(`/v1/projects/${projectId}/agents/${name}`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),

  validatePolicy: (name: string, policy_yaml: string, projectId: string) =>
    request<ValidatePolicyResponse>(
      `/v1/projects/${projectId}/agents/${name}/validate`,
      { method: "POST", body: JSON.stringify({ policy_yaml }) },
    ),

  getAuditSummary: (scope: AuditScope, projectId: string) =>
    request<AuditSummary>(
      `/v1/projects/${projectId}/audit/summary${qs({ ...scope })}`,
    ),

  getAuditTimeseries: (scope: AuditScope, projectId: string) =>
    request<AuditTimeseriesPoint[]>(
      `/v1/projects/${projectId}/audit/timeseries${qs({ ...scope })}`,
    ),

  listAuditDecisions: (filters: AuditDecisionFilters, projectId: string) =>
    request<AuditDecisionPage>(
      `/v1/projects/${projectId}/audit/decisions${qs({ ...filters })}`,
    ),

  getAuditAnomalies: (scope: AnomalyScope, projectId: string) =>
    request<AuditAnomaly[]>(
      `/v1/projects/${projectId}/audit/anomalies${qs({ ...scope })}`,
    ),

  listBanEnforcements: (filters: BanEnforcementFilters, projectId: string) =>
    request<BanEnforcementPage>(
      `/v1/projects/${projectId}/audit/ban-enforcements${qs({ ...filters })}`,
    ),

  listBans: (projectId: string, includeRevoked = false) =>
    request<BanRead[]>(
      `/v1/projects/${projectId}/bans${
        includeRevoked ? "?include_revoked=true" : ""
      }`,
    ),

  createBan: (body: BanCreateBody, projectId: string) =>
    request<BanRead>(`/v1/projects/${projectId}/bans`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  revokeBan: (banId: string, projectId: string) =>
    request<void>(`/v1/projects/${projectId}/bans/${banId}`, {
      method: "DELETE",
    }),

  getLlmUsageSummary: (scope: LlmUsageScope, projectId: string) =>
    request<LlmInvocationSummary>(
      `/v1/projects/${projectId}/llm/summary${qs({ ...scope })}`,
    ),

  // --- policy modules (multi-module editor) --------------------------------
  // `path` may contain slashes (subfolders); the route's `{path:path}` keeps
  // them, so `encodePath` encodes each segment but preserves the separators.

  listPolicyModules: (projectId: string) =>
    request<PolicyModuleRead[]>(`/v1/projects/${projectId}/policy-modules`),

  upsertPolicyModule: (
    projectId: string,
    tier: PolicyTier,
    path: string,
    content: string,
  ) =>
    request<PolicyModuleRead>(
      `/v1/projects/${projectId}/policy-modules/${tier}/${encodePath(path)}`,
      { method: "PUT", body: JSON.stringify({ content }) },
    ),

  deletePolicyModule: (projectId: string, tier: PolicyTier, path: string) =>
    request<void>(
      `/v1/projects/${projectId}/policy-modules/${tier}/${encodePath(path)}`,
      { method: "DELETE" },
    ),

  movePolicyModule: (
    projectId: string,
    tier: PolicyTier,
    path: string,
    newPath: string,
  ) =>
    request<PolicyModuleRead>(
      `/v1/projects/${projectId}/policy-modules/${tier}/${encodePath(path)}`,
      { method: "PATCH", body: JSON.stringify({ new_path: newPath }) },
    ),

  getPolicyRoles: (projectId: string) =>
    request<{ roles: RoleBindings }>(
      `/v1/projects/${projectId}/policy-roles`,
    ).then((r) => r.roles),

  setPolicyRoles: (projectId: string, roles: RoleBindings) =>
    request<{ roles: RoleBindings }>(`/v1/projects/${projectId}/policy-roles`, {
      method: "PUT",
      body: JSON.stringify({ roles }),
    }).then((r) => r.roles),

  resolvePolicy: (projectId: string, role?: string) =>
    request<{ roles: ResolvedPolicy }>(
      `/v1/projects/${projectId}/policy/resolve${qs({ role })}`,
    ).then((r) => r.roles),

  checkPolicy: (projectId: string) =>
    request<{ ok: boolean; lints: PolicyLint[] }>(
      `/v1/projects/${projectId}/policy/check`,
    ),

  previewPolicy: (projectId: string, draft?: PolicyDraft | null) =>
    request<PolicyPreviewResponse>(`/v1/projects/${projectId}/policy/preview`, {
      method: "POST",
      body: JSON.stringify({ draft: draft ?? null }),
    }),

  testPolicy: (projectId: string, body: PolicyTestRequest) =>
    request<PolicyTestResponse>(`/v1/projects/${projectId}/policy/test`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
};
