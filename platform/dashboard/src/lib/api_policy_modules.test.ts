/**
 * Request-shape tests for the policy-module API surface: right verb, right
 * URL (nested paths stay un-encoded so `{path:path}` keeps the slashes),
 * right body, and the `.roles` unwrapping on the roles/resolve reads.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "./api";

interface Captured {
  url: string;
  method: string;
  body: unknown;
}

function capture(responseBody: unknown, status = 200): Captured[] {
  const calls: Captured[] = [];
  vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    });
    if (status === 204) return new Response(null, { status });
    return new Response(JSON.stringify(responseBody), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  return calls;
}

afterEach(() => vi.restoreAllMocks());

const P = "p1";

describe("policy-module api requests", () => {
  it("lists modules", async () => {
    const calls = capture([]);
    await api.listPolicyModules(P);
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-modules",
      method: "GET",
    });
  });

  it("upserts a nested capability without encoding the slash", async () => {
    const calls = capture({});
    await api.upsertPolicyModule(P, "capability", "team_a/payments", "yaml");
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-modules/capability/team_a/payments",
      method: "PUT",
      body: { content: "yaml" },
    });
  });

  it("percent-encodes path segments but keeps the slash separators", async () => {
    const calls = capture({});
    await api.upsertPolicyModule(P, "capability", "team a/pay #1", "y");
    expect(calls[0].url).toBe(
      "/v1/projects/p1/policy-modules/capability/team%20a/pay%20%231",
    );
  });

  it("moves a module via PATCH with new_path", async () => {
    const calls = capture({});
    await api.movePolicyModule(P, "capability", "old", "team_a/new");
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-modules/capability/old",
      method: "PATCH",
      body: { new_path: "team_a/new" },
    });
  });

  it("deletes a module", async () => {
    const calls = capture(null, 204);
    await api.deletePolicyModule(P, "boundary", "org_core");
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-modules/boundary/org_core",
      method: "DELETE",
    });
  });

  it("unwraps .roles on get + put", async () => {
    const calls = capture({ roles: { default: ["read_only"] } });
    const got = await api.getPolicyRoles(P);
    expect(got).toEqual({ default: ["read_only"] });

    const put = await api.setPolicyRoles(P, { billing: ["payments"] });
    expect(put).toEqual({ default: ["read_only"] }); // echoed stub body
    expect(calls[1]).toMatchObject({
      url: "/v1/projects/p1/policy-roles",
      method: "PUT",
      body: { roles: { billing: ["payments"] } },
    });
  });

  it("passes role as a query param on resolve and unwraps .roles", async () => {
    const calls = capture({ roles: { billing: { tools: {} } } });
    const resolved = await api.resolvePolicy(P, "billing");
    expect(resolved).toEqual({ billing: { tools: {} } });
    expect(calls[0].url).toBe("/v1/projects/p1/policy/resolve?role=billing");
  });

  it("omits the query string when no role is given", async () => {
    const calls = capture({ roles: {} });
    await api.resolvePolicy(P);
    expect(calls[0].url).toBe("/v1/projects/p1/policy/resolve");
  });

  it("posts a preview with the draft overlay", async () => {
    const calls = capture({ resolved: {}, lints: [] });
    await api.previewPolicy(P, {
      module: { tier: "capability", path: "x", content: "c" },
    });
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy/preview",
      method: "POST",
      body: {
        draft: { module: { tier: "capability", path: "x", content: "c" } },
      },
    });
  });

  it("posts a test call", async () => {
    const calls = capture({
      outcome: "allow",
      reason: null,
      violations: [],
      hint: null,
    });
    await api.testPolicy(P, {
      role: "billing",
      tool: "refund_order",
      args: { amount: 50 },
    });
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy/test",
      method: "POST",
      body: { role: "billing", tool: "refund_order", args: { amount: 50 } },
    });
  });
});

describe("policy-folder api requests", () => {
  it("lists folders", async () => {
    const calls = capture([]);
    await api.listPolicyFolders(P);
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-folders",
      method: "GET",
    });
  });

  it("creates a folder via PUT, encoding path segments", async () => {
    const calls = capture({ tier: "capability", path: "team a/x" });
    await api.createPolicyFolder(P, "capability", "team a/x");
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-folders/capability/team%20a/x",
      method: "PUT",
    });
  });

  it("deletes a folder", async () => {
    const calls = capture(null, 204);
    await api.deletePolicyFolder(P, "boundary", "team_a");
    expect(calls[0]).toMatchObject({
      url: "/v1/projects/p1/policy-folders/boundary/team_a",
      method: "DELETE",
    });
  });
});
