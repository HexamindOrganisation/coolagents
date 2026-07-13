/**
 * Tests for the ban hooks (lib/bans.ts).
 *
 * Covers the wire contract the Bans page and the cross-page tie-ins
 * depend on: useBans fetch shape, useCreateBan sending only the target
 * field that matches ban_type (+ cache invalidation + 409 surfacing),
 * useRevokeBan's DELETE, and useCanManageBans' role gate.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useActive } from "./active";
import { useBans, useCanManageBans, useCreateBan, useRevokeBan } from "./bans";

const PROJECT = "p1";

function makeQc(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

function wrapper(qc: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const BAN = {
  id: "ban_1",
  project_id: PROJECT,
  ban_type: "user",
  target_agent_name: null,
  target_user_id: "u1",
  reason: "spam",
  created_by_user_id: "creator",
  created_at: "2026-06-01T10:00:00Z",
  revoked_at: null,
  active: true,
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useBans", () => {
  it("fetches active bans for the project", async () => {
    const calls: string[] = [];
    vi.spyOn(window, "fetch").mockImplementation(async (input) => {
      calls.push(String(input));
      return jsonResponse([BAN]);
    });

    const { result } = renderHook(() => useBans(PROJECT), {
      wrapper: wrapper(makeQc()),
    });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toHaveLength(1);
    expect(calls[0]).toBe(`/v1/projects/${PROJECT}/bans`);
  });

  it("adds include_revoked=true when requested", async () => {
    const calls: string[] = [];
    vi.spyOn(window, "fetch").mockImplementation(async (input) => {
      calls.push(String(input));
      return jsonResponse([]);
    });

    const { result } = renderHook(
      () => useBans(PROJECT, { includeRevoked: true }),
      { wrapper: wrapper(makeQc()) },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(calls[0]).toBe(`/v1/projects/${PROJECT}/bans?include_revoked=true`);
  });

  it("stays disabled while projectId is null", () => {
    const fetchSpy = vi.spyOn(window, "fetch");
    renderHook(() => useBans(null), { wrapper: wrapper(makeQc()) });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("useCreateBan", () => {
  it("sends only the agent target for an agent ban, and invalidates", async () => {
    let sentBody: unknown;
    vi.spyOn(window, "fetch").mockImplementation(async (_input, init) => {
      sentBody = JSON.parse(String(init?.body));
      return jsonResponse({ ...BAN, ban_type: "agent" }, 201);
    });
    const qc = makeQc();
    const invalidate = vi.spyOn(qc, "invalidateQueries");

    const { result } = renderHook(() => useCreateBan(), {
      wrapper: wrapper(qc),
    });
    await act(async () => {
      await result.current.mutateAsync({
        projectId: PROJECT,
        ban_type: "agent",
        target_agent_name: "a1",
      });
    });

    // No target_user_id, no reason — the server's cross-validator rejects
    // a body that sets the wrong target, so the hook must not send it.
    expect(sentBody).toEqual({ ban_type: "agent", target_agent_name: "a1" });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["bans", PROJECT] });
  });

  it("sends the user target and reason for a user ban", async () => {
    let sentBody: unknown;
    vi.spyOn(window, "fetch").mockImplementation(async (_input, init) => {
      sentBody = JSON.parse(String(init?.body));
      return jsonResponse(BAN, 201);
    });

    const { result } = renderHook(() => useCreateBan(), {
      wrapper: wrapper(makeQc()),
    });
    await act(async () => {
      await result.current.mutateAsync({
        projectId: PROJECT,
        ban_type: "user",
        target_user_id: "u1",
        reason: "spam",
      });
    });

    expect(sentBody).toEqual({
      ban_type: "user",
      target_user_id: "u1",
      reason: "spam",
    });
  });

  it("surfaces a 409 (duplicate active ban) as an ApiError", async () => {
    vi.spyOn(window, "fetch").mockResolvedValue(
      jsonResponse({ detail: "already exists" }, 409),
    );

    const { result } = renderHook(() => useCreateBan(), {
      wrapper: wrapper(makeQc()),
    });

    await expect(
      result.current.mutateAsync({
        projectId: PROJECT,
        ban_type: "user",
        target_user_id: "u1",
      }),
    ).rejects.toMatchObject({ status: 409 });
  });
});

describe("useRevokeBan", () => {
  it("DELETEs the ban and invalidates the project's bans", async () => {
    const calls: { url: string; method?: string }[] = [];
    vi.spyOn(window, "fetch").mockImplementation(async (input, init) => {
      calls.push({ url: String(input), method: init?.method });
      return new Response(null, { status: 204 });
    });
    const qc = makeQc();
    const invalidate = vi.spyOn(qc, "invalidateQueries");

    const { result } = renderHook(() => useRevokeBan(), {
      wrapper: wrapper(qc),
    });
    await act(async () => {
      await result.current.mutateAsync({ projectId: PROJECT, banId: "ban_1" });
    });

    expect(calls[0]).toEqual({
      url: `/v1/projects/${PROJECT}/bans/ban_1`,
      method: "DELETE",
    });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ["bans", PROJECT] });
  });
});

describe("useCanManageBans", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
    });
  });

  function stubRole(role: string) {
    vi.spyOn(window, "fetch").mockImplementation(async () =>
      jsonResponse([
        {
          id: "org-1",
          slug: "acme",
          name: "Acme",
          created_at: "2026-01-01T00:00:00Z",
          role,
        },
      ]),
    );
    return renderHook(() => useCanManageBans(), { wrapper: wrapper(makeQc()) });
  }

  it("is true for an owner", async () => {
    const { result } = stubRole("owner");
    await waitFor(() => expect(result.current).toBe(true));
  });

  it("is true for an admin", async () => {
    const { result } = stubRole("admin");
    await waitFor(() => expect(result.current).toBe(true));
  });

  it("is false for a plain member", async () => {
    const { result } = stubRole("member");
    await waitFor(() => expect(window.fetch).toHaveBeenCalled());
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current).toBe(false);
  });
});
