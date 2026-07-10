/**
 * Tests for the /agents page — scoped to the "ban agent" cross-page
 * tie-in (§9.6): the link deep-links into /bans?ban_agent=<name> and is
 * admin-gated, sitting beside the existing "edit policy" link.
 */

import { act, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useActive } from "@/lib/active";
import { AgentsPage } from "@/routes/Agents";
import { renderWithProviders } from "@/test/render";

const PROJECT = "p1";

const MANIFEST = {
  name: "support_bot",
  manifest: {
    name: "support_bot",
    description: null,
    framework: "langchain",
    model: null,
    system_prompt: null,
    tools: [],
  },
  version: 1,
  content_hash: "hash-1",
  updated_at: "2026-06-01T10:00:00Z",
};

function stubFetch(role: string) {
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL) => {
      const url = new URL(String(input), "http://localhost");
      switch (url.pathname) {
        case "/v1/orgs":
          return json([
            {
              id: "org-1",
              slug: "acme",
              name: "Acme Inc",
              created_at: "2026-01-01T00:00:00Z",
              role,
            },
          ]);
        case "/v1/orgs/org-1/projects":
          return json([
            {
              id: PROJECT,
              org_id: "org-1",
              name: "demo-project",
              created_at: "2026-01-01T00:00:00Z",
            },
          ]);
        case `/v1/projects/${PROJECT}/agents/manifest`:
          return json([MANIFEST]);
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
}

describe("AgentsPage — ban tie-in", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an admin a ban-agent link pointing at the prefilled /bans route", async () => {
    stubFetch("admin");
    renderWithProviders(<AgentsPage />, { initialRoute: "/agents" });

    const link = await screen.findByRole("link", { name: /ban agent/i });
    expect(link).toHaveAttribute("href", "/bans?ban_agent=support_bot");
  });

  it("hides the ban-agent link from a plain member", async () => {
    stubFetch("member");
    renderWithProviders(<AgentsPage />, { initialRoute: "/agents" });

    // The edit-policy link still renders, proving the header mounted —
    // only the ban affordance is gated away.
    await screen.findByRole("link", { name: /edit policy/i });
    await waitFor(() =>
      expect(screen.queryByRole("link", { name: /ban agent/i })).toBeNull(),
    );
  });
});
