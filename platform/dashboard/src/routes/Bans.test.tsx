/**
 * Tests for the /bans page.
 *
 * Invariants:
 *   1. no-project scope → the empty state, no ban fetch.
 *   2. Admin sees the active-bans list + a Create ban CTA.
 *   3. Non-admins are hard-blocked (both ban reads are admin-only
 *      server-side) — "Admins only", no Create ban.
 *   4. The create dialog opens from the header CTA.
 *   5. Deep links from the tie-ins (`?ban_user=` / `?ban_agent=`)
 *      auto-open the dialog, pre-set to the right type + target.
 *   6. Revoke confirms, then DELETEs the ban.
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { BanEnforcementRow } from "@/lib/api";
import { useActive } from "@/lib/active";
import { BansPage } from "@/routes/Bans";
import { renderWithProviders } from "@/test/render";

const PROJECT = "p1";

interface Call {
  url: string;
  method: string;
  body?: unknown;
}

const BAN = {
  id: "ban_1",
  project_id: PROJECT,
  ban_type: "user",
  target_agent_name: null,
  target_user_id: "u1",
  reason: "spam",
  created_by_user_id: "usr_creator",
  created_by_email: "creator@acme.dev",
  created_at: "2026-06-01T10:00:00Z",
  revoked_at: null,
  active: true,
};

const ENFORCEMENT: BanEnforcementRow = {
  event_id: "evt-1",
  occurred_at: "2026-06-01T10:00:00Z",
  received_at: "2026-06-01T10:00:01Z",
  agent_name: "healthcare_agent",
  session_id: "sess-1",
  user_id: "clinician_nurse",
  ban_type: "agent",
  ban_id: "ban_evt",
  reason: "incident 42",
};

interface StubOptions {
  role?: string;
  bans?: unknown[];
  agents?: { name: string }[];
  enforcements?: BanEnforcementRow[];
}

function stubFetch({
  role = "owner",
  bans = [],
  agents = [],
  enforcements = [],
}: StubOptions = {}): Call[] {
  const calls: Call[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const raw = typeof input === "string" ? input : input.toString();
      const url = new URL(raw, "http://localhost");
      const method = init?.method ?? "GET";
      calls.push({
        url: url.pathname + url.search,
        method,
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });

      switch (true) {
        case url.pathname === "/v1/orgs":
          return json([
            {
              id: "org-1",
              slug: "acme",
              name: "Acme Inc",
              created_at: "2026-01-01T00:00:00Z",
              role,
            },
          ]);
        case url.pathname === "/v1/orgs/org-1/projects":
          return json([
            {
              id: PROJECT,
              org_id: "org-1",
              name: "demo-project",
              created_at: "2026-01-01T00:00:00Z",
            },
          ]);
        case url.pathname === `/v1/projects/${PROJECT}/bans` &&
          method === "POST":
          return json({ ...BAN, id: "ban_new" }, 201);
        case url.pathname === `/v1/projects/${PROJECT}/bans`:
          return json(bans);
        case url.pathname.startsWith(`/v1/projects/${PROJECT}/bans/`) &&
          method === "DELETE":
          return new Response(null, { status: 204 });
        case url.pathname ===
          `/v1/projects/${PROJECT}/audit/ban-enforcements`: {
          // Paginate like the real endpoint: slice by offset/limit, report
          // the true unpaginated total.
          const offset = Number(url.searchParams.get("offset") ?? 0);
          const limit = Number(url.searchParams.get("limit") ?? 25);
          return json({
            rows: enforcements.slice(offset, offset + limit),
            total: enforcements.length,
            limit,
            offset,
          });
        }
        case url.pathname === `/v1/projects/${PROJECT}/agents`:
          return json(agents);
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
  return calls;
}

describe("BansPage", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the no-project empty state and skips the ban fetch", async () => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: null });
    });
    const calls = stubFetch();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    expect(await screen.findByText("No project selected")).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("/bans"))).toBe(false);
  });

  it("lists active bans and shows the Create ban CTA for an admin", async () => {
    stubFetch({ role: "admin", bans: [BAN] });
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    expect(await screen.findByText("u1")).toBeInTheDocument();
    // "Created by" shows the resolved email, not the raw user id.
    expect(screen.getByText("creator@acme.dev")).toBeInTheDocument();
    expect(screen.queryByText("usr_creator")).toBeNull();
    expect(
      screen.getByRole("button", { name: /create ban/i }),
    ).toBeInTheDocument();
  });

  it("hard-blocks non-admins with no Create ban CTA", async () => {
    stubFetch({ role: "member", bans: [BAN] });
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    expect(await screen.findByText("Admins only")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /create ban/i })).toBeNull();
  });

  it("opens the create dialog from the header CTA", async () => {
    stubFetch({ role: "admin" });
    const user = userEvent.setup();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    await user.click(
      await screen.findByRole("button", { name: /create ban/i }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(
      within(dialog).getByRole("heading", { name: "Create ban" }),
    ).toBeInTheDocument();
  });

  it("auto-opens the dialog pre-set to User from ?ban_user=", async () => {
    stubFetch({ role: "admin" });
    renderWithProviders(<BansPage />, { initialRoute: "/bans?ban_user=u-9" });

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("User ID")).toBeInTheDocument();
    expect(within(dialog).getByDisplayValue("u-9")).toBeInTheDocument();
  });

  it("auto-opens the dialog pre-set to Agent from ?ban_agent=", async () => {
    stubFetch({ role: "admin", agents: [{ name: "support_bot" }] });
    renderWithProviders(<BansPage />, {
      initialRoute: "/bans?ban_agent=support_bot",
    });

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Agent to ban")).toBeInTheDocument();
  });

  it("does not open a phantom dialog when a non-admin follows a deep link", async () => {
    stubFetch({ role: "member" });
    renderWithProviders(<BansPage />, { initialRoute: "/bans?ban_user=u-9" });

    // Non-admin lands on the admin-required notice, and the prefill effect
    // must not leave a dialog dangling for a branch that never renders.
    expect(await screen.findByText("Admins only")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("revokes a ban after confirmation", async () => {
    const calls = stubFetch({ role: "admin", bans: [BAN] });
    const user = userEvent.setup();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    // Row revoke → confirm dialog → confirm.
    await user.click(await screen.findByRole("button", { name: /revoke/i }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Revoke ban?")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: /^revoke$/i }));

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === "DELETE" &&
            c.url === `/v1/projects/${PROJECT}/bans/ban_1`,
        ),
      ).toBe(true),
    );
  });

  it("opens a detail drawer with full info when a blocked attempt is clicked", async () => {
    stubFetch({ role: "admin", enforcements: [ENFORCEMENT] });
    const user = userEvent.setup();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    // Click the row (its reason cell is unique before the drawer opens).
    await user.click(await screen.findByText("incident 42"));

    // Drawer-only content: the refusal banner, the Enforcement section, and
    // the session id (not shown in the table row).
    expect(
      screen.getByText(/Refused before the model ran/),
    ).toBeInTheDocument();
    expect(screen.getByText("Enforcement")).toBeInTheDocument();
    expect(screen.getByText("sess-1")).toBeInTheDocument();
  });

  it("pages blocked attempts by offset and hides Load more at the end", async () => {
    // 30 rows over a PAGE_SIZE of 25 → two pages. The old growing-limit code
    // stranded rows past the server's 200 cap behind a stuck button; offset
    // paging reaches them and the button clears once all are loaded.
    const many: BanEnforcementRow[] = Array.from({ length: 30 }, (_, i) => ({
      ...ENFORCEMENT,
      event_id: `evt-${i}`,
      ban_id: `ban_${i}`,
      reason: `r${i}`,
    }));
    stubFetch({ role: "admin", enforcements: many });
    const user = userEvent.setup();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    // First page: rows 0–24, and a Load more button (row 25 not yet loaded).
    await screen.findByText("r0");
    expect(screen.getByText("r24")).toBeInTheDocument();
    expect(screen.queryByText("r25")).toBeNull();

    // Second page appends the remainder; then the button is gone.
    await user.click(screen.getByRole("button", { name: /load .* more/i }));
    expect(await screen.findByText("r29")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /load .* more/i })).toBeNull();
  });

  it("closes the blocked-attempt drawer", async () => {
    stubFetch({ role: "admin", enforcements: [ENFORCEMENT] });
    const user = userEvent.setup();
    renderWithProviders(<BansPage />, { initialRoute: "/bans" });

    await user.click(await screen.findByText("incident 42"));
    expect(
      screen.getByText(/Refused before the model ran/),
    ).toBeInTheDocument();

    await user.click(screen.getByTitle("Close (Esc)"));
    expect(screen.queryByText(/Refused before the model ran/)).toBeNull();
  });
});
