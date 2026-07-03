/**
 * Smoke tests for the public /invites/:inviteId/accept landing.
 *
 * The page is a state machine over (preview-query state) × (signed-in?,
 * email matches?). We exercise one row of that table per test:
 *
 *   1. Signed-in, email matches → Accept button → POST → navigate
 *   2. Preview 404 → "invitation not found" card
 *   3. Preview 410 → "invitation expired" card
 *   4. Signed-in, email mismatch → "isn't for this account" card (no Accept)
 *   5. Signed-out → "Sign in to accept" CTA (no Accept)
 *
 * Post-accept race cases (403/409 returned from the accept POST after
 * a successful preview) are covered by the backend integration tests
 * in platform/api/tests/domains/invitations/test_invites.py — replicating them here would
 * mostly test sonner's portal rendering, which jsdom + RTL can't reach
 * cleanly.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router-dom";

import { AcceptInvitationPage } from "@/routes/AcceptInvitation";
import { renderWithProviders } from "@/test/render";

type RouteSpec =
  | { status?: number; json: unknown }
  | { status: number; body?: string };

/** Tiny router for the fetch spy — keyed by ``METHOD path``. Unknown
 * routes 404 with a JSON error envelope so React Query surfaces them
 * as ApiError(404), the same shape as production. */
function stubFetch(routes: Record<string, RouteSpec>): void {
  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const path = url.split("?")[0];
      const method = (init?.method ?? "GET").toUpperCase();
      const key = `${method} ${path}`;
      const spec = routes[key];
      if (!spec) {
        return new Response(JSON.stringify({ detail: `no stub for ${key}` }), {
          status: 404,
        });
      }
      if ("json" in spec) {
        return new Response(JSON.stringify(spec.json), {
          status: spec.status ?? 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(spec.body ?? "", { status: spec.status });
    },
  );
}

function renderPage(inviteId: string) {
  return renderWithProviders(
    <Routes>
      <Route
        path="/invites/:inviteId/accept"
        element={<AcceptInvitationPage />}
      />
      {/* Landing target after a successful accept — we don't render
          anything meaningful, just a sentinel the test can spot. */}
      <Route
        path="/orgs/:orgId/members"
        element={<div data-testid="members-page" />}
      />
      <Route path="/sign-in" element={<div data-testid="signin-page" />} />
    </Routes>,
    { initialRoute: `/invites/${inviteId}/accept` },
  );
}

const PREVIEW = {
  email: "alice@example.com",
  role: "admin",
  invited_by_email: "me@example.com",
  org_id: "org-1",
  org_name: "Acme Inc",
  org_slug: "acme",
  expires_at: "2030-01-01T00:00:00Z",
};

const USER_ALICE = {
  id: "alice-uid",
  email: "alice@example.com",
  is_active: true,
  is_superuser: false,
  is_verified: true,
};

const USER_BOB = {
  id: "bob-uid",
  email: "bob@example.com",
  is_active: true,
  is_superuser: false,
  is_verified: true,
};

describe("AcceptInvitationPage", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("signed-in matching email → Accept → POST → lands on members page", async () => {
    stubFetch({
      "GET /v1/invites/inv-1": { json: PREVIEW },
      "GET /v1/users/me": { json: USER_ALICE },
      "POST /v1/invites/inv-1/accept": {
        json: {
          user_id: "alice-uid",
          email: "alice@example.com",
          role: "admin",
          joined_at: "2026-06-03T00:00:00Z",
        },
      },
    });

    const user = userEvent.setup();
    renderPage("inv-1");

    // Wait for the preview to land and the Accept card to render.
    await waitFor(() => {
      expect(screen.getByText(/Join Acme Inc/i)).toBeInTheDocument();
    });

    await user.click(screen.getByText("Accept invitation"));

    // Navigation target is the joined org's members page.
    await waitFor(() => {
      expect(screen.getByTestId("members-page")).toBeInTheDocument();
    });
  });

  it('preview 404 renders the "not found" card with no Accept button', async () => {
    stubFetch({
      "GET /v1/invites/missing-1": {
        status: 404,
        json: { detail: "invitation not found" },
      },
      "GET /v1/users/me": { json: USER_ALICE },
    });

    renderPage("missing-1");

    await waitFor(() => {
      expect(screen.getByText(/Invitation not found/i)).toBeInTheDocument();
    });
    expect(screen.queryByText("Accept invitation")).not.toBeInTheDocument();
  });

  it('preview 410 renders the "expired" card', async () => {
    stubFetch({
      "GET /v1/invites/old-1": {
        status: 410,
        json: { detail: "invitation expired or already used" },
      },
      "GET /v1/users/me": { json: USER_ALICE },
    });

    renderPage("old-1");

    await waitFor(() => {
      expect(screen.getByText(/Invitation expired/i)).toBeInTheDocument();
    });
    expect(screen.queryByText("Accept invitation")).not.toBeInTheDocument();
  });

  it('signed-in wrong email → "not for this account" card, no Accept', async () => {
    stubFetch({
      "GET /v1/invites/inv-1": { json: PREVIEW },
      "GET /v1/users/me": { json: USER_BOB },
    });

    renderPage("inv-1");

    await waitFor(() => {
      expect(screen.getByText(/isn't for this account/i)).toBeInTheDocument();
    });
    // The mismatch card names both addresses so the user knows which
    // account to switch to. The invited address shows twice (in the
    // description sentence + in the alert callout); we just want to
    // assert both names appear somewhere.
    expect(screen.getAllByText("alice@example.com").length).toBeGreaterThan(0);
    expect(screen.getByText("bob@example.com")).toBeInTheDocument();
    expect(screen.queryByText("Accept invitation")).not.toBeInTheDocument();
    expect(screen.getByText(/Sign out & switch account/i)).toBeInTheDocument();
  });

  it('signed-out → "Sign in to accept" CTA, no Accept', async () => {
    // /v1/users/me returns 401 → useUser resolves to user=null. No
    // ``credentials: include`` complications — we just return the
    // status the backend would emit for an anonymous request.
    stubFetch({
      "GET /v1/invites/inv-1": { json: PREVIEW },
      "GET /v1/users/me": { status: 401, body: "" },
    });

    renderPage("inv-1");

    await waitFor(() => {
      expect(
        screen.getByText(/You're invited to Acme Inc/i),
      ).toBeInTheDocument();
    });
    expect(screen.getByText("Sign in to accept")).toBeInTheDocument();
    expect(screen.queryByText("Accept invitation")).not.toBeInTheDocument();
  });
});
