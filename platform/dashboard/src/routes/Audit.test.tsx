/**
 * Smoke tests for the /audit page.
 *
 * Five load-bearing invariants:
 *
 *   1. Picking an agent in the filter bar re-queries with `agent=` in
 *      the URL — the filter state actually reaches the API.
 *   2. The outcome KPI cards toggle the outcome filter (on → chip +
 *      `outcome=` in the decisions URL; off → chip gone).
 *   3. Clicking a table row opens the detail drawer; Esc closes it.
 *   4. Selecting a row fetches its session siblings (`session_id=`)
 *      and the "Same session" list cross-links to the sibling event.
 *   5. The date filter row opens via the Custom toggle, reflects custom
 *      date selections, and collapses when a preset range is selected.
 *   6. Clicking a breakdown bar sets the dimension filter; clicking it
 *      again clears it.
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes, useSearchParams } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditAnomaly, AuditDecisionRow } from "@/lib/api";
import { useActive } from "@/lib/active";
import { EMPTY_AUDIT_FILTERS, useAuditFilters } from "@/lib/audit-filters";
import { AuditPage } from "@/routes/Audit";
import { renderWithProviders } from "@/test/render";

const PROJECT = "p1";

const counts = (all: number, allow: number, deny: number, appr = 0) => ({
  all,
  allow,
  deny,
  needs_approval: appr,
});

const SUMMARY = {
  totals: counts(10, 6, 4),
  by_agent: [
    { key: "example_agent", ...counts(9, 6, 3) },
    { key: "scraper", ...counts(1, 0, 1) },
  ],
  by_role: [
    { key: "analyst", ...counts(6, 6, 0) },
    // The no-role bucket arrives as a raw "" key over the wire.
    { key: "", ...counts(4, 0, 4) },
  ],
  by_tool: [{ key: "read_file", ...counts(4, 0, 4) }],
};

const ROW: AuditDecisionRow = {
  event_id: "evt-1",
  occurred_at: "2026-06-01T10:00:00Z",
  received_at: "2026-06-01T10:00:01Z",
  agent_name: "example_agent",
  agent_version_id: "v1",
  session_id: "sess-1",
  user_id: "u1",
  tool_name: "read_file",
  role: "",
  user_roles: [],
  deciding_role: "",
  outcome: "deny",
  error_type: "policy_denied",
  reason: "blocked by policy",
  violations: ["no-secrets"],
  hint: null,
  arguments: { path: "/etc/passwd" },
  attributes: { department: "finance" },
};

const ANOMALY: AuditAnomaly = {
  user_id: "bob",
  severity: "high",
  deny: 8,
  all: 10,
  deny_rate: 0.8,
  first_seen: "2026-06-01T09:00:00Z",
  last_seen: "2026-06-01T10:00:00Z",
};

/** Sibling event in the same session — only reachable via the drawer's
 * "Same session" list (the main table stub returns ROW alone). */
const SIBLING: AuditDecisionRow = {
  ...ROW,
  event_id: "evt-2",
  tool_name: "send_email",
  outcome: "allow",
  reason: "",
  violations: [],
  // A multi-role caller granted by its *second* role — the case the legacy
  // scalar `role` could not express.
  role: "support",
  user_roles: ["support", "billing"],
  deciding_role: "billing",
  // No ABAC bag — the drawer must omit the section rather than show an empty box.
  attributes: null,
};

/**
 * Same fetch-stub helper pattern as Orgs.test.tsx, extended to record
 * every requested URL (path + query) so tests can assert what filter
 * state actually reached the API.
 */
function stubFetch(anomalies: AuditAnomaly[] = [], role = "owner"): string[] {
  const calls: string[] = [];
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL) => {
      const raw = typeof input === "string" ? input : input.toString();
      const url = new URL(raw, "http://localhost");
      calls.push(url.pathname + url.search);

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
        case `/v1/projects/${PROJECT}/audit/summary`:
          return json(SUMMARY);
        case `/v1/projects/${PROJECT}/audit/timeseries`:
          return json([]);
        case `/v1/projects/${PROJECT}/audit/decisions`: {
          // The drawer's session drill-down vs the main table.
          if (url.searchParams.get("session_id") === "sess-1") {
            return json({
              rows: [ROW, SIBLING],
              total: 2,
              limit: 12,
              offset: 0,
            });
          }
          return json({ rows: [ROW], total: 1, limit: 40, offset: 0 });
        }
        case `/v1/projects/${PROJECT}/audit/anomalies`:
          return json(anomalies);
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
  return calls;
}

/** Open the detail drawer by clicking ROW's line in the events table. */
async function openDrawer(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByText("blocked by policy"));
  // The drawer header renders the event id — unique to the drawer.
  await screen.findByText("evt-1");
}

/** Landing route for the "Ban user" tie-in — echoes the deep-link query
 * param so tests assert exactly what the anomaly row navigated to. */
function BansSentinel() {
  const [sp] = useSearchParams();
  return <div>ban_user={sp.get("ban_user")}</div>;
}

describe("AuditPage", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
      // The filter store is module-global — reset so a filter dialled in
      // by test A doesn't narrow test B's queries.
      useAuditFilters.setState({
        filters: EMPTY_AUDIT_FILTERS,
        tableLimit: 40,
      });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("agent filter selection lands in the next query URL", async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    // Wait for data to land, then open the agent select (Radix trigger)
    // and pick an option from the popup.
    await screen.findByText("blocked by policy");
    // The subtitle names the ACTIVE project — not a hardcoded constant.
    expect(await screen.findByText("demo-project")).toBeInTheDocument();

    // With no filters set, optionsQ and summaryQ hash to the same query key
    // and dedupe into ONE fetch of the unscoped summary.
    expect(
      calls.filter(
        (u) => u === `/v1/projects/${PROJECT}/audit/summary?window=30d`,
      ),
    ).toHaveLength(1);
    // Radix puts pointer-events:none on the value span — click the trigger.
    await user.click(screen.getByText("All agents").closest("button")!);
    await user.click(
      await screen.findByRole("option", { name: "example_agent" }),
    );

    await waitFor(() => {
      expect(
        calls.some(
          (u) =>
            u.includes("/audit/decisions") && u.includes("agent=example_agent"),
        ),
      ).toBe(true);
    });
    // The scoped summary (KPIs/breakdown) narrows too.
    expect(
      calls.some(
        (u) =>
          u.includes("/audit/summary") && u.includes("agent=example_agent"),
      ),
    ).toBe(true);
  });

  it('maps the empty-role bucket to "(none)" locally and queries role=', async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    // The "" key from the wire displays as "(none)" in the dropdown…
    await screen.findByText("blocked by policy");
    await user.click(screen.getByText("All roles").closest("button")!);
    await user.click(await screen.findByRole("option", { name: "(none)" }));

    // …and selecting it sends `role=` (empty value) — no "(none)" sentinel
    // ever leaves the dashboard.
    await waitFor(() => {
      expect(
        calls.some(
          (u) => u.includes("/audit/decisions") && /[?&]role=(&|$)/.test(u),
        ),
      ).toBe(true);
    });
    expect(
      calls.some((u) => u.includes("(none)") || u.includes("%28none%29")),
    ).toBe(false);
  });

  it("outcome KPI card toggles the outcome filter", async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await user.click(await screen.findByText("Denied"));

    // On: the decisions query narrows and the active chip appears.
    await waitFor(() => {
      expect(
        calls.some(
          (u) => u.includes("/audit/decisions") && u.includes("outcome=deny"),
        ),
      ).toBe(true);
    });
    // ActiveChips only renders when a filter is set — "Clear all" is its
    // unique anchor ("deny" alone also matches the FilterBar segment).
    expect(screen.getByText("Clear all")).toBeInTheDocument();

    // Off: clicking the same card clears the filter again.
    await user.click(screen.getByText("Denied"));
    await waitFor(() => {
      expect(screen.queryByText("Clear all")).not.toBeInTheDocument();
    });
  });

  it("clicking a breakdown bar sets the dimension filter; clicking it again clears it", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await screen.findByText("blocked by policy");
    // "read_file" also appears in the events table — scope the query to
    // the breakdown card (identified by its Tabs) to avoid ambiguity, and
    // grab the row once since a second lookup would stay ambiguous too.
    const breakdownCard = screen
      .getByRole("tablist")
      .closest(".p-6") as HTMLElement;
    const bar = within(breakdownCard)
      .getByText("read_file")
      .closest(".mb-\\[11px\\]") as HTMLElement;

    await user.click(bar);
    await waitFor(() => {
      expect(useAuditFilters.getState().filters.tool).toBe("read_file");
    });

    await user.click(bar);
    await waitFor(() => {
      expect(useAuditFilters.getState().filters.tool).toBe("");
    });
  });

  it("row click opens the detail drawer; Esc closes it", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await openDrawer(user);
    // Drawer body renders the violation tag and the envelope section.
    expect(screen.getByText("no-secrets")).toBeInTheDocument();
    expect(screen.getByText("Envelope")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    await waitFor(() => {
      expect(screen.queryByText("evt-1")).not.toBeInTheDocument();
    });
  });

  it("drawer renders the context attributes bag that drove the decision", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await openDrawer(user);
    expect(screen.getByText("Context attributes")).toBeInTheDocument();
    expect(
      screen.getByText(
        (_, el) =>
          el?.tagName === "PRE" &&
          (el.textContent ?? "").includes('"department": "finance"'),
      ),
    ).toBeInTheDocument();
  });

  it("drawer omits the context attributes section when there is no bag", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await openDrawer(user);
    // Drill to the sibling, whose attributes are null.
    const sibling = await screen.findByText("send_email");
    await user.click(sibling);
    await screen.findByText("evt-2");

    expect(screen.queryByText("Context attributes")).not.toBeInTheDocument();
  });

  it("drawer names the roles evaluated and the role that granted the call", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await openDrawer(user);
    const sibling = await screen.findByText("send_email");
    await user.click(sibling);
    await screen.findByText("evt-2");

    expect(screen.getByText("roles evaluated")).toBeInTheDocument();
    expect(screen.getByText("support, billing")).toBeInTheDocument();
    // The granting role is the second one — reading `role` would have said
    // "support" and misattributed the grant.
    expect(screen.getByText("granted by")).toBeInTheDocument();
    expect(screen.getByText("billing")).toBeInTheDocument();
  });

  it("drawer marks a deny as granted by no role", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    // ROW is a deny with no roles recorded at all.
    await openDrawer(user);
    expect(screen.getByText("∅ none")).toBeInTheDocument();
    expect(screen.getByText("∅ none — no role granted it")).toBeInTheDocument();
  });

  it("same-session list drills into the sibling event", async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<AuditPage />);

    await openDrawer(user);

    // Selecting the row fires the session drill-down query…
    await waitFor(() => {
      expect(
        calls.some(
          (u) =>
            u.includes("/audit/decisions") && u.includes("session_id=sess-1"),
        ),
      ).toBe(true);
    });
    // …whose result lists the sibling (selected event excluded).
    const sibling = await screen.findByText("send_email");
    await user.click(sibling);

    // The drawer now shows the sibling event.
    await screen.findByText("evt-2");
    expect(screen.queryByText("evt-1")).not.toBeInTheDocument();
  });

  describe("date filter", () => {
    it("clicking Custom opens a row showing the implied range label", async () => {
      stubFetch();
      const user = userEvent.setup();
      renderWithProviders(<AuditPage />);

      await screen.findByText("blocked by policy");

      await user.click(screen.getByText("Custom"));

      // The date picker button appears with a range label (implied 30d window)
      expect(screen.getByRole("button", { name: /→/ })).toBeInTheDocument();
    });

    it("range toggle button clears an active date filter and hides the row", async () => {
      stubFetch();
      const user = userEvent.setup();

      act(() => {
        useAuditFilters.setState({
          filters: {
            ...EMPTY_AUDIT_FILTERS,
            customMode: true,
            start_date: new Date(2026, 5, 1),
            end_date: new Date(2026, 5, 15),
          },
          tableLimit: 40,
        });
      });

      renderWithProviders(<AuditPage />);
      await screen.findByText("blocked by policy");

      // Dates are pre-set so the date row renders immediately
      expect(
        screen.getByRole("button", { name: /Jun 1, 2026 → Jun 15, 2026/ }),
      ).toBeInTheDocument();

      // Click any range preset — it clears dates and dismisses the row
      await user.click(screen.getByText("7d"));

      await waitFor(() => {
        expect(useAuditFilters.getState().filters.start_date).toBeNull();
        expect(useAuditFilters.getState().filters.end_date).toBeNull();
      });
      expect(
        screen.queryByRole("button", { name: /→/ }),
      ).not.toBeInTheDocument();
    });

    it("dates set in the store render as the formatted range in the picker button", async () => {
      stubFetch();
      const user = userEvent.setup();
      renderWithProviders(<AuditPage />);

      await screen.findByText("blocked by policy");
      await user.click(screen.getByText("Custom"));

      act(() => {
        useAuditFilters.setState((s) => ({
          ...s,
          filters: {
            ...s.filters,
            start_date: new Date(2026, 5, 1),
            end_date: new Date(2026, 5, 15),
          },
        }));
      });

      await screen.findByRole("button", { name: /Jun 1, 2026 → Jun 15, 2026/ });
    });

    it("Clear all collapses the date row and resets range when Custom is active", async () => {
      stubFetch();
      const user = userEvent.setup();

      // Seed: custom range + an agent filter so ActiveChips renders
      act(() => {
        useAuditFilters.setState({
          filters: {
            ...EMPTY_AUDIT_FILTERS,
            customMode: true,
            agent: "example_agent",
            start_date: new Date(2026, 5, 1),
            end_date: new Date(2026, 5, 15),
          },
          tableLimit: 40,
        });
      });

      renderWithProviders(<AuditPage />);
      await screen.findByText("blocked by policy");

      // Date row is visible and agent chip is showing (Clear all button confirms ActiveChips rendered)
      expect(
        screen.getByRole("button", { name: /Jun 1, 2026 → Jun 15, 2026/ }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /clear all/i }),
      ).toBeInTheDocument();

      // Click "Clear all"
      await user.click(screen.getByRole("button", { name: /clear all/i }));

      // Date row collapses and range reverts to a preset
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /→/ }),
        ).not.toBeInTheDocument();
      });
      expect(useAuditFilters.getState().filters.customMode).toBe(false);
      expect(useAuditFilters.getState().filters.start_date).toBeNull();
      expect(useAuditFilters.getState().filters.end_date).toBeNull();
    });

    it("selecting a preset dismisses the date picker and clears the dates", async () => {
      stubFetch();
      const user = userEvent.setup();
      renderWithProviders(<AuditPage />);

      await screen.findByText("blocked by policy");

      await user.click(screen.getByText("Custom"));
      expect(screen.getByRole("button", { name: /→/ })).toBeInTheDocument();

      await user.click(screen.getByText("30d"));

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /→/ }),
        ).not.toBeInTheDocument();
      });
      expect(useAuditFilters.getState().filters.start_date).toBeNull();
      expect(useAuditFilters.getState().filters.end_date).toBeNull();
    });
  });

  describe("AnomaliesCard", () => {
    it("renders when the API returns anomalies", async () => {
      stubFetch([ANOMALY]);
      renderWithProviders(<AuditPage />);

      expect(await screen.findByText(/1 detected/)).toBeInTheDocument();
      expect(screen.getByText("bob")).toBeInTheDocument();
      expect(screen.getByText("High")).toBeInTheDocument();
      expect(screen.getByText("80%")).toBeInTheDocument();
    });

    it("row click sets date range and user filter; user= appears in decisions query", async () => {
      const calls = stubFetch([ANOMALY]);
      const user = userEvent.setup();
      renderWithProviders(<AuditPage />);

      await user.click(await screen.findByText("bob"));

      await waitFor(() => {
        expect(useAuditFilters.getState().filters.user).toBe("bob");
        expect(useAuditFilters.getState().filters.customMode).toBe(true);
        expect(useAuditFilters.getState().filters.start_date).not.toBeNull();
      });
      await waitFor(() => {
        expect(
          calls.some(
            (u) => u.includes("/audit/decisions") && u.includes("user=bob"),
          ),
        ).toBe(true);
      });
      expect(screen.getByText("Clear all")).toBeInTheDocument();
    });

    it("renders a Medium badge for medium-severity anomalies", async () => {
      stubFetch([{ ...ANOMALY, severity: "medium" }]);
      renderWithProviders(<AuditPage />);

      expect(await screen.findByText("Medium")).toBeInTheDocument();
      expect(screen.queryByText("High")).not.toBeInTheDocument();
    });

    it("renders a multi-day range when the burst spans two calendar days", async () => {
      // Noon-to-noon (48 h apart) guarantees different calendar days in any timezone.
      stubFetch([
        {
          ...ANOMALY,
          first_seen: "2026-06-01T12:00:00Z",
          last_seen: "2026-06-03T12:00:00Z",
        },
      ]);
      renderWithProviders(<AuditPage />);

      await screen.findByText("bob");
      // Multi-day format shows the year twice (once per date); same-day shows it once.
      expect(
        screen.getByText(
          (t) => (t.match(/\d{4}/g) ?? []).length >= 2 && t.includes("→"),
        ),
      ).toBeInTheDocument();
    });

    it("does not render when the API returns no anomalies", async () => {
      stubFetch();
      renderWithProviders(<AuditPage />);

      await screen.findByText("blocked by policy");
      expect(screen.queryByText(/detected/)).not.toBeInTheDocument();
    });
  });

  describe("Ban user tie-in", () => {
    it("navigates to /bans?ban_user= when an admin bans an anomalous user", async () => {
      stubFetch([ANOMALY], "admin");
      const user = userEvent.setup();
      renderWithProviders(
        <Routes>
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/bans" element={<BansSentinel />} />
        </Routes>,
        { initialRoute: "/audit" },
      );

      await screen.findByText("bob");
      await user.click(screen.getByRole("button", { name: /ban user/i }));

      // Real router navigation — the sentinel proves the exact query param.
      expect(await screen.findByText("ban_user=bob")).toBeInTheDocument();
    });

    it("hides the Ban user action from non-admins", async () => {
      stubFetch([ANOMALY], "member");
      renderWithProviders(<AuditPage />);

      await screen.findByText("bob");
      expect(screen.queryByRole("button", { name: /ban user/i })).toBeNull();
    });
  });
});
