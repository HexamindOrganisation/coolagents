/**
 * Smoke tests for the /usage page.
 *
 * Load-bearing invariants:
 *
 *   1. KPI tiles render compact token counts and range-based averages
 *      (24h → hourly average, everything else → daily average).
 *   2. Filter selection (model) lands in the next query URL.
 *   3. The empty-user bucket ("" over the wire) displays as "(none)" and
 *      round-trips back to `user=` (empty) — the crash this page used to
 *      hit before FilterSelect got a NO_VALUE_LABEL mapping.
 *   4. The breakdown card's dimension tabs and metric select switch what's
 *      rendered, and clicking a bar sets/clears the matching filter.
 *   5. Active chips render the current filter and "Clear all" resets it.
 *   6. The no-project empty state renders when the active org has none.
 */

import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useActive } from "@/lib/active";
import { EMPTY_USAGE_FILTERS, useUsageFilters } from "@/lib/usage-filters";
import { UsagePage } from "@/routes/Usage";
import { renderWithProviders } from "@/test/render";

const PROJECT = "p1";

const row = (
  key: string,
  calls: number,
  input_tokens: number,
  output_tokens: number,
) => ({
  key,
  calls,
  input_tokens,
  output_tokens,
  total_tokens: input_tokens + output_tokens,
});

const SUMMARY = {
  totals: {
    calls: 1234,
    input_tokens: 900_000,
    output_tokens: 300_000,
    total_tokens: 1_200_000,
  },
  by_model: [
    row("gpt-4", 800, 600_000, 200_000),
    row("gpt-3.5", 434, 300_000, 100_000),
  ],
  by_agent: [
    row("example_agent", 1000, 700_000, 200_000),
    row("scraper", 234, 200_000, 100_000),
  ],
  by_user: [
    row("alice", 900, 700_000, 200_000),
    // The no-user bucket arrives as a raw "" key over the wire.
    row("", 334, 200_000, 100_000),
  ],
};

const SUMMARY_EMPTY = {
  totals: { calls: 0, input_tokens: 0, output_tokens: 0, total_tokens: 0 },
  by_model: [],
  by_agent: [],
  by_user: [],
};

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

const ORGS = [
  {
    id: "org-1",
    slug: "acme",
    name: "Acme Inc",
    created_at: "2026-01-01T00:00:00Z",
    role: "owner",
  },
];

/** Same fetch-stub helper pattern as Audit.test.tsx, recording every
 * requested URL so tests can assert what filter state reached the API. */
function stubFetch(summary: unknown = SUMMARY): string[] {
  const calls: string[] = [];
  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL) => {
      const raw = typeof input === "string" ? input : input.toString();
      const url = new URL(raw, "http://localhost");
      calls.push(url.pathname + url.search);

      switch (url.pathname) {
        case "/v1/orgs":
          return json(ORGS);
        case "/v1/orgs/org-1/projects":
          return json([
            {
              id: PROJECT,
              org_id: "org-1",
              name: "demo-project",
              created_at: "2026-01-01T00:00:00Z",
            },
          ]);
        case `/v1/projects/${PROJECT}/llm/summary`:
          return json(summary);
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
  return calls;
}

/** Active org with zero projects — drives the `no-project` branch. */
function stubFetchNoProjects(): void {
  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL) => {
      const raw = typeof input === "string" ? input : input.toString();
      const url = new URL(raw, "http://localhost");
      switch (url.pathname) {
        case "/v1/orgs":
          return json(ORGS);
        case "/v1/orgs/org-1/projects":
          return json([]);
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
}

describe("UsagePage", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
      // The filter store is module-global — reset so a filter dialled in
      // by test A doesn't narrow test B's queries.
      useUsageFilters.setState({ filters: EMPTY_USAGE_FILTERS });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders KPI tiles with compact token counts and a daily average", async () => {
    stubFetch();
    renderWithProviders(<UsagePage />);

    expect(await screen.findByText("demo-project")).toBeInTheDocument();
    expect(await screen.findByText("1.20M")).toBeInTheDocument();
    expect(screen.getByText("900.0K")).toBeInTheDocument();
    expect(screen.getByText("300.0K")).toBeInTheDocument();
    expect(screen.getByText("75% of total")).toBeInTheDocument();
    expect(screen.getByText("25% of total")).toBeInTheDocument();
    expect(screen.getByText("41/day avg")).toBeInTheDocument();
    expect(screen.getByText("40000/day avg")).toBeInTheDocument();
  });

  it("shows zero percentages and the empty breakdown message with no calls yet", async () => {
    stubFetch(SUMMARY_EMPTY);
    renderWithProviders(<UsagePage />);

    expect(await screen.findByText("demo-project")).toBeInTheDocument();
    expect(screen.getAllByText("0% of total")).toHaveLength(2);
    expect(screen.getByText("No LLM calls match.")).toBeInTheDocument();
  });

  it("shows an hourly average for the 24h range", async () => {
    stubFetch();
    act(() => {
      useUsageFilters.setState((s) => ({
        filters: { ...s.filters, range: "24h" },
      }));
    });
    renderWithProviders(<UsagePage />);

    expect(await screen.findByText("51.4/hr avg")).toBeInTheDocument();
  });

  it("agent and model filter selections land in the next query URL", async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    await screen.findByText("demo-project");
    // With no filters set, optionsQ and summaryQ dedupe into one fetch.
    expect(
      calls.filter(
        (u) => u === `/v1/projects/${PROJECT}/llm/summary?window=30d`,
      ),
    ).toHaveLength(1);

    await user.click(screen.getByText("All agents").closest("button")!);
    await user.click(
      await screen.findByRole("option", { name: "example_agent" }),
    );
    await waitFor(() => {
      expect(calls.some((u) => u.includes("agent=example_agent"))).toBe(true);
    });

    await user.click(screen.getByText("All models").closest("button")!);
    await user.click(await screen.findByRole("option", { name: "gpt-4" }));

    await waitFor(() => {
      expect(calls.some((u) => u.includes("model=gpt-4"))).toBe(true);
    });
  });

  it('maps the empty-user bucket to "(none)" locally and queries user=', async () => {
    const calls = stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    // The "" key from the wire displays as "(none)" in the dropdown…
    await screen.findByText("demo-project");
    await user.click(screen.getByText("All users").closest("button")!);
    await user.click(await screen.findByRole("option", { name: "(none)" }));

    // …and selecting it sends `user=` (empty value) — no "(none)" sentinel
    // ever leaves the dashboard, and the page doesn't crash rendering it
    // (Radix throws on an empty-string <Select.Item> value).
    await waitFor(() => {
      expect(calls.some((u) => /[?&]user=(&|$)/.test(u))).toBe(true);
    });
    expect(
      calls.some((u) => u.includes("(none)") || u.includes("%28none%29")),
    ).toBe(false);
  });

  it("breakdown dimension tabs switch rows, including the (none) user bucket", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    await screen.findByText("gpt-4");
    expect(screen.getByText("gpt-3.5")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Agents" }));
    expect(await screen.findByText("example_agent")).toBeInTheDocument();
    expect(screen.getByText("scraper")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Users" }));
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("(none)")).toBeInTheDocument();
  });

  it("metric select toggles the footer legend between tokens and calls", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    await screen.findByText("gpt-4");
    expect(screen.getByText("total tokens")).toBeInTheDocument();

    await user.click(screen.getByText("by tokens").closest("button")!);
    await user.click(await screen.findByRole("option", { name: "by calls" }));

    expect(await screen.findByText("calls")).toBeInTheDocument();
  });

  it("clicking a breakdown bar sets the filter; clicking it again clears it", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    // Grab the row once — after the first click, "gpt-4" also shows up in
    // the model filter select and the active chip, so re-querying by text
    // would be ambiguous.
    const bar = (await screen.findByText("gpt-4")).closest(
      ".mb-\\[11px\\]",
    ) as HTMLElement;

    await user.click(bar);
    await waitFor(() => {
      expect(useUsageFilters.getState().filters.model).toBe("gpt-4");
    });
    expect(screen.getByText("Clear all")).toBeInTheDocument();

    await user.click(bar);
    await waitFor(() => {
      expect(useUsageFilters.getState().filters.model).toBe("");
    });
  });

  it("a chip's own remove button clears just that filter; Clear all resets the rest", async () => {
    stubFetch();
    act(() => {
      useUsageFilters.setState((s) => ({
        filters: { ...s.filters, model: "gpt-4", agent: "example_agent" },
      }));
    });
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    const chipsRow = (await screen.findByText("Filters")).closest(
      "div",
    ) as HTMLElement;
    // One remove ("×") button per active chip (agent, model) + "Clear all".
    const buttons = within(chipsRow).getAllByRole("button");
    expect(buttons).toHaveLength(3);

    // Chips render in ["agent", "model", "user"] order — remove the first
    // (agent) and confirm the model filter is untouched.
    await user.click(buttons[0]);
    await waitFor(() => {
      expect(useUsageFilters.getState().filters.agent).toBe("");
    });
    expect(useUsageFilters.getState().filters.model).toBe("gpt-4");
    expect(screen.getByText("Clear all")).toBeInTheDocument();

    await user.click(screen.getByText("Clear all"));
    await waitFor(() => {
      expect(useUsageFilters.getState().filters.model).toBe("");
    });
    expect(screen.queryByText("Clear all")).not.toBeInTheDocument();
  });

  it("Custom toggles the date range picker row; a preset range updates the filter", async () => {
    stubFetch();
    const user = userEvent.setup();
    renderWithProviders(<UsagePage />);

    await screen.findByText("demo-project");
    await user.click(screen.getByText("Custom"));
    expect(screen.getByRole("button", { name: /→/ })).toBeInTheDocument();

    await user.click(screen.getByText("7d"));
    await waitFor(() => {
      expect(useUsageFilters.getState().filters.range).toBe("7d");
    });
    expect(screen.queryByRole("button", { name: /→/ })).not.toBeInTheDocument();
  });

  it("renders the empty-project state when the active org has no projects", async () => {
    stubFetchNoProjects();
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: null });
    });
    renderWithProviders(<UsagePage />);

    expect(await screen.findByText("No project selected")).toBeInTheDocument();
  });
});
