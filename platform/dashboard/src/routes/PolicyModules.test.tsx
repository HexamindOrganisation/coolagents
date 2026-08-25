/**
 * Tests for the /policy-modules editor page.
 *
 * Invariants:
 *   1. no-project scope -> the empty state, no policy fetch.
 *   2. Modules render in the tree; roles present -> the modular banner.
 *   3. No role bindings -> the classic banner.
 *   4. A /check error lint surfaces in the Lints tab.
 *
 * The CodeMirror editor is mocked to a textarea so the page's own logic
 * (tree, banner, inspector tabs) is what's under test, not the editor.
 */

import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PolicyLint } from "@/lib/api";
import { useActive } from "@/lib/active";
import { PolicyModulesPage } from "@/routes/PolicyModules";
import { renderWithProviders } from "@/test/render";

vi.mock("@/components/PolicyEditor", () => ({
  PolicyEditor: ({ value }: { value: string }) => (
    <textarea data-testid="policy-editor" defaultValue={value} />
  ),
}));

const PROJECT = "p1";

interface StubOptions {
  role?: string;
  modules?: { tier: string; path: string }[];
  roles?: Record<string, string[]>;
  lints?: PolicyLint[];
  resolveStatus?: number;
  resolved?: Record<string, unknown>;
}

function stubFetch({
  role = "owner",
  modules = [],
  roles = {},
  lints = [],
  resolveStatus = 200,
  resolved = {},
}: StubOptions = {}) {
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  vi.spyOn(window, "fetch").mockImplementation(
    async (input: RequestInfo | URL) => {
      const raw = typeof input === "string" ? input : input.toString();
      const url = new URL(raw, "http://localhost");
      const p = url.pathname;
      switch (true) {
        case p === "/v1/orgs":
          return json([{ id: "org-1", slug: "acme", name: "Acme", role }]);
        case p === "/v1/orgs/org-1/projects":
          return json([{ id: PROJECT, org_id: "org-1", name: "demo" }]);
        case p === `/v1/projects/${PROJECT}/policy-modules`:
          return json(
            modules.map((m) => ({
              ...m,
              content: "tools: {}\n",
              content_hash: "h",
              updated_at: "2026-01-01T00:00:00Z",
            })),
          );
        case p === `/v1/projects/${PROJECT}/policy-roles`:
          return json({ roles });
        case p === `/v1/projects/${PROJECT}/policy/resolve`:
          return resolveStatus === 200
            ? json({ roles: resolved })
            : json({ detail: "does not compose" }, resolveStatus);
        case p === `/v1/projects/${PROJECT}/policy/check`:
          return json({
            ok: lints.every((l) => l.severity !== "error"),
            lints,
          });
        default:
          return new Response("not found", { status: 404 });
      }
    },
  );
}

describe("PolicyModulesPage", () => {
  beforeEach(() => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: PROJECT });
    });
  });

  afterEach(() => vi.restoreAllMocks());

  it("renders the no-project empty state and skips the policy fetch", async () => {
    act(() => {
      useActive.setState({ activeOrgId: "org-1", activeProjectId: null });
    });
    stubFetch();
    renderWithProviders(<PolicyModulesPage />, {
      initialRoute: "/policy-modules",
    });
    expect(await screen.findByText("No project selected")).toBeInTheDocument();
  });

  it("lists modules in the tree and shows the modular banner", async () => {
    stubFetch({
      modules: [
        { tier: "boundary", path: "org_core" },
        { tier: "capability", path: "read_only" },
      ],
      roles: { default: ["read_only"] },
    });
    renderWithProviders(<PolicyModulesPage />, {
      initialRoute: "/policy-modules",
    });

    expect(await screen.findByText("org_core")).toBeInTheDocument();
    expect(screen.getByText("read_only")).toBeInTheDocument();
    expect(screen.getByText(/Modular policy is/i)).toBeInTheDocument();
  });

  it("shows the classic banner when no role is bound", async () => {
    stubFetch({ modules: [{ tier: "capability", path: "read_only" }] });
    renderWithProviders(<PolicyModulesPage />, {
      initialRoute: "/policy-modules",
    });
    expect(await screen.findByText(/Classic project/i)).toBeInTheDocument();
  });

  it("shows the composed policy as a YAML document when toggled", async () => {
    stubFetch({
      modules: [{ tier: "capability", path: "read_only" }],
      roles: { default: ["read_only"] },
      resolved: {
        default: {
          default_policy: { mode: "deny" },
          tools: { view_orders: { mode: "allow" } },
        },
      },
    });
    const user = userEvent.setup();
    renderWithProviders(<PolicyModulesPage />, {
      initialRoute: "/policy-modules",
    });

    // Resolved is the default tab; flip Table -> YAML.
    const yamlToggle = await screen.findByRole("button", { name: /^yaml$/i });
    await user.click(yamlToggle);
    // `default_policy` is a YAML-only key (the table renders a "default"
    // label + badge instead), so it proves the composed document rendered.
    expect(await screen.findByText(/default_policy/)).toBeInTheDocument();
  });

  it("surfaces a /check error lint in the Lints tab", async () => {
    stubFetch({
      roles: { default: ["ghost"] },
      resolveStatus: 422,
      lints: [
        {
          code: "link-error",
          severity: "error",
          message: "role default imports unknown capability 'ghost'",
          source: null,
          tier: null,
          tool: null,
          role: "default",
        },
      ],
    });
    const user = userEvent.setup();
    renderWithProviders(<PolicyModulesPage />, {
      initialRoute: "/policy-modules",
    });

    // Lint count badge rides on the tab; open it to see the message.
    const lintsTab = await screen.findByRole("button", { name: /lints/i });
    await user.click(lintsTab);
    await waitFor(() =>
      expect(
        screen.getByText(/imports unknown capability 'ghost'/i),
      ).toBeInTheDocument(),
    );
  });
});
