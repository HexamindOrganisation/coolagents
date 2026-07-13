/**
 * CreateBanDialog — reset-on-open contract + error handling.
 *
 * The dialog seeds its fields from `initial` only on the closed→open
 * transition, NOT on every `initial` identity change (the parent re-derives
 * `initial` on URL-param churn, which would otherwise wipe typed input). And
 * a failed create surfaces a user-facing error without closing the dialog.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";

import {
  CreateBanDialog,
  type CreateBanInitial,
} from "@/components/bans/CreateBanDialog";

vi.mock("sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn() },
}));

function wrap(
  initial: CreateBanInitial,
  onOpenChange: (open: boolean) => void = () => {},
): ReactNode {
  // A fresh QueryClient per wrap — the dialog's agents query is disabled for a
  // user ban, so no GET fires; only the create POST is exercised (mocked).
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return (
    <QueryClientProvider client={qc}>
      <CreateBanDialog
        open
        onOpenChange={onOpenChange}
        projectId="p1"
        initial={initial}
      />
    </QueryClientProvider>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.mocked(toast.error).mockClear();
});

describe("CreateBanDialog", () => {
  it("keeps typed input when the parent re-derives `initial` while open", async () => {
    const user = userEvent.setup();
    const { rerender } = render(wrap({ ban_type: "user", target: "u-1" }));

    const input = await screen.findByLabelText("User ID");
    expect(input).toHaveValue("u-1");

    await user.clear(input);
    await user.type(input, "u-edited");
    expect(input).toHaveValue("u-edited");

    // Parent re-render with a NEW `initial` object of the same shape (what
    // happens on URL-param churn). The dialog stays open, so the edit must
    // survive rather than being reset back to the prefill.
    rerender(wrap({ ban_type: "user", target: "u-1" }));

    expect(screen.getByLabelText("User ID")).toHaveValue("u-edited");
  });

  it("shows a user-facing error and stays open when create returns 409", async () => {
    const onOpenChange = vi.fn();
    vi.spyOn(window, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "already banned" }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const user = userEvent.setup();
    render(wrap({ ban_type: "user", target: "u-1" }, onOpenChange));

    await user.click(screen.getByRole("button", { name: /create ban/i }));

    // Friendly, status-mapped copy — not the raw server detail.
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "An active ban already exists for this target.",
      ),
    );
    // Dialog is not closed on failure (onOpenChange(false) never fires), so the
    // operator can fix and retry.
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(
      screen.getByRole("heading", { name: "Create ban" }),
    ).toBeInTheDocument();
  });
});
