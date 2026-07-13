/**
 * CreateBanDialog — focused on the reset-on-open contract.
 *
 * The dialog seeds its fields from `initial` only on the closed→open
 * transition, NOT on every `initial` identity change. The parent
 * (Bans.tsx) re-derives `initial` when URL params change, so a reset keyed
 * on `initial` would wipe whatever the operator typed mid-edit.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";

import {
  CreateBanDialog,
  type CreateBanInitial,
} from "@/components/bans/CreateBanDialog";

function wrap(initial: CreateBanInitial): ReactNode {
  // A fresh QueryClient per wrap isn't needed — the dialog's agents query is
  // disabled for a user ban, so no request fires here.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return (
    <QueryClientProvider client={qc}>
      <CreateBanDialog
        open
        onOpenChange={() => {}}
        projectId="p1"
        initial={initial}
      />
    </QueryClientProvider>
  );
}

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
});
