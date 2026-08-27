/**
 * Small persisted UI-preference store (separate from `active`, which holds the
 * org/project scope). Currently just the workspace-sidebar collapsed state, so
 * a collapse survives a reload.
 */

import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

interface UiState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
}

export const useUi = create<UiState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      toggleSidebar: () =>
        set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
    }),
    {
      name: "hexgate-ui",
      storage: createJSONStorage(() => localStorage),
    },
  ),
);
