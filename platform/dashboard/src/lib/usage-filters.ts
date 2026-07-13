/**
 * Usage-page filter state.
 *
 * Zustand (like ``useAuditFilters``) so the dialled-in slice survives
 * navigating away and back within the session — deliberately NOT
 * ``persist``-ed, same reasoning as audit-filters: a stale filter from
 * last week silently narrowing today's usage view would read as missing
 * data. No ``tableLimit``/``loadMore`` here — Usage has no events table.
 */

import { create } from "zustand";

import type { Range } from "./date-range";

// '' = "all".
export interface UsageFilters {
  agent: string;
  model: string;
  user: string;
  range: Range;
  customMode: boolean;
  start_date: Date | null;
  end_date: Date | null;
}

export type SetUsageFilters = (
  updater: (prev: UsageFilters) => UsageFilters,
) => void;

export const EMPTY_USAGE_FILTERS: UsageFilters = {
  agent: "",
  model: "",
  user: "",
  range: "30d",
  customMode: false,
  start_date: null,
  end_date: null,
};

interface UsageFilterState {
  filters: UsageFilters;
  setFilters: SetUsageFilters;
}

export const useUsageFilters = create<UsageFilterState>()((set) => ({
  filters: EMPTY_USAGE_FILTERS,
  setFilters: (updater) => set((s) => ({ filters: updater(s.filters) })),
}));
