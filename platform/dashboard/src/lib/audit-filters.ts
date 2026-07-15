/**
 * Audit-page filter + paging state.
 *
 * Zustand (like ``useActive``) rather than page-local ``useState`` so the
 * slice the user dialled in survives navigating away and back within the
 * session — deliberately NOT ``persist``-ed: a stale filter from last week
 * silently narrowing today's audit view would read as missing data.
 *
 * Folding ``tableLimit`` into the same store lets ``setFilters`` reset
 * paging atomically — any filter change starts the table back at page one,
 * without the page component wiring that invariant by hand.
 */

import { create } from "zustand";

import type { AuditOutcome } from "./api";
import { type BaseDashboardFilters, RANGE_DAYS } from "./date-range";

export { RANGE_DAYS };

// '' = "all"; outcome applies to the events table only.
export interface AuditFilters extends BaseDashboardFilters {
  role: string;
  tool: string;
  outcome: "" | AuditOutcome;
}

export type SetAuditFilters = (
  updater: (prev: AuditFilters) => AuditFilters,
) => void;

export const EMPTY_AUDIT_FILTERS: AuditFilters = {
  agent: "",
  role: "",
  tool: "",
  user: "",
  outcome: "",
  range: "30d",
  customMode: false,
  start_date: null,
  end_date: null,
};

const PAGE_SIZE = 40;
const MAX_LIMIT = 200;

interface AuditFilterState {
  filters: AuditFilters;
  tableLimit: number;
  setFilters: SetAuditFilters;
  loadMore: () => void;
}

export const useAuditFilters = create<AuditFilterState>()((set) => ({
  filters: EMPTY_AUDIT_FILTERS,
  tableLimit: PAGE_SIZE,
  setFilters: (updater) =>
    set((s) => ({ filters: updater(s.filters), tableLimit: PAGE_SIZE })),
  loadMore: () =>
    set((s) => ({ tableLimit: Math.min(s.tableLimit + PAGE_SIZE, MAX_LIMIT) })),
}));
