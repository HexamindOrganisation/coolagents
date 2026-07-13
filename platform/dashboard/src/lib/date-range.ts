/**
 * Shared window/range math for dashboard pages with a preset-range +
 * custom-date-picker toggle (Audit, Usage). Neutral module — both
 * audit-filters.ts and usage-filters.ts import from here rather than one
 * page's filter store owning logic the other needs too.
 */

export type Range = "24h" | "7d" | "30d" | "90d";

export const RANGE_DAYS: Record<Range, number> = {
  "24h": 1,
  "7d": 7,
  "30d": 30,
  "90d": 90,
};

/** Effective day count for a window: explicit custom dates win when both
 * are set, otherwise falls back to the preset range's day count. */
export function rangeDays(
  range: Range,
  start: Date | null,
  end: Date | null,
): number {
  if (start && end) {
    return Math.max(
      1,
      Math.round((end.getTime() - start.getTime()) / 86_400_000),
    );
  }
  return RANGE_DAYS[range];
}
