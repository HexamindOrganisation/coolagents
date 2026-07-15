/**
 * Range/Custom toggle + date-range popover for a dashboard page header —
 * preset buttons (24h/7d/30d/90d) plus a "Custom" mode that opens a
 * two-date calendar. Shared by Audit's and Usage's headers, which operate
 * on identical fields (range, customMode, start_date, end_date) already
 * unified under the Range type in date-range.ts.
 */

import { endOfDay, format } from "date-fns";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import {
  RANGE_DAYS,
  type Range,
  type RangePickerFilters,
} from "@/lib/date-range";

const DATE_FMT = "MMM d, yyyy";

function impliedRangeLabel(range: Range): string {
  const now = new Date();
  const start = new Date(now.getTime() - RANGE_DAYS[range] * 86_400_000);
  return `${format(start, DATE_FMT)} → ${format(now, DATE_FMT)}`;
}

export function DashboardRangePicker<F extends RangePickerFilters>({
  f,
  setF,
}: {
  f: F;
  setF: (updater: (prev: F) => F) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <ToggleGroup
        type="single"
        value={f.customMode ? "custom" : f.range}
        onValueChange={(v) => {
          if (!v) return;
          if (v === "custom") {
            setF((p) => ({ ...p, customMode: true }));
          } else {
            setF((p) => ({
              ...p,
              range: v as Range,
              customMode: false,
              start_date: null,
              end_date: null,
            }));
          }
        }}
      >
        {(["24h", "7d", "30d", "90d"] as const).map((r) => (
          <ToggleGroupItem key={r} value={r}>
            {r}
          </ToggleGroupItem>
        ))}
        <ToggleGroupItem value="custom">Custom</ToggleGroupItem>
      </ToggleGroup>
      {f.customMode && (
        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" className="h-8 text-[13px] font-normal">
              {f.start_date && f.end_date
                ? `${format(f.start_date, DATE_FMT)} → ${format(f.end_date, DATE_FMT)}`
                : f.start_date
                  ? `${format(f.start_date, DATE_FMT)} → …`
                  : impliedRangeLabel(f.range)}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-auto p-0" align="end">
            <Calendar
              mode="range"
              selected={{
                from: f.start_date ?? undefined,
                to: f.end_date ?? undefined,
              }}
              onSelect={(range) =>
                setF((p) => ({
                  ...p,
                  start_date: range?.from ?? null,
                  end_date: range?.to ? endOfDay(range.to) : null,
                }))
              }
            />
          </PopoverContent>
        </Popover>
      )}
    </div>
  );
}
