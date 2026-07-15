/**
 * Select with an "all" option — the value that maps to no filter is
 * represented on the wire as "", but Radix Select items can't carry
 * value="". ALL is a UI-local stand-in swapped at the boundary.
 * Shared by Audit's and Usage's filter bars.
 */

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export const ALL = "__all__";

export function FilterSelect({
  value,
  all,
  opts,
  onChange,
}: {
  value: string;
  all: string;
  opts: string[];
  onChange: (v: string) => void;
}) {
  return (
    <Select
      value={value || ALL}
      onValueChange={(v) => onChange(v === ALL ? "" : v)}
    >
      <SelectTrigger className="h-8 w-auto min-w-32 gap-1.5 text-[13px]">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>{all}</SelectItem>
        {opts.map((o) => (
          <SelectItem key={o} value={o} className="font-mono text-xs">
            {o}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
