/**
 * Active-filter chip row + "Clear all" — one chip per set filter key, each
 * clearable individually. Shared by Audit's and Usage's filter bars, which
 * differ only in which keys are chip-eligible and what "clear all" resets.
 */

import { X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export function ActiveFilterChips<F extends object>({
  f,
  setF,
  chipKeys,
  onClearAll,
}: {
  f: F;
  setF: (updater: (prev: F) => F) => void;
  chipKeys: (keyof F)[];
  onClearAll: () => void;
}) {
  const active = chipKeys.filter((k) => f[k]);
  if (!active.length) return null;
  return (
    <div className="mb-4 flex flex-wrap items-center gap-1.5">
      <span className="text-[11.5px] text-muted-foreground">Filters</span>
      {active.map((k) => (
        <Badge key={String(k)} className="gap-1 pr-1 text-muted-foreground">
          {String(k)}:{" "}
          <span className="font-mono text-foreground">{String(f[k])}</span>
          <button
            onClick={() => setF((p) => ({ ...p, [k]: "" }) as F)}
            className="inline-flex cursor-pointer text-muted-foreground hover:text-foreground"
          >
            <X className="size-3" />
          </button>
        </Badge>
      ))}
      <Button
        variant="ghost"
        size="sm"
        className="h-6 px-2 text-xs"
        onClick={onClearAll}
      >
        Clear all
      </Button>
    </div>
  );
}
