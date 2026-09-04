import type { ReactNode } from "react";
import { Info, Layers } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * Classic-vs-modular status bar — doubles as the page's top bar (there's no
 * separate title; the sidebar already says "Modules"). A project is modular
 * once it has at least one role binding; until then agents enforce their own
 * `policy.yaml` and the module library changes nothing (no `policy_mode`
 * column — bindings are the signal). `trailing` holds right-aligned actions
 * (e.g. the docs link).
 */
export function ModularBanner({
  modular,
  trailing,
}: {
  modular: boolean;
  trailing?: ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex items-center gap-2 px-6 py-2 text-xs border-b",
        modular
          ? "border-primary/30 bg-primary/5 text-primary"
          : "border-approval/30 bg-approval/5 text-approval",
      )}
    >
      {modular ? (
        <Layers className="size-3.5 shrink-0" />
      ) : (
        <Info className="size-3.5 shrink-0" />
      )}
      <span className="min-w-0 flex-1">
        {modular ? (
          <>
            Modular policy is <span className="font-medium">active</span>.
            Agents in this project enforce the composed bundle below.
          </>
        ) : (
          <>
            Classic project — agents enforce their own policy. Bind a role in{" "}
            <span className="font-mono">roles.yaml</span> to switch this project
            to the modular library.
          </>
        )}
      </span>
      {trailing && <div className="shrink-0">{trailing}</div>}
    </div>
  );
}
