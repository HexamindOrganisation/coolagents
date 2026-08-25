import { Info, Layers } from "lucide-react";

/**
 * Classic-vs-modular banner. A project is modular once it has at least one
 * role binding; until then agents enforce their own `policy.yaml` and the
 * module library changes nothing. Reused verbatim from the resolve semantics
 * server-side (no `policy_mode` column — bindings are the signal).
 */
export function ModularBanner({ modular }: { modular: boolean }) {
  if (modular) {
    return (
      <div className="flex items-center gap-2 px-6 py-2 text-xs border-b border-primary/30 bg-primary/5 text-primary">
        <Layers className="size-3.5 shrink-0" />
        <span>
          Modular policy is <span className="font-medium">active</span>. Agents
          in this project enforce the composed bundle below.
        </span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 px-6 py-2 text-xs border-b border-approval/30 bg-approval/5 text-approval">
      <Info className="size-3.5 shrink-0" />
      <span>
        Classic project — agents enforce their own policy. Bind a role in{" "}
        <span className="font-mono">roles.yaml</span> to switch this project to
        the modular library.
      </span>
    </div>
  );
}
