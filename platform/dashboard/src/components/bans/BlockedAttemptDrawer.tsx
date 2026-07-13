import { useEffect, type ReactNode } from "react";
import { ShieldAlert, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { BanEnforcementRow } from "@/lib/api";
import { BanTypeBadge } from "./BanTypeBadge";
import { formatAbsolute, formatRelative } from "./format";

/** One labelled key/value row. Mirrors the Audit detail drawer's ``KV`` so
 * the two drawers read the same. */
function KV({
  k,
  children,
  mono,
  muted,
}: {
  k: string;
  children: ReactNode;
  mono?: boolean;
  muted?: boolean;
}) {
  return (
    <div className="grid grid-cols-[116px_1fr] items-baseline gap-2.5 py-[5px] text-[12.5px]">
      <div className="text-muted-foreground">{k}</div>
      <div
        className={`break-words ${mono ? "font-mono text-xs" : ""} ${
          muted ? "text-muted-foreground" : "text-foreground"
        }`}
      >
        {children}
      </div>
    </div>
  );
}

function DrawerSection({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="mt-[22px]">
      <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      {children}
    </div>
  );
}

/** Placeholder shown when a value the platform stamps optionally is absent. */
function Empty() {
  return <span className="text-muted-foreground">∅ none</span>;
}

/**
 * Full detail for one blocked attempt, in a right-hand slide-over — the
 * ban-side counterpart to the Audit page's decision drawer. A ban is refused
 * before any tool call, so there are no tool/args/violations to show; the
 * event carries the target, the identity context, the ban it matched, and
 * timing. Closes on backdrop click or Esc.
 */
export function BlockedAttemptDrawer({
  event,
  onClose,
}: {
  event: BanEnforcementRow | null;
  onClose: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!event) return null;
  const target = event.ban_type === "agent" ? event.agent_name : event.user_id;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        onClick={onClose}
        className="absolute inset-0 bg-black/55 backdrop-blur-[1px]"
      />
      <aside className="relative flex h-full w-[472px] max-w-[92vw] flex-col border-l border-border bg-card shadow-2xl">
        <div className="flex items-center gap-2.5 border-b border-border px-5 py-4">
          <BanTypeBadge type={event.ban_type} />
          <span className="flex-1 truncate font-mono text-xs text-muted-foreground">
            {event.event_id}
          </span>
          <Button
            variant="ghost"
            size="icon"
            onClick={onClose}
            title="Close (Esc)"
          >
            <X className="size-4" />
          </Button>
        </div>

        <div className="flex-1 overflow-auto px-5 pb-6 pt-1 scrollbar-thin">
          <div className="mt-[18px] flex flex-wrap items-baseline gap-2">
            <span className="font-mono text-[17px] font-semibold text-foreground">
              {target}
            </span>
            <span className="text-[13px] text-muted-foreground">
              blocked · {event.ban_type} ban
            </span>
          </div>

          <div className="mt-2 flex items-start gap-2 rounded-lg border border-destructive/25 bg-destructive/10 px-3 py-2.5 text-[13px] leading-relaxed text-foreground">
            <ShieldAlert className="mt-px size-4 shrink-0 text-destructive" />
            <span>
              Refused before the model ran.{" "}
              {event.reason || "No reason recorded."}
            </span>
          </div>

          <DrawerSection label="Enforcement">
            <KV k="ban type">
              {event.ban_type === "agent" ? "Agent" : "User"}
            </KV>
            <KV k="target" mono>
              {target || <Empty />}
            </KV>
            <KV k="agent" mono>
              {event.agent_name || <Empty />}
            </KV>
            <KV k="user" mono>
              {event.user_id || <Empty />}
            </KV>
            <KV k="session" mono>
              {event.session_id || <Empty />}
            </KV>
            <KV k="ban id" mono>
              {event.ban_id}
            </KV>
            <KV k="reason">{event.reason || <Empty />}</KV>
          </DrawerSection>

          <DrawerSection label="Timing">
            <KV k="occurred">
              {formatAbsolute(event.occurred_at)}{" "}
              <span className="text-muted-foreground">
                ({formatRelative(event.occurred_at)})
              </span>
            </KV>
            <KV k="received" muted>
              {formatAbsolute(event.received_at)}
            </KV>
            <KV k="event id" mono muted>
              {event.event_id}
            </KV>
          </DrawerSection>
        </div>
      </aside>
    </div>
  );
}
