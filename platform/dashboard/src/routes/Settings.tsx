import {
  AlertTriangle,
  Clock3,
  Cog,
  KeyRound,
  Sliders,
  Webhook,
  type LucideIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useProjectScoped } from "@/lib/active";
import { cn } from "@/lib/utils";

/**
 * /settings — project-scoped configuration.
 *
 * Section shell for now: every card lists the eventual scope of that
 * area with a "Coming soon" badge. Ships the "someone thought about
 * this" signal that a completely blank page tanks, and gives operators
 * an expectation of where each future control will live.
 *
 * When each section ships, replace its ``Coming soon`` badge with
 * the real form. Keep the card + description as-is — they double as
 * inline documentation next to the controls.
 *
 * The roadmap cards render regardless of project scope — an org-owner
 * with no projects yet still needs to see what's coming. A subtle
 * "select a project to configure" banner appears when scope isn't
 * resolved, so the empty state doesn't lie about interactivity.
 */
export function SettingsPage() {
  const scope = useProjectScoped();
  const projectResolved =
    scope.status === "ready" || scope.status === "loading";

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Project configuration — applies to every agent, token, and policy in
          this project.
        </p>
      </header>

      {!projectResolved && (
        <div className="rounded-md border border-border bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          Select or create a project from the switcher above to configure it.
          The roadmap below applies to every project.
        </div>
      )}

      {SECTIONS.map((section) => (
        <SectionCard key={section.title} {...section} />
      ))}
    </div>
  );
}

interface Section {
  title: string;
  icon: LucideIcon;
  description: string;
  items: string[];
  /** Danger-zone sections get a red border + destructive-tinted icon. */
  destructive?: boolean;
}

const SECTIONS: Section[] = [
  {
    title: "General",
    icon: Cog,
    description: "Basics — project name, ownership, lifecycle.",
    items: ["Project name", "Delete project (confirm-typing)"],
  },
  {
    title: "Bundle & runtime",
    icon: Sliders,
    description:
      "Defaults every agent inherits. Individual agents can override in their manifest.",
    items: [
      "Default model",
      "Default framework adapter",
      "Bundle version pinning",
      "Decision timeout",
      "Approval TTL",
    ],
  },
  {
    title: "Webhooks",
    icon: Webhook,
    description:
      "Outbound HTTP notifications for decision + agent lifecycle events.",
    items: [
      "decision.denied · decision.needs_approval · agent.registered URLs",
      "Signing secret + verification headers",
      "Delivery log (last 100 attempts, retry state)",
    ],
  },
  {
    title: "Retention",
    icon: Clock3,
    description:
      "How long the audit log keeps decision events, and what fields are scrubbed.",
    items: [
      "Audit retention window (30 / 90 / 365 days / forever)",
      "PII scrubbing on `arguments` (regex + field-name rules)",
    ],
  },
  {
    title: "Environment variables",
    icon: KeyRound,
    description:
      'Key/value pairs injected into the policy evaluation context — read from policy conditions like `env.STAGE == "prod"`.',
    items: ["Add / edit / remove env vars", "Values masked in the UI + audit"],
  },
  {
    title: "Danger zone",
    icon: AlertTriangle,
    description:
      "Destructive operations. Every action here requires a confirm-typing dialog.",
    items: [
      "Rotate signing key (invalidates every bundle + biscuit)",
      "Revoke all tokens",
      "Purge audit history",
    ],
    destructive: true,
  },
];

function SectionCard({
  title,
  icon: Icon,
  description,
  items,
  destructive,
}: Section) {
  return (
    <Card
      className={cn(destructive && "border-[hsl(var(--semantic-deny))]/40")}
    >
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <span
              className={cn(
                "grid place-items-center rounded-md size-9 shrink-0",
                destructive
                  ? "bg-[hsl(var(--semantic-deny))]/10 text-[hsl(var(--semantic-deny))]"
                  : "bg-muted text-muted-foreground",
              )}
            >
              <Icon className="size-4" />
            </span>
            <div>
              <CardTitle className="text-base">{title}</CardTitle>
              <CardDescription className="mt-1">{description}</CardDescription>
            </div>
          </div>
          <Badge variant="outline" className="shrink-0">
            Coming soon
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <ul className="space-y-1.5 text-sm text-muted-foreground">
          {items.map((item) => (
            <li key={item} className="flex items-start gap-2">
              <span className="mt-1.5 size-1 rounded-full bg-muted-foreground/40" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
