import { useEffect } from "react";
import { useNavigate, NavLink, Outlet } from "react-router-dom";
import {
  Ban,
  Building2,
  FileCode,
  Fingerprint,
  KeyRound,
  LogOut,
  MessageSquareCode,
  Network,
  ScrollText,
  Server,
  Settings2,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { OrgProjectSwitcher } from "@/components/OrgProjectSwitcher";
import { PreviewBanner } from "@/components/PreviewBanner";
import { VerifyEmailBanner } from "@/components/VerifyEmailBanner";
import { useActive } from "@/lib/active";
import { useLogout, useUser } from "@/lib/auth";
import { useOrgs } from "@/lib/orgs";
import { useProjects } from "@/lib/projects";
import { cn } from "@/lib/utils";

/**
 * Bootstrap effect — runs on every AppShell mount.
 *
 * If no active org is set (first-ever visit or post-logout sign-in),
 * pick the user's first org. Once an org is active, if no project is
 * set, pick its first project (or null if the org is empty). Keeps
 * the switcher in a usable default state so a freshly-signed-up user
 * immediately sees their own data, not an empty/error state.
 *
 * Idempotent — won't overwrite a valid existing selection.
 */
function useActiveBootstrap(): void {
  const { activeOrgId, activeProjectId, setActiveOrg, setActiveProject } =
    useActive();
  const orgsQuery = useOrgs();
  const projectsQuery = useProjects(activeOrgId);

  // First-org bootstrap. Don't run while orgs are loading — we'd
  // briefly set null and flicker the switcher label.
  useEffect(() => {
    if (orgsQuery.isLoading || !orgsQuery.data) return;
    if (activeOrgId === null) {
      const first = orgsQuery.data[0];
      if (first) setActiveOrg(first.id);
      return;
    }
    // Stale-org cleanup: the persisted activeOrgId refers to an org
    // the user no longer belongs to (e.g., they got removed). Reset
    // to the first remaining one.
    if (!orgsQuery.data.some((o) => o.id === activeOrgId)) {
      const fallback = orgsQuery.data[0] ?? null;
      setActiveOrg(fallback?.id ?? null);
    }
  }, [orgsQuery.isLoading, orgsQuery.data, activeOrgId, setActiveOrg]);

  // First-project bootstrap, scoped to the active org. setActiveOrg
  // clears activeProjectId in the store so we'll always come through
  // here after an org change.
  useEffect(() => {
    if (!activeOrgId || projectsQuery.isLoading || !projectsQuery.data) return;
    if (activeProjectId === null) {
      const first = projectsQuery.data[0];
      if (first) setActiveProject(first.id);
      return;
    }
    // Stale-project cleanup (e.g., project deleted in another tab).
    if (!projectsQuery.data.some((p) => p.id === activeProjectId)) {
      const fallback = projectsQuery.data[0] ?? null;
      setActiveProject(fallback?.id ?? null);
    }
  }, [
    activeOrgId,
    activeProjectId,
    projectsQuery.isLoading,
    projectsQuery.data,
    setActiveProject,
  ]);
}

const workspaceLinks = [
  { to: "/agents", label: "Agents", icon: FileCode },
  { to: "/policies", label: "Policies", icon: ShieldCheck },
  { to: "/graph", label: "Graph", icon: Network },
  { to: "/playground", label: "Playground", icon: MessageSquareCode },
  { to: "/audit", label: "Audit", icon: ScrollText },
  { to: "/bans", label: "Bans", icon: Ban },
  { to: "/tokens", label: "Tokens", icon: KeyRound },
  { to: "/orgs", label: "Organizations", icon: Building2 },
  { to: "/settings", label: "Settings", icon: Settings2 },
];

const environmentLinks = [
  { to: "/control-plane", label: "Control plane", icon: Server, status: "OK" },
  { to: "/signing-key", label: "Signing key", icon: Fingerprint },
];

function NavItem({
  to,
  label,
  icon: Icon,
  end,
  badge,
  status,
}: {
  to: string;
  label: string;
  icon: LucideIcon;
  end?: boolean;
  badge?: string;
  status?: string;
}) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        cn(
          "flex h-9 items-center justify-between rounded-md px-3 text-sm transition-colors",
          isActive
            ? "bg-primary/15 text-primary font-medium"
            : "text-muted-foreground hover:bg-accent hover:text-foreground",
        )
      }
    >
      <span className="flex items-center gap-2.5">
        <Icon className="size-4" />
        {label}
      </span>
      {badge && (
        <span className="text-[11px] text-muted-foreground">{badge}</span>
      )}
      {status && (
        <span className="rounded-full bg-allow/15 px-1.5 py-0.5 text-[10px] font-medium text-allow">
          {status}
        </span>
      )}
    </NavLink>
  );
}

export function AppShell() {
  // Pick a default active org + project on first load so the switcher
  // shows something usable instead of "Pick an organization" empty
  // state. Idempotent — won't overwrite an existing valid selection.
  useActiveBootstrap();

  return (
    <div className="flex h-screen bg-background text-foreground">
      <aside className="flex w-[220px] flex-col border-r border-border bg-card">
        <div className="flex h-14 items-center gap-2 px-4 border-b border-border">
          <img src="/icon.svg" alt="" className="size-7" />
          <span className="text-sm font-semibold">Hexgate</span>
        </div>

        <nav className="flex-1 overflow-y-auto p-3 scrollbar-thin">
          <div className="mb-4">
            <div className="px-3 pb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Workspace
            </div>
            <div className="flex flex-col gap-0.5">
              {workspaceLinks.map((l) => (
                <NavItem key={l.to} {...l} />
              ))}
            </div>
          </div>

          <div>
            <div className="px-3 pb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Environment
            </div>
            <div className="flex flex-col gap-0.5">
              {environmentLinks.map((l) => (
                <NavItem key={l.to} {...l} />
              ))}
            </div>
          </div>
        </nav>

        <div className="border-t border-border p-3 text-[11px] text-muted-foreground space-y-1">
          <div className="flex items-center gap-1.5">
            <span className="relative flex size-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-50" />
              <span className="relative inline-flex size-1.5 rounded-full bg-primary" />
            </span>
            Serving bundle <span className="font-mono text-foreground">v1</span>
          </div>
          <div>Pushed just now</div>
          <div>local · 1 region</div>
        </div>
      </aside>

      <div className="flex flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b border-border px-6">
          <div className="flex items-center gap-3">
            <OrgProjectSwitcher />
          </div>
          <UserMenu />
        </header>

        <PreviewBanner />
        <VerifyEmailBanner />

        <main className="flex-1 overflow-y-auto px-8 py-6 scrollbar-thin">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

/** Top-right corner: shows the signed-in user's initial + a sign-out
 * button. Phase 5 will replace this with a proper dropdown menu (and
 * an org switcher next to it); for now a flat layout is enough. */
function UserMenu() {
  const { user } = useUser();
  const logout = useLogout();
  const navigate = useNavigate();

  if (!user) return null;

  const initial = user.email.slice(0, 1).toUpperCase();

  return (
    <div className="flex items-center gap-3 text-muted-foreground">
      <div className="flex items-center gap-2">
        <span className="size-8 rounded-full bg-primary/20 text-primary grid place-items-center text-xs font-medium">
          {initial}
        </span>
        <span className="hidden text-xs text-foreground sm:inline">
          {user.email}
        </span>
      </div>
      <Button
        variant="ghost"
        size="icon"
        title="Sign out"
        disabled={logout.isPending}
        onClick={async () => {
          await logout.mutateAsync().catch(() => undefined);
          navigate("/sign-in", { replace: true });
        }}
      >
        <LogOut className="h-4 w-4" />
      </Button>
    </div>
  );
}
