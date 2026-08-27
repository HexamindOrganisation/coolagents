import { useState } from "react";
import { Check, ChevronsUpDown, FolderPlus, Plus } from "lucide-react";

import { CreateOrgDialog } from "@/components/CreateOrgDialog";
import { CreateProjectDialog } from "@/components/CreateProjectDialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useActive } from "@/lib/active";
import { useOrgs, type OrgWithRole } from "@/lib/orgs";
import { useProjects, type ProjectRead } from "@/lib/projects";
import { cn } from "@/lib/utils";

/**
 * The workspace switcher at the top of the sidebar. Reads the active org +
 * project from the store, lists all the user's orgs (with their
 * projects nested) in a single dropdown. "+ New project" /
 * "+ New organization" footer actions open the corresponding dialogs.
 *
 * Renders as a two-line block — project name on top, org name beneath — so
 * the project reads as the primary context (OpenAI-style) even though one
 * dropdown still switches both.
 *
 * Two state pieces:
 *   - which orgs/projects exist (from React Query)
 *   - which is active (from the zustand store)
 *
 * Bootstrap (auto-pick first org + project when nothing's active) is
 * handled by the parent AppShell so this component stays pure.
 */
export function OrgProjectSwitcher() {
  const { activeOrgId, activeProjectId, setActiveOrg, setActiveProject } =
    useActive();
  const orgsQuery = useOrgs();
  const projectsQuery = useProjects(activeOrgId);

  const [createOrgOpen, setCreateOrgOpen] = useState(false);
  const [createProjectOpen, setCreateProjectOpen] = useState(false);

  const orgs: OrgWithRole[] = orgsQuery.data ?? [];
  const projects: ProjectRead[] = projectsQuery.data ?? [];
  const activeOrg = orgs.find((o) => o.id === activeOrgId) ?? null;
  const activeProject = projects.find((p) => p.id === activeProjectId) ?? null;
  const label = switcherLabel(activeOrg, activeProject, orgsQuery.isLoading);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            type="button"
            className={cn(
              "flex w-full flex-col gap-0.5 rounded-md px-2 py-1 text-left",
              "transition-colors hover:bg-accent",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
            )}
          >
            <span className="flex w-full items-center gap-1">
              <span className="truncate text-sm font-medium text-foreground">
                {label.project}
              </span>
              <ChevronsUpDown className="ml-auto size-3 shrink-0 text-muted-foreground" />
            </span>
            {label.org && (
              <span className="truncate text-xs text-muted-foreground">
                {label.org}
              </span>
            )}
          </button>
        </DropdownMenuTrigger>

        <DropdownMenuContent align="start" className="min-w-[260px]">
          <DropdownMenuLabel>Organizations</DropdownMenuLabel>
          {orgs.length === 0 ? (
            <div className="px-2 py-3 text-xs text-muted-foreground">
              Loading…
            </div>
          ) : (
            orgs.map((org) => (
              <DropdownMenuItem
                key={org.id}
                onSelect={() => setActiveOrg(org.id)}
                className="flex items-center gap-2"
              >
                <span className="flex-1 truncate font-medium">{org.name}</span>
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                  {org.role}
                </span>
                {org.id === activeOrgId && (
                  <Check className="h-3.5 w-3.5 text-primary" />
                )}
              </DropdownMenuItem>
            ))
          )}

          <DropdownMenuSeparator />

          <DropdownMenuLabel>
            Projects{activeOrg ? ` in ${activeOrg.name}` : ""}
          </DropdownMenuLabel>
          {activeOrgId === null ? (
            <div className="px-2 py-3 text-xs text-muted-foreground">
              Pick an organization first.
            </div>
          ) : projectsQuery.isLoading ? (
            <div className="px-2 py-3 text-xs text-muted-foreground">
              Loading…
            </div>
          ) : projects.length === 0 ? (
            <div className="px-2 py-3 text-xs text-muted-foreground">
              No projects yet.
            </div>
          ) : (
            projects.map((project) => (
              <DropdownMenuItem
                key={project.id}
                onSelect={() => setActiveProject(project.id)}
                className="flex items-center gap-2"
              >
                <span className="flex-1 truncate font-mono text-xs">
                  {project.name}
                </span>
                {project.id === activeProjectId && (
                  <Check className="h-3.5 w-3.5 text-primary" />
                )}
              </DropdownMenuItem>
            ))
          )}

          <DropdownMenuSeparator />

          <DropdownMenuItem
            onSelect={() => setCreateProjectOpen(true)}
            disabled={!activeOrgId}
          >
            <FolderPlus className="h-3.5 w-3.5" />
            <span>New project</span>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => setCreateOrgOpen(true)}>
            <Plus className="h-3.5 w-3.5" />
            <span>New organization</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <CreateOrgDialog open={createOrgOpen} onOpenChange={setCreateOrgOpen} />
      <CreateProjectDialog
        open={createProjectOpen}
        onOpenChange={setCreateProjectOpen}
      />
    </>
  );
}

/** Project (primary line) + org (secondary line) for the two-line trigger. */
function switcherLabel(
  activeOrg: OrgWithRole | null,
  activeProject: ProjectRead | null,
  loading: boolean,
): { project: string; org: string } {
  if (loading) return { project: "Loading…", org: "" };
  if (!activeOrg) return { project: "Pick an organization", org: "" };
  return {
    project: activeProject?.name ?? "No project",
    org: activeOrg.name,
  };
}
