import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAgentSelection } from "@/lib/agent_param";
import {
  AlertTriangle,
  Bot,
  FileCode,
  Network,
  Save,
  ShieldCheck,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
} from "@xyflow/react";
import { api, type PolicyValidationError } from "@/lib/api";
import { useProjectScoped } from "@/lib/active";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { PolicyEditor } from "@/components/PolicyEditor";
import { nodeTypes } from "@/components/graph/nodes";
import { buildPolicyGraph } from "@/lib/policy_graph";
import { cn } from "@/lib/utils";

type Tab = "yaml" | "graph";

const TAB_LABEL: Record<Tab, string> = {
  yaml: "YAML",
  graph: "Graph",
};

const TAB_ICON: Record<Tab, typeof FileCode> = {
  yaml: FileCode,
  graph: Network,
};

export function PoliciesPage() {
  const scope = useProjectScoped();
  const agents = useQuery({
    queryKey: ["agents", scope.projectId],
    queryFn: () => api.listAgents(scope.projectId as string),
    enabled: !!scope.projectId,
  });
  // ?agent= drives selection so navigating /agents?agent=X → click
  // "edit policy →" → land on /policies with the SAME X preselected.
  // resetOn=projectId clears the URL on a real project switch, but
  // NOT on the initial mount — so incoming ?agent= from a link is
  // preserved.
  const {
    selected: selectedAgent,
    set: setSelectedAgent,
    requested,
    notFound,
  } = useAgentSelection(agents.data, { resetOn: scope.projectId });
  const [tab, setTab] = useState<Tab>("yaml");

  if (scope.status === "no-project") {
    return <NoProjectEmptyState resource="policies" />;
  }

  return (
    <div className="-mx-8 -my-6 h-[calc(100vh-56px)] flex flex-col overflow-hidden">
      {/* Top bar: agent picker + tabs */}
      <header className="flex items-center justify-between gap-4 px-6 py-3 border-b border-border bg-card">
        <div className="flex items-center gap-3">
          <ShieldCheck className="size-4 text-muted-foreground" />
          <span className="text-sm font-medium">Policy</span>
          <AgentPicker
            agents={agents.data ?? []}
            value={selectedAgent}
            onChange={setSelectedAgent}
            loading={agents.isLoading}
          />
        </div>
        <Tabs value={tab} onChange={setTab} />
      </header>

      {/* URL asked for an agent this project doesn't have — show a banner
          instead of silently editing the wrong agent's policy. */}
      {notFound && requested && (
        <div className="flex items-center gap-2 px-6 py-2 text-xs bg-approval/5 border-b border-approval/30 text-approval">
          <AlertTriangle className="size-3.5 shrink-0" />
          <span>
            No agent named{" "}
            <span className="font-mono font-medium">{requested}</span> in this
            project.
            {selectedAgent && (
              <>
                {" Showing "}
                <span className="font-mono font-medium">{selectedAgent}</span>
                {" instead."}
              </>
            )}
          </span>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {selectedAgent && scope.projectId ? (
          tab === "yaml" ? (
            <YamlEditor agentName={selectedAgent} projectId={scope.projectId} />
          ) : (
            <PolicyGraphTab
              agentName={selectedAgent}
              projectId={scope.projectId}
            />
          )
        ) : (
          <div className="h-full grid place-items-center text-sm text-muted-foreground">
            {agents.isLoading ? "Loading agents…" : "No agents to select."}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Lightweight tab strip used in /policies. Two tabs today (YAML, Graph);
 * the M2 Rego adapter will land a third here without restructuring.
 */
function Tabs({ value, onChange }: { value: Tab; onChange: (t: Tab) => void }) {
  return (
    <div className="flex items-center gap-1 rounded-md border border-border bg-background p-0.5">
      {(["yaml", "graph"] as const).map((t) => {
        const Icon = TAB_ICON[t];
        const active = value === t;
        return (
          <button
            key={t}
            onClick={() => onChange(t)}
            className={cn(
              "flex items-center gap-1.5 rounded px-3 py-1 text-xs font-medium transition-colors",
              active
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="size-3" />
            {TAB_LABEL[t]}
          </button>
        );
      })}
    </div>
  );
}

/**
 * Agent picker — plain native <select>, styled to match the rest of the
 * dashboard's controls. A dropdown is enough today (≤5 agents per project);
 * if a project grows past ~20 agents this becomes a combobox/typeahead.
 */
function AgentPicker({
  agents,
  value,
  onChange,
  loading,
}: {
  agents: { name: string }[];
  value: string | null;
  onChange: (name: string) => void;
  loading: boolean;
}) {
  if (loading) {
    return <span className="text-xs text-muted-foreground">loading…</span>;
  }
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="text-muted-foreground text-xs">Agent:</span>
      <div className="relative">
        <Bot className="absolute left-2 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground pointer-events-none" />
        <select
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value)}
          className="h-8 rounded-md border border-border bg-background pl-7 pr-3 text-sm font-mono focus:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          {agents.map((a) => (
            <option key={a.name} value={a.name}>
              {a.name}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

/**
 * YAML editor pane — wraps the canonical ``policy.yaml`` of the selected
 * agent. Same primitive the /agents page used to host inline; relocated
 * here as the write-path for policies. The /agents page now only shows
 * manifest data, no policy editing.
 */
function YamlEditor({
  agentName,
  projectId,
}: {
  agentName: string;
  projectId: string;
}) {
  const qc = useQueryClient();
  const agent = useQuery({
    queryKey: ["agent", projectId, agentName],
    queryFn: () => api.getAgent(agentName, projectId),
  });

  const [draft, setDraft] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [errors, setErrors] = useState<PolicyValidationError[] | null>(null);

  // Re-sync the draft when we switch agents or the server copy refreshes.
  useEffect(() => {
    if (!agent.data) return;
    setDraft(agent.data.policy_yaml);
    setDirty(false);
    setErrors(null);
  }, [agent.data]);

  const saveMutation = useMutation({
    mutationFn: () =>
      api.updateAgent(agentName, { policy_yaml: draft }, projectId),
    onSuccess: () => {
      setDirty(false);
      qc.invalidateQueries({ queryKey: ["agent", projectId, agentName] });
      qc.invalidateQueries({ queryKey: ["agents", projectId] });
    },
  });

  const validateMutation = useMutation({
    mutationFn: () => api.validatePolicy(agentName, draft, projectId),
    onSuccess: (resp) => setErrors(resp.errors),
  });

  const originalSource = agent.data?.policy_yaml ?? "";

  // Stable identity so PolicyEditor doesn't trigger a CodeMirror
  // reconfigure on every keystroke — @uiw/react-codemirror puts
  // `onChange` in its reconfigure effect's dep array.
  const handleEditorChange = useCallback(
    (next: string) => {
      setDraft(next);
      setDirty(next !== originalSource);
      setErrors((prev) => (prev ? null : prev));
    },
    [originalSource],
  );

  return (
    <div className="h-full flex flex-col">
      <header className="flex items-center justify-between gap-2 px-6 py-2 border-b border-border">
        <div className="flex items-center gap-2 text-sm">
          <FileCode className="size-3.5 text-muted-foreground" />
          <span className="font-mono">{agentName}/policy.yaml</span>
          {dirty && <Badge variant="approval">unsaved</Badge>}
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            size="sm"
            variant="outline"
            onClick={() => validateMutation.mutate()}
            disabled={validateMutation.isPending}
            className="gap-1.5 h-8"
          >
            <ShieldCheck className="size-3.5" />
            {validateMutation.isPending ? "Checking…" : "Validate"}
          </Button>
          <Button
            size="sm"
            onClick={() => saveMutation.mutate()}
            disabled={!dirty || saveMutation.isPending}
            className="gap-2 h-8"
          >
            <Save className="size-3.5" />
            {saveMutation.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </header>
      {errors && (
        <div
          className={cn(
            "px-6 py-2 text-xs border-b",
            errors.length === 0
              ? "bg-allow/5 border-allow/30 text-allow"
              : "bg-deny/5 border-deny/30 text-deny",
          )}
        >
          {errors.length === 0 ? (
            <span>Policy parses cleanly.</span>
          ) : (
            <ul className="space-y-0.5 font-mono">
              {errors.map((err, i) => (
                <li key={i}>
                  {err.role && (
                    <span className="text-foreground">{err.role}</span>
                  )}
                  {err.role && err.line ? ":" : ""}
                  {err.line ? err.line : ""}
                  {err.role || err.line ? " — " : ""}
                  {err.message}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <PolicyEditor
        value={draft}
        onChange={handleEditorChange}
        diagnostics={errors}
        className="flex-1 overflow-hidden"
      />
    </div>
  );
}

/**
 * Graph tab — react-flow visualization of the agent's inline-roles policy.
 *
 * Two columns: roles on the left, tools on the right. Each role → tool
 * edge is colored by mode (green allow / amber approval_required / red
 * deny) and labeled with the constraint count when present. Inheritance
 * edges between roles are dashed and labeled "inherits". Mixin roles get
 * the muted RoleNode styling so they read as helpers, not personas.
 *
 * The view is read-only. Edit happens in the YAML tab; the graph updates
 * on the next tab-flip (no live re-layout during typing — keeps the
 * mental model "one source of truth, two views").
 */
function PolicyGraphTab({
  agentName,
  projectId,
}: {
  agentName: string;
  projectId: string;
}) {
  const agent = useQuery({
    queryKey: ["agent", projectId, agentName],
    queryFn: () => api.getAgent(agentName, projectId),
  });

  const graph = useMemo(() => {
    if (!agent.data) return null;
    return buildPolicyGraph(agent.data.policy_yaml);
  }, [agent.data]);

  if (!graph) {
    return (
      <div className="h-full grid place-items-center text-sm text-muted-foreground">
        Loading policy…
      </div>
    );
  }

  if (!graph.ok) {
    return (
      <div className="h-full grid place-items-center gap-2 text-center px-8">
        <AlertTriangle className="size-6 text-approval mx-auto" />
        <p className="text-sm text-muted-foreground max-w-md">
          Fix the YAML to render the graph. The document must parse cleanly and
          declare a top-level <span className="font-mono">roles:</span> map.
        </p>
      </div>
    );
  }

  return (
    <div className="h-full">
      <ReactFlow
        nodes={graph.nodes}
        edges={graph.edges}
        nodeTypes={nodeTypes}
        nodesDraggable={true}
        nodesConnectable={false}
        edgesFocusable={false}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="hsl(var(--border))"
        />
        <Controls
          position="bottom-right"
          showInteractive={false}
          className="!bg-card !border-border [&>button]:!bg-card [&>button]:!border-border"
        />
      </ReactFlow>
    </div>
  );
}
