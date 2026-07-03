import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
} from "@xyflow/react";
import { api } from "@/lib/api";
import { useProjectScoped } from "@/lib/active";
import { buildOverviewGraph } from "@/lib/graph";
import { nodeTypes } from "@/components/graph/nodes";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { Badge } from "@/components/ui/badge";

export function GraphPage() {
  const scope = useProjectScoped();
  const agents = useQuery({
    queryKey: ["agents", scope.projectId],
    queryFn: () => api.listAgents(scope.projectId as string),
    enabled: !!scope.projectId,
  });
  // Manifests are the source of truth for tools on code-registered
  // agents (hexgate register), whose Agent.agent_yaml is empty. Legacy
  // YAML-edited agents just don't have a manifest entry and fall back
  // to agent_yaml parsing. Both queries hit the same project so the
  // pair reload together on a project switch.
  const manifests = useQuery({
    queryKey: ["agent-manifests", scope.projectId],
    queryFn: () => api.listAgentManifests(scope.projectId as string),
    enabled: !!scope.projectId,
  });

  const { nodes, edges, agentViews } = useMemo(() => {
    if (!agents.data) return { nodes: [], edges: [], agentViews: [] };
    return buildOverviewGraph(agents.data, manifests.data);
  }, [agents.data, manifests.data]);

  if (scope.status === "no-project") {
    return <NoProjectEmptyState resource="graph" />;
  }

  return (
    <div className="-mx-8 -my-6 h-[calc(100vh-56px)] flex flex-col">
      <div className="flex items-start justify-between px-8 py-5 border-b border-border">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            Graph overview
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Roles, agents, and tools for this project. Read-only — edit in{" "}
            <span className="font-mono text-foreground">/agents</span>.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <Badge variant="allow">allow</Badge>
          <Badge variant="approval">approval</Badge>
          <Badge variant="deny">deny</Badge>
        </div>
      </div>

      <div className="flex-1 relative">
        {agents.isLoading || manifests.isLoading ? (
          <div className="absolute inset-0 grid place-items-center text-sm text-muted-foreground">
            Loading…
          </div>
        ) : agentViews.length === 0 ? (
          <div className="absolute inset-0 grid place-items-center text-sm text-muted-foreground">
            No agents yet.
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            nodesDraggable={false}
            nodesConnectable={false}
            edgesFocusable={false}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            proOptions={{ hideAttribution: true }}
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={24}
              size={1}
              color="hsl(var(--border))"
            />
            <Controls showInteractive={false} />
            <MiniMap pannable maskColor="hsl(var(--background) / 0.6)" />
          </ReactFlow>
        )}
      </div>
    </div>
  );
}
