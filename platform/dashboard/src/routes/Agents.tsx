import { useQuery } from "@tanstack/react-query";
import { useAgentSelection } from "@/lib/agent_param";
import { Bot, FileText, ShieldCheck, Wrench } from "lucide-react";
import { Link } from "react-router-dom";
import {
  api,
  type AgentManifestView,
  type InputSchema,
  type ToolDefinition,
} from "@/lib/api";
import { useProjectScoped } from "@/lib/active";
import { Badge } from "@/components/ui/badge";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";

/**
 * /agents — read-only manifest view.
 *
 * Renders each agent's *registered* manifest, reconstructed from the
 * JSON snapshot stored on the latest AgentVersion row in Postgres (not
 * from the legacy agent.yaml text). When an Agent row exists but no
 * version has been registered yet (e.g. YAML-seeded fixtures), the view
 * degrades to an empty-state telling the user to register first.
 *
 * Editing happens elsewhere: policy authoring lives in /policies,
 * manifest registration goes through the SDK's ``hexgate register``.
 */
export function AgentsPage() {
  const scope = useProjectScoped();
  const manifests = useQuery({
    queryKey: ["agent-manifests", scope.projectId],
    queryFn: () => api.listAgentManifests(scope.projectId as string),
    enabled: !!scope.projectId,
  });
  // ?agent= drives selection so a link from /policies (or a shared URL
  // /agents?agent=support_bot) lands on the right agent. Falls back to
  // the first agent when the URL is unset or references a stale name.
  // resetOn=projectId means the URL clears on a real project change,
  // but NOT on the initial mount — so /agents?agent=beta from an
  // incoming link isn't stomped before the user sees it.
  const { selected: selectedName, set: setSelected } = useAgentSelection(
    manifests.data,
    { resetOn: scope.projectId },
  );

  const active = manifests.data?.find((m) => m.name === selectedName);

  if (scope.status === "no-project") {
    return <NoProjectEmptyState resource="agents" />;
  }

  return (
    <div className="-mx-8 -my-6 h-[calc(100vh-56px)] flex flex-col overflow-hidden">
      <header className="flex items-center gap-3 px-6 py-3 border-b border-border bg-card">
        <Bot className="size-4 text-muted-foreground" />
        <span className="text-sm font-medium">Agent</span>
        <AgentPicker
          agents={manifests.data ?? []}
          value={selectedName}
          onChange={setSelected}
          loading={manifests.isLoading}
        />
        <div className="flex-1" />
        {active && (
          <Link
            to={`/policies?agent=${encodeURIComponent(active.name)}`}
            className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5"
          >
            <ShieldCheck className="size-3" />
            edit policy →
          </Link>
        )}
      </header>

      <div className="flex-1 overflow-y-auto px-8 py-6 scrollbar-thin">
        {active ? (
          <ManifestView agent={active} />
        ) : (
          <div className="h-full grid place-items-center text-sm text-muted-foreground">
            {manifests.isLoading ? "Loading agents…" : "No agents to inspect."}
          </div>
        )}
      </div>
    </div>
  );
}

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
  if (loading)
    return <span className="text-xs text-muted-foreground">loading…</span>;
  return (
    <select
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
      className="h-8 rounded-md border border-border bg-background px-3 text-sm font-mono focus:outline-none focus-visible:ring-1 focus-visible:ring-ring"
    >
      {agents.map((a) => (
        <option key={a.name} value={a.name}>
          {a.name}
        </option>
      ))}
    </select>
  );
}

function ManifestView({ agent }: { agent: AgentManifestView }) {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <ManifestSummary agent={agent} />
      <ToolsSection
        tools={agent.manifest?.tools ?? []}
        unregistered={agent.manifest === null}
      />
      <SystemPromptSection
        prompt={agent.manifest?.system_prompt ?? null}
        unregistered={agent.manifest === null}
      />
    </div>
  );
}

function ManifestSummary({ agent }: { agent: AgentManifestView }) {
  const versionLabel =
    agent.version !== null ? `v${agent.version}` : "not registered";
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="px-5 py-4 border-b border-border flex items-center gap-2">
        <Bot className="size-4 text-primary" />
        <span className="text-sm font-medium">Manifest</span>
        <Badge variant="outline" className="ml-1 font-mono text-[11px]">
          {versionLabel}
        </Badge>
      </div>
      <dl className="divide-y divide-border text-sm">
        <ManifestRow label="Name" value={agent.name} mono />
        <ManifestRow
          label="Model"
          value={agent.manifest?.model?.trim() || "—"}
          mono
        />
        <ManifestRow
          label="Description"
          value={agent.manifest?.description?.trim() || "—"}
        />
        <ManifestRow
          label="Framework"
          value={agent.manifest?.framework?.trim() || "—"}
          mono
        />
        <ManifestRow
          label="Last updated"
          value={formatDate(agent.updated_at)}
        />
      </dl>
    </section>
  );
}

function ToolsSection({
  tools,
  unregistered,
}: {
  tools: ToolDefinition[];
  unregistered: boolean;
}) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="px-5 py-4 border-b border-border flex items-center gap-2">
        <Wrench className="size-4 text-muted-foreground" />
        <span className="text-sm font-medium">Tools</span>
        <Badge variant="outline" className="ml-1 font-mono text-[11px]">
          {tools.length}
        </Badge>
      </div>
      {tools.length === 0 ? (
        <p className="px-5 py-4 text-xs text-muted-foreground">
          {unregistered
            ? "Agent not registered yet — run `hexgate register` to populate."
            : "No tools declared."}
        </p>
      ) : (
        <ul className="divide-y divide-border">
          {tools.map((t) => (
            <ToolRow key={t.name} tool={t} />
          ))}
        </ul>
      )}
    </section>
  );
}

function SystemPromptSection({
  prompt,
  unregistered,
}: {
  prompt: string | null;
  unregistered: boolean;
}) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <div className="px-5 py-4 border-b border-border flex items-center gap-2">
        <FileText className="size-4 text-muted-foreground" />
        <span className="text-sm font-medium">System prompt</span>
        {prompt && (
          <Badge variant="outline" className="ml-1 font-mono text-[11px]">
            {prompt.length} chars
          </Badge>
        )}
      </div>
      {prompt ? (
        <details className="group" open>
          <summary className="px-5 py-2 text-[11px] text-muted-foreground cursor-pointer select-none">
            show / hide
          </summary>
          <pre className="px-5 pb-4 text-[12px] font-mono text-foreground whitespace-pre-wrap break-words">
            {prompt}
          </pre>
        </details>
      ) : (
        <p className="px-5 py-4 text-xs text-muted-foreground">
          {unregistered
            ? "Agent not registered yet — run `hexgate register` to populate."
            : "No system prompt declared."}
        </p>
      )}
    </section>
  );
}

function ToolRow({ tool }: { tool: ToolDefinition }) {
  return (
    <li className="px-5 py-4 space-y-2">
      <div className="flex items-baseline gap-3">
        <span className="font-mono text-sm text-foreground">{tool.name}</span>
      </div>
      {tool.description?.trim() ? (
        <p className="text-xs text-muted-foreground">{tool.description}</p>
      ) : null}
      <InputSchemaDetails schema={tool.input_schema} />
    </li>
  );
}

function InputSchemaDetails({ schema }: { schema: InputSchema }) {
  const entries = Object.entries(schema.properties);
  const required = new Set(schema.required);
  return (
    <details className="rounded-md border border-border bg-background/40 group">
      <summary className="px-3 py-2 cursor-pointer flex items-center gap-2 text-[11px] text-muted-foreground select-none">
        <span>inputs</span>
        <Badge variant="outline" className="font-mono text-[10px] py-0">
          {entries.length}
        </Badge>
      </summary>
      {entries.length === 0 ? (
        <p className="px-3 pb-2 text-[11px] text-muted-foreground">
          No inputs.
        </p>
      ) : (
        <ul className="px-3 pb-2 space-y-1 text-[11px] font-mono">
          {entries.map(([key, prop]) => (
            <li key={key} className="flex items-baseline gap-2">
              <span className="text-foreground">{key}</span>
              <span className="text-muted-foreground">: {prop.type}</span>
              {required.has(key) && (
                <Badge variant="outline" className="text-[9px] py-0">
                  required
                </Badge>
              )}
            </li>
          ))}
        </ul>
      )}
    </details>
  );
}

function ManifestRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="grid grid-cols-[120px_1fr] gap-4 px-5 py-2.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono text-foreground" : "text-foreground"}>
        {value}
      </dd>
    </div>
  );
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
