import { useMemo, useState } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { yaml } from "@codemirror/lang-yaml";
import { CheckCircle2, MinusCircle, Play, ShieldAlert } from "lucide-react";

import {
  ApiError,
  type PolicyDraft,
  type PolicyTestOutcome,
  type PolicyTestResponse,
  type RoleBindings,
} from "@/lib/api";
import { useTestPolicy } from "@/lib/policy_modules";
import { policyEditorThemeTransparent } from "@/components/PolicyEditor/theme";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// JSON is a subset of YAML, so the YAML grammar highlights the call JSON
// (keys / strings / numbers) without pulling in a separate lang-json dep.
const JSON_EXTENSIONS = [yaml()];
const JSON_BASIC_SETUP = {
  lineNumbers: false,
  foldGutter: false,
  highlightActiveLine: false,
  highlightActiveLineGutter: false,
  autocompletion: false,
  bracketMatching: true,
  closeBrackets: true,
} as const;

const SAMPLE = '{\n  "tool": "refund_order",\n  "args": { "amount": 50 }\n}';

const OUTCOME: Record<
  PolicyTestOutcome,
  { label: string; className: string; Icon: typeof CheckCircle2 }
> = {
  allow: {
    label: "ALLOW",
    className: "bg-allow/10 border-allow/40 text-allow",
    Icon: CheckCircle2,
  },
  deny: {
    label: "DENY",
    className: "bg-deny/10 border-deny/40 text-deny",
    Icon: MinusCircle,
  },
  approval_required: {
    label: "APPROVAL REQUIRED",
    className: "bg-approval/10 border-approval/40 text-approval",
    Icon: ShieldAlert,
  },
};

/**
 * Decision tester — "would this call be allowed?". A role + a JSON call
 * (`{tool, args, attributes?}`) evaluated against the WHOLE resolved policy
 * (boundaries + that role's capabilities composed), not the open module. The
 * unsaved `draft` is overlaid so the verdict matches the resolved preview.
 */
export function TestPanel({
  projectId,
  roles,
  draft,
  resolves,
}: {
  projectId: string;
  roles: RoleBindings;
  draft: PolicyDraft | null;
  resolves: boolean;
}) {
  const roleNames = useMemo(() => Object.keys(roles).sort(), [roles]);
  const [role, setRole] = useState<string>(roleNames[0] ?? "");
  const [call, setCall] = useState<string>(SAMPLE);
  const [parseError, setParseError] = useState<string | null>(null);
  const test = useTestPolicy(projectId);

  // Keep a valid role selected as bindings load / change.
  const effectiveRole = roleNames.includes(role) ? role : (roleNames[0] ?? "");

  function run() {
    let parsed: { tool?: unknown; args?: unknown; attributes?: unknown };
    try {
      parsed = JSON.parse(call);
    } catch (e) {
      setParseError(e instanceof Error ? e.message : "invalid JSON");
      return;
    }
    if (!parsed || typeof parsed.tool !== "string" || !parsed.tool) {
      setParseError('the call must include a string "tool"');
      return;
    }
    const isObj = (v: unknown) =>
      typeof v === "object" && v !== null && !Array.isArray(v);
    if (parsed.args !== undefined && !isObj(parsed.args)) {
      setParseError('"args" must be a JSON object');
      return;
    }
    if (
      parsed.attributes !== undefined &&
      parsed.attributes !== null &&
      !isObj(parsed.attributes)
    ) {
      setParseError('"attributes" must be a JSON object');
      return;
    }
    setParseError(null);
    test.mutate({
      role: effectiveRole,
      tool: parsed.tool,
      args: (parsed.args as Record<string, unknown>) ?? {},
      attributes: (parsed.attributes as Record<string, unknown>) ?? null,
      draft,
    });
  }

  const disabled = !resolves || roleNames.length === 0;

  return (
    <div className="h-full flex flex-col gap-3 p-4 overflow-y-auto scrollbar-thin">
      {disabled && (
        <p className="text-xs text-muted-foreground">
          {roleNames.length === 0
            ? "Bind a role in roles.yaml to test a call."
            : "The policy doesn't currently resolve — fix the lints, then test."}
        </p>
      )}

      <label className="flex flex-col gap-1 text-xs">
        <span className="text-muted-foreground">Role</span>
        <select
          value={effectiveRole}
          onChange={(e) => setRole(e.target.value)}
          disabled={disabled}
          className="h-8 rounded-md border border-border bg-background px-2 text-sm font-mono focus:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50"
        >
          {roleNames.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
      </label>

      <div className="flex flex-col gap-1 text-xs flex-1 min-h-[120px]">
        <span className="text-muted-foreground">Call (JSON)</span>
        <div
          className={cn(
            "flex-1 overflow-auto rounded-md border border-border scrollbar-thin",
            disabled && "opacity-50 pointer-events-none",
          )}
        >
          <CodeMirror
            value={call}
            onChange={setCall}
            editable={!disabled}
            extensions={JSON_EXTENSIONS}
            theme={policyEditorThemeTransparent}
            basicSetup={JSON_BASIC_SETUP}
            height="100%"
            className="text-xs"
          />
        </div>
      </div>

      {parseError && (
        <p className="text-xs text-deny font-mono">{parseError}</p>
      )}

      <Button
        size="sm"
        onClick={run}
        disabled={disabled || test.isPending}
        className="gap-1.5 h-8 self-start"
      >
        <Play className="size-3.5" />
        {test.isPending ? "Checking…" : "Check"}
      </Button>

      {test.isError && (
        <p className="text-xs text-deny">
          {test.error instanceof ApiError
            ? test.error.message
            : "Could not evaluate the call."}
        </p>
      )}
      {test.data && <Verdict verdict={test.data} />}
    </div>
  );
}

function Verdict({ verdict }: { verdict: PolicyTestResponse }) {
  const spec = OUTCOME[verdict.outcome];
  const { Icon } = spec;
  return (
    <div className={cn("rounded-md border p-3 space-y-2", spec.className)}>
      <div className="flex items-center gap-1.5 text-sm font-semibold">
        <Icon className="size-4" />
        {spec.label}
      </div>
      {verdict.reason && (
        <p className="text-xs text-foreground/80">{verdict.reason}</p>
      )}
      {verdict.violations.length > 0 && (
        <ul className="text-xs font-mono text-foreground/80 space-y-0.5">
          {verdict.violations.map((v, i) => (
            <li key={i}>· {v}</li>
          ))}
        </ul>
      )}
      {verdict.hint && (
        <p className="text-[11px] text-muted-foreground">{verdict.hint}</p>
      )}
    </div>
  );
}
