import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  Plus,
  Trash2,
  Clock,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { NoProjectEmptyState } from "@/components/NoProjectEmptyState";
import { DocsLink } from "@/components/DocsLink";
import { DOC_PATHS } from "@/lib/docs";
import { api, type TokenMintResponse } from "@/lib/api";
import { useProjectScoped } from "@/lib/active";
import { cn } from "@/lib/utils";

function formatRelative(iso: string | null): string {
  if (!iso) return "Never";
  const then = new Date(iso).getTime();
  const diff = Date.now() - then;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function formatCreated(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function JustMintedBanner({
  token,
  onDismiss,
}: {
  token: TokenMintResponse;
  onDismiss: () => void;
}) {
  // Brief "Copied!" feedback on successful copy, with a label since this
  // is the prominent action on the dialog. 1200ms is long enough to
  // register, short enough that the operator who clicks twice doesn't see
  // a stale checkmark.
  const [copied, setCopied] = useState(false);
  // Copy-only \u2014 no reveal UI. Matches the show-once + copy-only pattern
  // GitHub / AWS / Stripe / Vercel / Discord use for API tokens. The
  // mask still shows the env-tagged prefix and the last 4 chars so the
  // operator can visually distinguish multiple tokens later in the
  // table; the full value reaches the clipboard via the Copy button.
  //
  // Tokens are `fty_(test|live)_<uuid>_<biscuit>` \u2014 keep the 9-char
  // env-tagged prefix and the last 4 of the biscuit; everything between
  // (the project UUID + opaque biscuit bytes) is masked.
  const prefixEnd = token.full.indexOf("_", 4) + 1;
  const masked =
    token.full.slice(0, prefixEnd > 0 ? prefixEnd : 9) +
    "\u2022".repeat(20) +
    token.full.slice(-4);
  return (
    <div className="rounded-lg border border-primary/40 bg-primary/5 p-5">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-2 text-sm">
          <Fingerprint className="size-4 text-primary" />
          <span className="font-medium">API key minted</span>
          <span className="text-muted-foreground">·</span>
          <span className="font-mono text-xs">{token.name}</span>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-approval">
          <AlertTriangle className="size-3.5" />
          Copy it now — we won't be able to show it again.
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2 rounded-md border border-border bg-background px-4 py-3 font-mono text-sm">
        {/* `min-w-0` is required for flex-1 + truncate to actually
           clip — without it the span's intrinsic min-width keeps it
           from shrinking, and the masked token pushes Copy past the
           parent. */}
        <span className="min-w-0 flex-1 truncate">{masked}</span>
        <Button
          variant="default"
          size="sm"
          onClick={async () => {
            await navigator.clipboard.writeText(token.full);
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          }}
          className="gap-1.5"
        >
          {copied ? (
            <Check className="size-3.5" />
          ) : (
            <Copy className="size-3.5" />
          )}
          {copied ? "Copied!" : "Copy"}
        </Button>
      </div>

      <div className="mt-3 flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <Clock className="size-3.5" />
          Created just now
        </span>
        <span className="flex items-center gap-1.5">
          <KeyRound className="size-3.5" />
          {token.scopes.length} scope{token.scopes.length === 1 ? "" : "s"}
        </span>
        <button
          onClick={onDismiss}
          className="ml-auto text-muted-foreground hover:text-foreground"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

function MintDialog({
  projectId,
  onSuccess,
}: {
  projectId: string;
  onSuccess: (token: TokenMintResponse) => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [env, setEnv] = useState<"test" | "live">("live");
  const qc = useQueryClient();

  const mutation = useMutation({
    mutationFn: (body: Parameters<typeof api.mintToken>[0]) =>
      api.mintToken(body, projectId),
    onSuccess: (token) => {
      qc.invalidateQueries({ queryKey: ["tokens", projectId] });
      onSuccess(token);
      setOpen(false);
      setName("");
    },
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) mutation.reset();
      }}
    >
      <DialogTrigger asChild>
        <Button className="gap-2">
          <Plus className="size-4" />
          Mint new API key
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Mint API key</DialogTitle>
          <DialogDescription>
            API keys authenticate backend services to Hexgate. Use a clear name
            so you know where it's deployed.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="token-name">Name</Label>
            <Input
              id="token-name"
              placeholder="e.g. backend-prod"
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <Label>Environment</Label>
            <div className="flex gap-2">
              {(["test", "live"] as const).map((value) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => setEnv(value)}
                  className={cn(
                    "flex-1 h-9 rounded-md border text-sm capitalize transition-colors",
                    env === value
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:text-foreground",
                  )}
                >
                  {value}
                </button>
              ))}
            </div>
            <p className="text-[11px] text-muted-foreground">
              <span className="font-mono">fty_test_</span> keys read from a
              local policy file.
              <span className="font-mono">fty_live_</span> keys fetch signed
              bundles from the control plane.
            </p>
          </div>

          {mutation.isError && (
            <div className="rounded-md border border-deny/40 bg-deny/5 p-3 text-sm text-deny">
              {(mutation.error as Error).message}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            onClick={() => mutation.mutate({ name, env })}
            disabled={name.trim().length === 0 || mutation.isPending}
          >
            {mutation.isPending ? "Minting…" : "Mint API key"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function TokensPage() {
  const [justMinted, setJustMinted] = useState<TokenMintResponse | null>(null);
  const scope = useProjectScoped();
  // ``enabled: !!scope.projectId`` keeps React Query quiet while we
  // wait for the active-project bootstrap; the cache key includes the
  // id so switching projects doesn't show stale rows.
  const tokens = useQuery({
    queryKey: ["tokens", scope.projectId],
    queryFn: () => api.listTokens(scope.projectId as string),
    enabled: !!scope.projectId,
  });
  const qc = useQueryClient();
  const revoke = useMutation({
    mutationFn: (tokenId: string) =>
      api.revokeToken(tokenId, scope.projectId as string),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["tokens", scope.projectId] }),
  });

  if (scope.status === "no-project") {
    return (
      <div className="max-w-[1400px] mx-auto">
        <h1 className="text-2xl font-semibold tracking-tight">API keys</h1>
        <NoProjectEmptyState resource="API keys" />
      </div>
    );
  }

  return (
    <div className="max-w-[1400px] mx-auto">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">API keys</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Long-lived API keys for backend services. Never commit to source
            control.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <DocsLink path={DOC_PATHS.tokens} label="API key docs" />
          {scope.projectId && (
            <MintDialog projectId={scope.projectId} onSuccess={setJustMinted} />
          )}
        </div>
      </div>

      {justMinted && (
        <div className="mt-6">
          <JustMintedBanner
            token={justMinted}
            onDismiss={() => setJustMinted(null)}
          />
        </div>
      )}

      <div className="mt-6 rounded-lg border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <div className="text-sm">
            API keys{" "}
            <span className="text-muted-foreground">
              · {tokens.data?.length ?? 0}
            </span>
          </div>
        </div>

        {tokens.isLoading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">
            Loading…
          </div>
        ) : !tokens.data || tokens.data.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 py-16 text-center">
            <KeyRound className="size-12 text-muted-foreground/50" />
            <div className="text-sm font-medium">No API keys yet</div>
            <div className="max-w-xs text-xs text-muted-foreground">
              Mint your first API key to let a backend service authenticate to
              Hexgate.
            </div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="px-5 py-2.5 text-left font-medium">Name</th>
                <th className="px-5 py-2.5 text-left font-medium">API key</th>
                <th className="px-5 py-2.5 text-left font-medium">Scopes</th>
                <th className="px-5 py-2.5 text-left font-medium">Created</th>
                <th className="px-5 py-2.5 text-left font-medium">Last used</th>
                <th className="px-5 py-2.5 w-24" />
              </tr>
            </thead>
            <tbody>
              {tokens.data.map((t) => {
                const isTest = t.masked.startsWith("fty_test_");
                return (
                  <tr
                    key={t.id}
                    className="border-b border-border/50 last:border-b-0 hover:bg-accent/50"
                  >
                    <td className="px-5 py-3">
                      <span className="flex items-center gap-2">
                        <KeyRound className="size-3.5 text-muted-foreground" />
                        <span className="font-medium">{t.name}</span>
                        {isTest && <Badge variant="approval">test</Badge>}
                        {!t.last_used_at && (
                          <Badge variant="outline">stale</Badge>
                        )}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className="font-mono text-xs text-muted-foreground">
                        {t.masked}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className="inline-flex flex-wrap gap-1">
                        {t.scopes.slice(0, 2).map((s) => (
                          <Badge key={s} variant="default">
                            {s}
                          </Badge>
                        ))}
                        {t.scopes.length > 2 && (
                          <Badge variant="outline">
                            +{t.scopes.length - 2}
                          </Badge>
                        )}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-muted-foreground">
                      {formatCreated(t.created_at)}
                    </td>
                    <td
                      className={cn(
                        "px-5 py-3",
                        t.last_used_at
                          ? "text-muted-foreground"
                          : "text-approval",
                      )}
                    >
                      {formatRelative(t.last_used_at)}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-0.5">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 text-deny hover:text-deny hover:bg-deny/10"
                          onClick={() => revoke.mutate(t.id)}
                          title="Revoke"
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
