import { BookOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { docsUrl } from "@/lib/docs";

type DocsLinkProps = {
  path: string;
  label: string;
  compact?: boolean;
};

export function DocsLink({ path, label, compact = false }: DocsLinkProps) {
  if (compact) {
    return (
      <a
        href={docsUrl(path)}
        target="_blank"
        rel="noopener noreferrer"
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
      >
        <BookOpen className="size-3" />
        {label}
      </a>
    );
  }

  return (
    <Button asChild variant="ghost" className="gap-2 text-muted-foreground">
      <a href={docsUrl(path)} target="_blank" rel="noopener noreferrer">
        <BookOpen className="size-4" />
        {label}
      </a>
    </Button>
  );
}
