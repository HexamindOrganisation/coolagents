import { BookOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { docsUrl } from "@/lib/docs";

export function DocsLink({ path, label }: { path: string; label: string }) {
  return (
    <Button asChild variant="ghost" className="gap-2 text-muted-foreground">
      <a href={docsUrl(path)} target="_blank" rel="noopener noreferrer">
        <BookOpen className="size-4" />
        {label}
      </a>
    </Button>
  );
}
