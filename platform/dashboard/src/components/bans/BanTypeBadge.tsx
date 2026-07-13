import { Badge } from "@/components/ui/badge";
import type { BanType } from "@/lib/bans";

/**
 * The Agent / User ban-type badge — visually distinct per §9.7:
 *   - agent → indigo   (Badge `primary`  = bg-primary/15 text-primary)
 *   - user  → amber    (Badge `approval` = bg-approval/15 text-approval)
 *
 * Kept in `components/bans/` (not inside the page) so the cross-page
 * tie-ins — Audit "Ban user", Agents "Ban agent" — render the exact
 * same badge everywhere the ban type appears.
 */
export function BanTypeBadge({ type }: { type: BanType }) {
  return (
    <Badge variant={type === "agent" ? "primary" : "approval"}>
      {type === "agent" ? "Agent" : "User"}
    </Badge>
  );
}
