/** Shared time formatting for the Bans page tables. Relative for the
 * cell, absolute for the `title` tooltip on hover (§9.3). */

export function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

export function formatAbsolute(iso: string): string {
  return new Date(iso).toLocaleString();
}
