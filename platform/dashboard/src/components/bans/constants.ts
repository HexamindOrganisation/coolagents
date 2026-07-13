import type { AuditWindow } from "@/lib/api";

/**
 * When a ban starts (and stops) applying, in user-facing copy.
 *
 * The SDK checks bans at the start of every agent run — a conditional GET on
 * the ban feed (ETag/304) in `BanGate` — so there is no timed poll or TTL: a
 * create/revoke lands on the target's next run, and a run already in progress
 * is not interrupted. Hence an event ("the next run"), not a duration. Used
 * with the preposition "on" ("takes effect on the next run"). If the SDK later
 * grows a background poll/TTL (plan §4.6), revisit this wording.
 */
export const PROPAGATION_HINT = "the next run";

/** Blocked-attempts feed window options, in the order they render. */
export const WINDOWS: AuditWindow[] = ["24h", "7d", "30d", "90d"];

/** Page size for the blocked-attempts "Load more" pagination. */
export const PAGE_SIZE = 25;
