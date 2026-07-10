import type { AuditWindow } from "@/lib/api";

/**
 * The internal SDK refresh window a ban propagates within — surfaced in
 * copy so operators know a create/revoke isn't instantaneous.
 *
 * Placeholder value: align with the SDK's actual ban-feed poll cadence
 * (§4.6 "takes effect within ~N seconds") before shipping.
 */
export const PROPAGATION_HINT = "a few seconds";

/** Blocked-attempts feed window options, in the order they render. */
export const WINDOWS: AuditWindow[] = ["24h", "7d", "30d", "90d"];

/** Page size for the blocked-attempts "Load more" pagination. */
export const PAGE_SIZE = 25;
