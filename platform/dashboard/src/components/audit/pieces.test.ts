import { describe, expect, it } from "vitest";

import type { AuditDecisionRow } from "@/lib/api";
import { callerRoles } from "@/components/audit/pieces";

const row = (over: Partial<AuditDecisionRow>): AuditDecisionRow =>
  ({
    event_id: "e",
    occurred_at: "2026-06-01T10:00:00Z",
    received_at: "2026-06-01T10:00:01Z",
    agent_name: "a",
    agent_version_id: "v1",
    session_id: "s",
    user_id: "u",
    tool_name: "t",
    role: "",
    user_roles: [],
    deciding_role: "",
    outcome: "allow",
    error_type: "",
    reason: "",
    violations: [],
    hint: null,
    arguments: null,
    attributes: null,
    ...over,
  }) as AuditDecisionRow;

describe("callerRoles", () => {
  it("returns the recorded role set in order", () => {
    expect(callerRoles(row({ user_roles: ["support", "billing"] }))).toEqual([
      "support",
      "billing",
    ]);
  });

  it("prefers user_roles over the legacy scalar", () => {
    // `role` is only the FIRST role, so it must never override the full set.
    expect(
      callerRoles(row({ role: "support", user_roles: ["support", "billing"] })),
    ).toEqual(["support", "billing"]);
  });

  it("falls back to the legacy scalar when no set was recorded", () => {
    // A row from an API predating the column — must not blank out.
    expect(callerRoles(row({ role: "analyst", user_roles: [] }))).toEqual([
      "analyst",
    ]);
  });

  it("returns empty when neither is set, rather than a blank member", () => {
    // [""] would render as an empty chip and read as "a role named ''".
    expect(callerRoles(row({}))).toEqual([]);
  });

  it("tolerates user_roles being absent entirely", () => {
    // Defensive: a hand-rolled or stale API response may omit the key, and
    // the events table must not throw on it.
    const legacy = { ...row({ role: "analyst" }) } as Partial<AuditDecisionRow>;
    delete legacy.user_roles;
    expect(callerRoles(legacy as AuditDecisionRow)).toEqual(["analyst"]);
  });
});
