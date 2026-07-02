import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * Shared "which agent is the user looking at?" selection, backed by the
 * `?agent=` URL param so it survives navigation between /agents,
 * /policies (and any other future route that operates on one agent).
 *
 * Before this hook: each route held a local ``useState`` and auto-picked
 * the first agent on mount — so clicking "edit policy →" from /agents
 * would land on /policies with a DIFFERENT agent selected than the one
 * the user was just viewing.
 *
 * ## Design constraints (learned the hard way in review)
 *
 * 1. **URL is source of truth, never silently rewritten.** If the user
 *    (or a shared bookmark) lands with ``?agent=support_bot`` and that
 *    agent was later renamed, we do NOT auto-rewrite the URL to some
 *    other agent — that turns "share this link" into "your colleague
 *    opens a random agent's policy." The stale name stays visible in
 *    the URL; ``fallbackName`` (the first agent, session-only) is what
 *    the picker/consumer actually renders while the URL disagrees.
 *
 * 2. **No mount-time clear.** A ``useEffect(clear, [projectId])`` fires
 *    on first render before the project ever "switches", so the effect
 *    would wipe every incoming ?agent= param on page load. Instead, the
 *    hook watches ``resetOn`` internally with a ref so it fires only on
 *    real transitions.
 *
 * 3. **Loading window preserves the URL.** During the query's first
 *    tick ``knownNames`` is an empty array or ``undefined``. Naively
 *    checking ``names.includes(raw)`` returns ``false`` and would drop
 *    the URL value on the floor. When names aren't known yet we trust
 *    the URL and expose ``raw`` — validation happens once the list
 *    arrives.
 *
 * 4. **Single hook, no split.** The two-hook split invited a caller to
 *    forget the memo or the auto-select effect; every caller ended up
 *    pasting the same three lines of glue. One hook, one call.
 */
export interface AgentSelection {
  /**
   * The agent name to hand to the picker + downstream data queries.
   *
   * Priority: ``?agent=`` if it matches a known name (or if names are
   * still loading) → first known name as a session-only fallback →
   * ``null``. The URL is never mutated by the fallback path — if you
   * see this value differ from the URL, it's a bookmarked-but-renamed
   * agent and the user should be aware.
   */
  selected: string | null;
  /** True when ``selected`` came from ``?agent=``, false when it's the
   *  first-agent fallback. Callers can surface an "agent not found in
   *  this project" banner instead of silently misrouting the user. */
  fromUrl: boolean;
  /** Called by the picker's onChange — updates ?agent= via ``replace``
   *  so picker clicks don't pollute the back-button trail. */
  set: (name: string) => void;
  /** The raw ``?agent=`` URL value, unchanged. ``null`` when the URL
   *  has no such param. Useful for "you asked for X but we're showing
   *  Y" banners without callers having to re-read useSearchParams. */
  requested: string | null;
  /** True once the agents list has loaded AND the URL asked for a name
   *  that isn't in it. Gated on ``namesLoaded`` so the banner doesn't
   *  flash during the initial fetch, and gated on "no project switch
   *  in flight" so it doesn't fire when the user is deliberately
   *  moving between projects. */
  notFound: boolean;
}

export interface UseAgentSelectionOptions {
  /**
   * Value whose change should reset the URL param (typically the
   * active project id). On the FIRST render the current value is
   * captured; the hook only clears when it later transitions to a
   * different value. Prevents the mount-clear bug that stomped every
   * incoming `?agent=` param on load.
   */
  resetOn?: string | null;
}

/**
 * The one-line agent-selection hook every route on the "picks one
 * agent" pattern should call.
 *
 * Pass the raw list you got from the API — the hook extracts names +
 * derives the selection + wires the URL. Callers write:
 *
 *   const { selected, set } = useAgentSelection(agents.data, {
 *     resetOn: scope.projectId,
 *   });
 *
 * Instead of the previous 3-line boilerplate + eslint-disable.
 */
export function useAgentSelection(
  agents: readonly { name: string }[] | undefined,
  options: UseAgentSelectionOptions = {},
): AgentSelection {
  const [params, setParams] = useSearchParams();
  const raw = params.get("agent");
  const namesLoaded = agents !== undefined;
  const knownNames = useMemo(
    () => (agents ? agents.map((a) => a.name) : []),
    [agents],
  );

  // Track resetOn transitions across renders. A "real switch" is a
  // transition between two KNOWN project ids (both non-null and
  // different). null → realId is just orgs-hydration completing; the
  // user hasn't switched anything. realId → null is between-route
  // teardown. Neither counts.
  //
  // Held as state (not a ref) so lint is happy and the "just switched"
  // signal is visible during render. Setting state during render is
  // the React-blessed pattern for "adjust state when a prop changes";
  // React discards this render's output and re-runs synchronously
  // with the new state before committing anything to the DOM.
  const [lastResetOn, setLastResetOn] = useState<string | null | undefined>(
    options.resetOn,
  );
  const isSwitchingProjects =
    lastResetOn != null &&
    options.resetOn != null &&
    lastResetOn !== options.resetOn;

  // Resolve `selected`. Five-way branch:
  //   * mid-switch → the URL still carries the old project's ?agent=.
  //     Fall back to the new project's first agent (or null) so we
  //     don't fire a cross-project fetch this render. The effect
  //     below strips the stale param next tick.
  //   * names still loading → trust the URL (don't drop a valid value
  //     just because the list hasn't arrived yet).
  //   * URL points at a known name → use it.
  //   * URL is missing OR points at a name the list doesn't have →
  //     fall back to first known name (session-only, no URL write).
  let selected: string | null;
  let fromUrl: boolean;
  if (isSwitchingProjects) {
    selected = knownNames.length > 0 ? knownNames[0] : null;
    fromUrl = false;
  } else if (raw && !namesLoaded) {
    selected = raw;
    fromUrl = true;
  } else if (raw && knownNames.includes(raw)) {
    selected = raw;
    fromUrl = true;
  } else if (knownNames.length > 0) {
    selected = knownNames[0];
    fromUrl = false;
  } else {
    selected = null;
    fromUrl = false;
  }

  // "You asked for X, we're showing Y." Only fires once names have
  // loaded (so no flash during the initial fetch) and only when the
  // requested name genuinely isn't in the new project (never on the
  // switch itself, which will resolve next tick).
  const notFound =
    raw !== null &&
    namesLoaded &&
    !knownNames.includes(raw) &&
    !isSwitchingProjects;

  const set = useCallback(
    (name: string) => {
      const next = new URLSearchParams(params);
      next.set("agent", name);
      setParams(next, { replace: true });
    },
    [params, setParams],
  );

  // Only a real switch between two known project ids clears the URL.
  // Hydration (null → realId) and route exits (realId → null) leave
  // the URL alone. ``resetOn=undefined`` opts out entirely.
  useEffect(() => {
    if (lastResetOn === options.resetOn) return;
    setLastResetOn(options.resetOn);
    if (lastResetOn == null || options.resetOn == null) return;
    if (params.has("agent")) {
      const next = new URLSearchParams(params);
      next.delete("agent");
      setParams(next, { replace: true });
    }
  }, [options.resetOn, lastResetOn, params, setParams]);

  return { selected, fromUrl, set, requested: raw, notFound };
}
