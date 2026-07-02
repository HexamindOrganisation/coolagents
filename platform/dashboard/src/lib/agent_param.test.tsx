/**
 * Tests for ``useAgentSelection`` — the single hook that backs
 * ?agent= sync across /agents and /policies.
 *
 * The invariants this file pins (many learned in review after the
 * first draft broke every one of them):
 *
 *   1. ?agent= from the URL is preserved on first render, even while
 *      the agents query is still loading (knownNames=undefined).
 *   2. When the URL points at a stale/renamed agent, ``selected``
 *      falls back to the first known name — but the URL is NEVER
 *      auto-rewritten (bookmarks stay shareable, ``fromUrl`` flags
 *      the divergence so callers can surface a banner).
 *   3. ``set()`` writes ?agent= with replace, no back-button pollution.
 *   4. ``resetOn`` only clears on real transitions — a stable value
 *      across renders does NOT wipe an incoming URL param at mount.
 *   5. ``resetOn`` = undefined opts out of reset entirely.
 */

import { act, renderHook } from "@testing-library/react";
import type { JSX, ReactNode } from "react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { useAgentSelection } from "./agent_param";

function wrapperAt(initialUrl: string) {
  return ({ children }: { children: ReactNode }): JSX.Element => (
    <MemoryRouter initialEntries={[initialUrl]}>{children}</MemoryRouter>
  );
}

const AGENTS = (...names: string[]) => names.map((name) => ({ name }));

describe("useAgentSelection — URL is source of truth", () => {
  it("returns the ?agent= value when it matches a known name", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies?agent=beta") },
    );
    expect(result.current.selected).toBe("beta");
    expect(result.current.fromUrl).toBe(true);
  });

  it("preserves ?agent= on first render while agents are still loading", () => {
    // Regression for the loading-race bug: previously, knownNames=[]
    // during the query's first tick made ``[].includes("beta")`` false,
    // dropping the URL value on the floor. Passing undefined here
    // simulates the pre-fetch state; the URL value must ride through.
    const { result } = renderHook(() => useAgentSelection(undefined), {
      wrapper: wrapperAt("/policies?agent=beta"),
    });
    expect(result.current.selected).toBe("beta");
    expect(result.current.fromUrl).toBe(true);
  });
});

describe("useAgentSelection — stale/missing URL falls back without rewriting", () => {
  it("falls back to the first known name when ?agent= doesn't match", () => {
    // Bookmark to a renamed / deleted agent. ``selected`` must produce
    // SOMETHING so the picker isn't blank, but ``fromUrl=false`` tells
    // the caller "this isn't what the URL asked for."
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies?agent=gone") },
    );
    expect(result.current.selected).toBe("alpha");
    expect(result.current.fromUrl).toBe(false);
  });

  it("does NOT auto-rewrite the URL on stale-fallback", () => {
    // Regression for the "silent-misroute-on-share" bug: previously,
    // useAutoSelectFirstAgent called set() on any mismatch, replacing
    // ?agent=support_bot (renamed) with ?agent=alpha_agent — so
    // sharing the URL from the address bar sent colleagues to the
    // wrong agent. The stale URL must remain visible.
    const { result } = renderHook(
      () => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"));
        const location = useLocation();
        return { sel, location };
      },
      { wrapper: wrapperAt("/policies?agent=gone") },
    );
    expect(result.current.location.search).toBe("?agent=gone");
  });

  it("falls back to first agent when no ?agent= param is set", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies") },
    );
    expect(result.current.selected).toBe("alpha");
    expect(result.current.fromUrl).toBe(false);
  });

  it("returns null when no agents are known and URL is unset", () => {
    const { result } = renderHook(() => useAgentSelection(AGENTS()), {
      wrapper: wrapperAt("/policies"),
    });
    expect(result.current.selected).toBeNull();
    expect(result.current.fromUrl).toBe(false);
  });

  it("returns null when the agents query hasn't returned yet AND URL is unset", () => {
    // Nothing to select from + nothing on the URL → null is honest,
    // don't invent a value.
    const { result } = renderHook(() => useAgentSelection(undefined), {
      wrapper: wrapperAt("/policies"),
    });
    expect(result.current.selected).toBeNull();
  });
});

describe("useAgentSelection — set() writes to URL", () => {
  it("set() writes ?agent= without pushing a history entry", () => {
    const { result } = renderHook(
      () => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"));
        const location = useLocation();
        return { sel, location };
      },
      { wrapper: wrapperAt("/policies") },
    );
    act(() => {
      result.current.sel.set("beta");
    });
    expect(result.current.location.search).toBe("?agent=beta");
    expect(result.current.sel.selected).toBe("beta");
    expect(result.current.sel.fromUrl).toBe(true);
  });

  it("set() preserves other query params", () => {
    // A future route may add e.g. ?tab=graph — set/reset on agent must
    // not stomp unrelated keys.
    const { result } = renderHook(
      () => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"));
        const location = useLocation();
        return { sel, location };
      },
      { wrapper: wrapperAt("/policies?tab=graph") },
    );
    act(() => {
      result.current.sel.set("alpha");
    });
    expect(result.current.location.search).toContain("tab=graph");
    expect(result.current.location.search).toContain("agent=alpha");
  });
});

describe("useAgentSelection — resetOn", () => {
  it("does NOT clear the URL on the initial mount, even when resetOn is set", () => {
    // Regression for the mount-clear bug that stomped every incoming
    // ?agent= on load — the ref must snapshot the initial resetOn
    // value and only clear on a real transition later.
    const { result } = renderHook(
      ({ project }: { project: string }) => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"), {
          resetOn: project,
        });
        const location = useLocation();
        return { sel, location };
      },
      {
        initialProps: { project: "proj-1" },
        wrapper: wrapperAt("/policies?agent=beta"),
      },
    );
    expect(result.current.location.search).toBe("?agent=beta");
    expect(result.current.sel.selected).toBe("beta");
  });

  it("clears the URL when resetOn transitions to a different value", () => {
    const { result, rerender } = renderHook(
      ({ project }: { project: string }) => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"), {
          resetOn: project,
        });
        const location = useLocation();
        return { sel, location };
      },
      {
        initialProps: { project: "proj-1" },
        wrapper: wrapperAt("/policies?agent=beta"),
      },
    );

    // Sanity: URL preserved on mount.
    expect(result.current.location.search).toBe("?agent=beta");

    // Project switch → agent param cleared (the previous project's
    // agent name means nothing here).
    rerender({ project: "proj-2" });
    expect(result.current.location.search).not.toContain("agent=beta");
    // First-agent fallback kicked in — no user-visible "empty" state.
    expect(result.current.sel.selected).toBe("alpha");
    expect(result.current.sel.fromUrl).toBe(false);
  });

  it("resetOn=undefined opts out of clearing entirely", () => {
    // Routes with no project scope don't want the URL wiped ever.
    const { result, rerender } = renderHook(
      () => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"));
        const location = useLocation();
        return { sel, location };
      },
      { wrapper: wrapperAt("/policies?agent=beta") },
    );
    rerender();
    rerender();
    expect(result.current.location.search).toBe("?agent=beta");
  });

  it("does NOT clear the URL when resetOn hydrates from null to a real id", () => {
    // Regression for the hydration-clear bug. useProjectScoped returns
    // null while useOrgs() is loading, then transitions to a real id
    // once orgs land. The old ref-guard fired the reset on that
    // transition, stripping ?agent= on every cold page load. The fix:
    // a transition where either endpoint is null/undefined is not a
    // "switch" and must leave the URL alone.
    const { result, rerender } = renderHook(
      ({ project }: { project: string | null }) => {
        const sel = useAgentSelection(AGENTS("alpha", "beta"), {
          resetOn: project,
        });
        const location = useLocation();
        return { sel, location };
      },
      {
        initialProps: { project: null },
        wrapper: wrapperAt("/policies?agent=beta"),
      },
    );

    // Orgs finished loading — project id materializes. The URL param
    // must stay put; the user did not switch projects, we just learned
    // which project they were already on.
    rerender({ project: "proj-1" });
    expect(result.current.location.search).toBe("?agent=beta");
    expect(result.current.sel.selected).toBe("beta");
    expect(result.current.sel.fromUrl).toBe(true);
  });

  it("does NOT leak the old project's ?agent= into the new project on a switch", () => {
    // Regression for the loading-window race. On a project switch,
    // react-query drops agents.data to undefined until the new fetch
    // lands. The old loading-window branch trusted `raw` unconditionally
    // and handed the stale name to downstream fetches — a 404 flash or
    // (worse) a cross-project edit if the name happened to collide.
    // Fix: detect the switch during render and fall back to the new
    // project's first agent (or null) instead of the stale URL value.
    let currentAgents: readonly { name: string }[] | undefined = AGENTS(
      "alpha",
      "beta",
    );
    const { result, rerender } = renderHook(
      ({ project }: { project: string }) => {
        const sel = useAgentSelection(currentAgents, { resetOn: project });
        return { sel };
      },
      {
        initialProps: { project: "proj-1" },
        wrapper: wrapperAt("/policies?agent=beta"),
      },
    );

    // Sanity: URL wins on mount.
    expect(result.current.sel.selected).toBe("beta");

    // Project switch AND react-query drops data to undefined at the
    // same tick — the switching-projects guard must fire even though
    // knownNames is empty here.
    currentAgents = undefined;
    rerender({ project: "proj-2" });
    expect(result.current.sel.selected).toBeNull();
    expect(result.current.sel.fromUrl).toBe(false);
  });
});

describe("useAgentSelection — notFound + requested for the banner", () => {
  it("exposes requested = raw ?agent= value regardless of match", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies?agent=gone") },
    );
    expect(result.current.requested).toBe("gone");
  });

  it("requested is null when ?agent= is absent", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies") },
    );
    expect(result.current.requested).toBeNull();
  });

  it("notFound=true once names have loaded and ?agent= is not among them", () => {
    // Regression for the silent-misroute-to-wrong-agent bug. fromUrl
    // was computed but never surfaced, so callers had no signal to
    // render the "we're editing X, not Y" banner. Save then went to
    // the wrong agent.
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies?agent=gone") },
    );
    expect(result.current.notFound).toBe(true);
    expect(result.current.selected).toBe("alpha");
  });

  it("notFound=false while names are still loading (no flash)", () => {
    // The banner must not appear during the initial fetch — the URL
    // param may well be valid, we just don't know yet.
    const { result } = renderHook(() => useAgentSelection(undefined), {
      wrapper: wrapperAt("/policies?agent=beta"),
    });
    expect(result.current.notFound).toBe(false);
  });

  it("notFound=false when the URL matches a known name", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies?agent=beta") },
    );
    expect(result.current.notFound).toBe(false);
  });

  it("notFound=false when ?agent= is absent (fallback is expected, not an error)", () => {
    const { result } = renderHook(
      () => useAgentSelection(AGENTS("alpha", "beta")),
      { wrapper: wrapperAt("/policies") },
    );
    expect(result.current.notFound).toBe(false);
  });
});
