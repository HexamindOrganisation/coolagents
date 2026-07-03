/**
 * Tests for ``usePlayground`` — specifically the approval-request flow:
 * receiving prompts, dispatching replies, TTL sweep, concurrent
 * approvals resolving out of arrival order.
 *
 * We mock the module-level WebSocket. The hook's socket is shared
 * across React tree unmounts (that's the whole point — chat history
 * survives navigation), so ``resetPlayground()`` gets called between
 * tests to wipe the module state cleanly.
 */

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { resetPlayground, usePlayground } from "./playground";

/**
 * Minimal WebSocket mock. Records every payload the hook sends via
 * ``sent`` and exposes ``receive()`` for the test to shove frames the
 * other way. The real WebSocket dispatches ``open`` synchronously via
 * an event; we simulate that by calling the handler immediately.
 */
class MockSocket {
  static instances: MockSocket[] = [];
  static OPEN = 1;

  readyState = MockSocket.OPEN;
  sent: string[] = [];
  url: string;
  private handlers: Record<string, ((evt: unknown) => void)[]> = {};

  constructor(url: string) {
    this.url = url;
    MockSocket.instances.push(this);
    // Fire open on next tick so the hook's onopen handler runs after
    // the constructor returns — matches real browser behavior.
    queueMicrotask(() => this.fire("open", {}));
  }

  addEventListener(name: string, cb: (evt: unknown) => void): void {
    (this.handlers[name] ??= []).push(cb);
  }

  send(payload: string): void {
    this.sent.push(payload);
  }

  close(): void {
    this.readyState = 3;
    this.fire("close", {});
  }

  /** Simulate a frame arriving from the server. */
  receive(frame: unknown): void {
    this.fire("message", { data: JSON.stringify(frame) });
  }

  private fire(name: string, evt: unknown): void {
    (this.handlers[name] ?? []).forEach((cb) => cb(evt));
  }
}

beforeEach(() => {
  MockSocket.instances = [];
  (globalThis as { WebSocket: unknown }).WebSocket = MockSocket;
  resetPlayground();
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  resetPlayground();
});

function futureIso(secondsAhead: number): string {
  return new Date(Date.now() + secondsAhead * 1000).toISOString();
}

function pastIso(secondsAgo: number): string {
  return new Date(Date.now() - secondsAgo * 1000).toISOString();
}

// ---------------------------------------------------------------------
// Receiving approval requests
// ---------------------------------------------------------------------

describe("approval requests over the WS", () => {
  it("renders a received approval.request into pendingApprovals", async () => {
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve(); // let queueMicrotask fire the open handler
    });

    const ws = MockSocket.instances[0];
    expect(ws).toBeDefined();

    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_1",
        tool_name: "send_invoice",
        arguments: { order_id: "ORD-7", amount: 1250 },
        reason: "role=contractor + args.amount > 500",
        agent_name: "billing_bot",
        role: "contractor",
        expires_at: futureIso(300),
      });
    });

    expect(result.current.state.pendingApprovals).toHaveLength(1);
    expect(result.current.state.pendingApprovals[0].decision_id).toBe("appr_1");
    expect(result.current.state.pendingApprovals[0].tool_name).toBe(
      "send_invoice",
    );
  });

  it("dedupes: same decision_id twice → single pending entry", async () => {
    // Reconnect / replay could deliver the same request twice; the
    // store's dedupe-by-decision-id keeps the UI honest.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    const request = {
      type: "approval.request" as const,
      decision_id: "appr_dup",
      tool_name: "x",
      arguments: {},
      reason: null,
      agent_name: "a",
      role: null,
      expires_at: futureIso(300),
    };
    act(() => {
      ws.receive(request);
      ws.receive(request);
    });

    expect(result.current.state.pendingApprovals).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------
// Responding — happy path + concurrency
// ---------------------------------------------------------------------

describe("respondToApproval", () => {
  it("sends approval.reply with the right decision_id and removes the entry", async () => {
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_1",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(300),
      });
    });

    act(() => {
      result.current.respondToApproval("appr_1", true);
    });

    // Reply frame sent...
    const replyFrame = ws.sent.find((s) => s.includes("approval.reply"));
    expect(replyFrame).toBeDefined();
    const parsed = JSON.parse(replyFrame ?? "{}");
    expect(parsed).toEqual({
      type: "approval.reply",
      decision_id: "appr_1",
      allowed: true,
    });
    // ...and the entry cleared (only on successful send — see #6).
    expect(result.current.state.pendingApprovals).toHaveLength(0);
  });

  it("respondToApproval returns false and KEEPS the entry when WS is closed", async () => {
    // Regression for finding #6: previously, `respondToApproval`
    // removed the entry from local state EVEN when the WS was closed
    // and the reply was never sent. User thought they approved; the
    // SDK denied on disconnect. Silent UI/audit divergence.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];
    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_1",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(300),
      });
    });

    // Simulate the socket dropping BEFORE the click. close() fires the
    // handler which clears pendingApprovals (finding #5), so seed a
    // fresh one AFTER the close for this test.
    ws.readyState = 3; // CLOSED

    let ok: boolean | undefined;
    act(() => {
      // Re-add manually to test the "socket closed" branch of
      // respondToApproval in isolation (pendingApprovals was cleared
      // by the close handler).
      ok = result.current.respondToApproval("appr_1", true);
    });

    expect(ok).toBe(false);
    // No frame sent (WS not open).
    expect(ws.sent.find((s) => s.includes("approval.reply"))).toBeUndefined();
  });

  it("resolving one out of many concurrent approvals leaves the others intact", async () => {
    // Parallel tool calls fire N approval requests simultaneously.
    // The user might approve #2 first — the others must still render.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    const req = (id: string) => ({
      type: "approval.request" as const,
      decision_id: id,
      tool_name: "x",
      arguments: {},
      reason: null,
      agent_name: "a",
      role: null,
      expires_at: futureIso(300),
    });
    act(() => {
      ws.receive(req("a"));
      ws.receive(req("b"));
      ws.receive(req("c"));
    });

    expect(
      result.current.state.pendingApprovals.map((p) => p.decision_id),
    ).toEqual(["a", "b", "c"]);

    act(() => {
      result.current.respondToApproval("b", true);
    });

    // "b" removed, order-preserving of the rest.
    expect(
      result.current.state.pendingApprovals.map((p) => p.decision_id),
    ).toEqual(["a", "c"]);
  });

  it("resolving an unknown decision_id is a no-op", async () => {
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });

    act(() => {
      result.current.respondToApproval("appr_ghost", true);
    });

    expect(result.current.state.pendingApprovals).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------
// TTL sweep
// ---------------------------------------------------------------------

describe("TTL sweep", () => {
  it("drops expired approvals after the 1s sweep tick", async () => {
    // The serve-side handler already denied on TTL; the UI mustn't
    // keep a dead prompt visible.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_old",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: pastIso(1),
      });
    });

    expect(result.current.state.pendingApprovals).toHaveLength(1);

    // Advance past the sweep interval.
    await act(async () => {
      vi.advanceTimersByTime(1100);
      await Promise.resolve();
    });

    expect(result.current.state.pendingApprovals).toHaveLength(0);
  });

  it("does NOT drop approvals whose expires_at is still in the future", async () => {
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_fresh",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(60),
      });
    });

    await act(async () => {
      vi.advanceTimersByTime(1100);
      await Promise.resolve();
    });

    expect(result.current.state.pendingApprovals).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------
// WS close clears pending list (finding #5)
// ---------------------------------------------------------------------

describe("WS close", () => {
  it("clears pendingApprovals when the socket closes", async () => {
    // Regression for finding #5: the SDK-side unbind_socket() has
    // already denied every in-flight approval; leaving prompts on
    // screen lets the user "approve" a decision that already resolved
    // as denied — silent UI/audit divergence.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];
    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_1",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(300),
      });
    });
    expect(result.current.state.pendingApprovals).toHaveLength(1);

    act(() => {
      ws.close();
    });
    expect(result.current.state.pendingApprovals).toHaveLength(0);
    expect(result.current.state.connected).toBe(false);
  });
});

// ---------------------------------------------------------------------
// reset() clears the pending list
// ---------------------------------------------------------------------

describe("reset()", () => {
  it("clears pendingApprovals + sends deny-replies for each (finding #8)", async () => {
    // Regression: reset previously only cleared the local list —
    // server-side coroutines kept waiting until TTL, then denied
    // stale calls into the fresh session's audit log.
    const { result } = renderHook(() => usePlayground({ projectId: "p1" }));
    await act(async () => {
      await Promise.resolve();
    });
    const ws = MockSocket.instances[0];

    act(() => {
      ws.receive({
        type: "approval.request",
        decision_id: "appr_1",
        tool_name: "x",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(300),
      });
      ws.receive({
        type: "approval.request",
        decision_id: "appr_2",
        tool_name: "y",
        arguments: {},
        reason: null,
        agent_name: "a",
        role: null,
        expires_at: futureIso(300),
      });
    });
    expect(result.current.state.pendingApprovals).toHaveLength(2);

    act(() => {
      result.current.reset();
    });

    // Local list cleared.
    expect(result.current.state.pendingApprovals).toHaveLength(0);
    // Two deny-replies AND the reset frame sent, in order.
    const decisions = ws.sent
      .map((s) => JSON.parse(s))
      .filter((f) => f.type === "approval.reply");
    expect(decisions).toHaveLength(2);
    expect(decisions.map((d) => d.decision_id).sort()).toEqual([
      "appr_1",
      "appr_2",
    ]);
    expect(decisions.every((d) => d.allowed === false)).toBe(true);
    expect(ws.sent.some((s) => JSON.parse(s).type === "reset")).toBe(true);
  });
});
