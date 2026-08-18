import { useEffect, useSyncExternalStore } from "react";

export type ToolCallState = "started" | "completed" | "failed";
export type BlockType = "text" | "reasoning" | "tool_call";

export interface RunStartEvent {
  event_type: "run_start";
  query: string;
  run_id: string;
}

export interface BlockStartEvent {
  event_type: "block_start";
  block_id: string;
  block_type: BlockType;
}

export interface BlockDeltaEvent {
  event_type: "block_delta";
  block_id: string;
  block_type: BlockType;
  text: string;
}

export interface BlockEndEvent {
  event_type: "block_end";
  block_id: string;
  block_type: BlockType;
}

export interface ToolStartEvent {
  event_type: "tool_start";
  tool_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
}

export interface ToolEndEvent {
  event_type: "tool_end";
  tool_id: string;
  tool_name: string;
  state: ToolCallState;
  output_summary?: string | null;
}

export interface RunEndEvent {
  event_type: "run_end";
  result: { message: string };
}

export interface ErrorEvent {
  event_type: "error";
  message: string;
}

/**
 * Approval prompt emitted by ``hexgate serve`` when the enforcer flags
 * a tool call as ``approval_required``. The serve process blocks on
 * ``asyncio.Event`` until we send back an ``approval.reply`` with the
 * matching ``decision_id``. Fail-closed on both ends: TTL expiry or
 * server disconnect denies the underlying tool call.
 *
 * Uses ``type`` (not ``event_type``) — approval is a control frame,
 * not a streaming event, so it lines up with the other controls
 * (hello, session_reset, agent_online) rather than the LLM-turn
 * stream (run_start, block_delta, ...).
 */
export interface ApprovalRequestEvent {
  type: "approval.request";
  decision_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  reason: string | null;
  agent_name: string;
  /** The *deciding* role — whose policy gated this call. Null when none did. */
  role: string | null;
  /** Every role the caller carried. Absent from an older `hexgate serve`. */
  roles?: string[];
  expires_at: string; // ISO
}

export type StreamEvent =
  | RunStartEvent
  | BlockStartEvent
  | BlockDeltaEvent
  | BlockEndEvent
  | ToolStartEvent
  | ToolEndEvent
  | RunEndEvent
  | ErrorEvent;

export interface AgentOnlineEvent {
  type: "agent_online";
  online: boolean;
  agent?: string | null;
}
export interface SessionResetEvent {
  type: "session_reset";
}
export type ControlEvent = AgentOnlineEvent | SessionResetEvent;

// ——— UI model ———

export interface ToolCall {
  id: string;
  name: string;
  args: Record<string, unknown>;
  state: ToolCallState;
  outputSummary?: string | null;
  startedAt: number;
  endedAt?: number;
}

export interface AssistantTurn {
  id: string;
  streaming: boolean;
  text: string;
  reasoning: string;
  tools: ToolCall[];
  error?: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  turn?: AssistantTurn;
}

export interface PlaygroundState {
  connected: boolean;
  agentOnline: boolean;
  agentName: string | null;
  messages: ChatMessage[];
  decisions: ToolCall[];
  /** id of the assistant turn currently being streamed into. */
  currentTurnId: string | null;
  /** Approval prompts awaiting a click. Keyed by decision_id on
   * removal — NEVER by array index, since concurrent parallel tool
   * calls can resolve out of arrival order. */
  pendingApprovals: ApprovalRequestEvent[];
}

interface Options {
  projectId: string;
}

// ---------------------------------------------------------------------
// Module-level store
// ---------------------------------------------------------------------
//
// State + WebSocket live above React's component lifecycle so navigating
// away from /playground (e.g. to /policies) and back doesn't reset the
// chat. The hook subscribes via useSyncExternalStore; the socket
// connection survives unmount and is reused on remount.
//
// Lifecycle:
//   * First mount in a project: open the socket, populate state.
//   * Subsequent mounts (same project): no-op — the socket is already
//     up and `cachedState` is whatever the prior session left it at.
//   * Project switch: close the old socket, wipe state, open a new one
//     under the new project's chat endpoint.
//   * Tab close: browser destroys everything. We never explicitly close
//     in cleanup because the React component unmount is not the right
//     trigger for socket teardown here.

const INITIAL_STATE: PlaygroundState = {
  connected: false,
  agentOnline: false,
  agentName: null,
  messages: [],
  decisions: [],
  currentTurnId: null,
  pendingApprovals: [],
};

let cachedState: PlaygroundState = INITIAL_STATE;
const listeners = new Set<() => void>();

let activeSocket: WebSocket | null = null;
let activeProjectId: string | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempts = 0;

function setStore(updater: (s: PlaygroundState) => PlaygroundState): void {
  cachedState = updater(cachedState);
  listeners.forEach((l) => l());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function getSnapshot(): PlaygroundState {
  return cachedState;
}

function handleFrame(frame: unknown): void {
  if (!frame || typeof frame !== "object") return;
  const f = frame as { type?: string; event_type?: string };
  if (f.type === "agent_online") {
    const ev = f as AgentOnlineEvent;
    setStore((s) => ({
      ...s,
      agentOnline: Boolean(ev.online),
      agentName: ev.agent ?? (ev.online ? s.agentName : null),
    }));
    return;
  }
  if (f.type === "session_reset") return;
  if (f.type === "approval.request") {
    const req = f as ApprovalRequestEvent;
    setStore((s) => {
      // Idempotent — reconnect/replay must not duplicate an already-
      // pending approval. Match by decision_id.
      if (s.pendingApprovals.some((a) => a.decision_id === req.decision_id)) {
        return s;
      }
      return { ...s, pendingApprovals: [...s.pendingApprovals, req] };
    });
    return;
  }
  if (f.event_type) setStore((s) => applyEvent(s, f as StreamEvent));
}

function connectSocket(projectId: string): void {
  // Project changed under us while a reconnect was pending — abandon.
  if (activeProjectId !== projectId) return;
  const url = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/v1/projects/${projectId}/chat`;
  const ws = new WebSocket(url);
  activeSocket = ws;

  ws.addEventListener("open", () => {
    reconnectAttempts = 0;
    setStore((s) => ({ ...s, connected: true }));
  });

  ws.addEventListener("close", () => {
    // Clear pendingApprovals: the SDK-side unbind_socket() has already
    // denied every in-flight approval, so leaving prompts on screen
    // would let the user "approve" a decision that already resolved as
    // denied server-side — silent UI/audit divergence.
    setStore((s) => ({
      ...s,
      connected: false,
      agentOnline: false,
      pendingApprovals: [],
    }));
    if (activeProjectId === projectId) {
      const delay = Math.min(1000 * 2 ** reconnectAttempts, 15000);
      reconnectAttempts += 1;
      reconnectTimer = setTimeout(() => connectSocket(projectId), delay);
    }
  });

  ws.addEventListener("message", (evt) => {
    let payload: unknown;
    try {
      payload = JSON.parse(evt.data);
    } catch {
      return;
    }
    handleFrame(payload);
  });
}

/**
 * Drop all playground state + tear down the socket. Called from
 * `useLogout` so that a sign-out + sign-in cycle on the same browser
 * tab doesn't leak the prior user's chat history (module-level state
 * survives the React tree teardown, which is the whole point of the
 * refactor — but not across user identities).
 *
 * Idempotent: safe to call when no socket is open.
 */
export function resetPlayground(): void {
  if (activeSocket) {
    activeSocket.close();
    activeSocket = null;
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  activeProjectId = null;
  reconnectAttempts = 0;
  cachedState = INITIAL_STATE;
  listeners.forEach((l) => l());
}

function ensureSocketFor(projectId: string): void {
  // Same project + live socket → nothing to do. This is the common
  // remount path (route navigated away and back).
  if (activeProjectId === projectId && activeSocket) return;

  // Project switched — the prior session belongs to a different project,
  // wipe it and open a fresh connection.
  if (activeProjectId !== null && activeProjectId !== projectId) {
    activeSocket?.close();
    cachedState = INITIAL_STATE;
    listeners.forEach((l) => l());
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  activeProjectId = projectId;
  reconnectAttempts = 0;
  connectSocket(projectId);
}

// ---------------------------------------------------------------------
// React hook
// ---------------------------------------------------------------------

export function usePlayground({ projectId }: Options) {
  const state = useSyncExternalStore(subscribe, getSnapshot);

  useEffect(() => {
    ensureSocketFor(projectId);
    // No cleanup — the socket is intentionally module-scoped so
    // chat history survives route changes. Project-switch teardown
    // happens inside ensureSocketFor on the next mount.
  }, [projectId]);

  // Sweep expired approvals from the pending list every second — only
  // while there ARE pending approvals. In the common idle case (no
  // pending) the interval is not installed, so an open Playground tab
  // contributes zero timer wakeups.
  const hasPending = state.pendingApprovals.length > 0;
  useEffect(() => {
    if (!hasPending) return;
    const id = setInterval(() => {
      setStore((s) => {
        if (s.pendingApprovals.length === 0) return s;
        const now = Date.now();
        const kept = s.pendingApprovals.filter(
          (a) => new Date(a.expires_at).getTime() > now,
        );
        return kept.length === s.pendingApprovals.length
          ? s
          : { ...s, pendingApprovals: kept };
      });
    }, 1000);
    return () => clearInterval(id);
  }, [hasPending]);

  /**
   * Send a chat message, optionally scoped to one or more roles.
   *
   * A non-empty `roles` sends a `user_attenuation` block, which makes the dev's
   * `hexgate serve` attenuate its token to carry one `role()` fact per name for
   * this turn. The most permissive outcome wins, so adding a role only widens.
   */
  function sendChat(message: string, opts?: { roles?: string[] }) {
    const ws = activeSocket;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const turnId = randomId();
    const userMsg: ChatMessage = {
      id: randomId(),
      role: "user",
      content: message,
    };
    const turn: AssistantTurn = {
      id: turnId,
      streaming: true,
      text: "",
      reasoning: "",
      tools: [],
    };
    setStore((s) => ({
      ...s,
      currentTurnId: turnId,
      messages: [
        ...s.messages,
        userMsg,
        { id: turn.id, role: "assistant", content: "", turn },
      ],
    }));
    const frame: Record<string, unknown> = { type: "chat", message };
    const roles = (opts?.roles ?? []).filter(Boolean);
    if (roles.length) {
      frame.user_attenuation = {
        user: "playground",
        roles,
        // Singular kept for one release: a pinned older `hexgate serve` reads
        // only `role`. The current one prefers `roles`.
        role: roles[0],
        ttl_seconds: 300,
      };
    }
    ws.send(JSON.stringify(frame));
  }

  function reset() {
    const ws = activeSocket;
    const isOpen = ws && ws.readyState === WebSocket.OPEN;
    // Fire an explicit deny for each still-pending approval BEFORE the
    // reset frame. Without this, the serve-side coroutines keep waiting
    // up to the full 5min TTL, and denied events from the "old" turn
    // then land in the middle of the fresh session's audit log.
    if (isOpen) {
      for (const req of cachedState.pendingApprovals) {
        ws.send(
          JSON.stringify({
            type: "approval.reply",
            decision_id: req.decision_id,
            allowed: false,
          }),
        );
      }
      ws.send(JSON.stringify({ type: "reset" }));
    }
    setStore((s) => ({
      ...s,
      currentTurnId: null,
      messages: [],
      decisions: [],
      pendingApprovals: [],
    }));
  }

  /**
   * Resolve a pending approval prompt. Sends ``approval.reply`` to the
   * serve process — its ``asyncio.Event`` unblocks and the tool call
   * either runs (allowed=true) or returns a policy-denied envelope
   * (allowed=false). The local removal is gated on a SUCCESSFUL send:
   * if the WS is closed we keep the entry so the user sees the
   * disconnected state instead of a phantom "you approved this"
   * outcome that the SDK never received.
   */
  function respondToApproval(decision_id: string, allowed: boolean): boolean {
    const ws = activeSocket;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    try {
      ws.send(
        JSON.stringify({
          type: "approval.reply",
          decision_id,
          allowed,
        }),
      );
    } catch {
      return false;
    }
    setStore((s) => ({
      ...s,
      pendingApprovals: s.pendingApprovals.filter(
        (a) => a.decision_id !== decision_id,
      ),
    }));
    return true;
  }

  return { state, sendChat, reset, respondToApproval };
}

/**
 * Pure reducer over PlaygroundState + StreamEvent.
 *
 * No external mutations, no refs. Safe under React 18 StrictMode, which
 * double-invokes state updaters to verify they're deterministic. Called
 * N times with the same input, always returns the same output.
 */
function applyEvent(
  state: PlaygroundState,
  event: StreamEvent,
): PlaygroundState {
  const turnId = state.currentTurnId;
  if (!turnId) return state;

  const msgIdx = state.messages.findIndex((m) => m.turn?.id === turnId);
  if (msgIdx < 0) return state;

  const msg = state.messages[msgIdx];
  const turn = msg.turn;
  if (!turn) return state;

  const withTurn = (nextTurn: AssistantTurn): PlaygroundState => {
    const nextMessages = state.messages.slice();
    nextMessages[msgIdx] = { ...msg, content: nextTurn.text, turn: nextTurn };
    return { ...state, messages: nextMessages };
  };

  switch (event.event_type) {
    case "run_start":
      return withTurn({ ...turn, streaming: true });

    case "block_delta": {
      if (event.block_type === "text") {
        return withTurn({ ...turn, text: turn.text + event.text });
      }
      if (event.block_type === "reasoning") {
        return withTurn({ ...turn, reasoning: turn.reasoning + event.text });
      }
      return state;
    }

    case "tool_start": {
      if (turn.tools.some((t) => t.id === event.tool_id)) {
        return state;
      }
      const call: ToolCall = {
        id: event.tool_id,
        name: event.tool_name,
        args: event.arguments,
        state: "started",
        startedAt: Date.now(),
      };
      const nextTurn: AssistantTurn = { ...turn, tools: [...turn.tools, call] };
      const decisions = state.decisions.some((d) => d.id === call.id)
        ? state.decisions
        : [...state.decisions, call];
      return { ...withTurn(nextTurn), decisions };
    }

    case "tool_end": {
      const idx = turn.tools.findIndex((t) => t.id === event.tool_id);
      if (idx < 0) return state;
      const existing = turn.tools[idx];
      // No-op if already in the terminal state from a prior pass.
      if (
        existing.state === event.state &&
        existing.outputSummary === (event.output_summary ?? undefined)
      ) {
        return state;
      }
      const updated: ToolCall = {
        ...existing,
        state: event.state,
        outputSummary: event.output_summary ?? undefined,
        endedAt: existing.endedAt ?? Date.now(),
      };
      const tools = turn.tools.slice();
      tools[idx] = updated;
      const nextTurn: AssistantTurn = { ...turn, tools };
      const decisions = state.decisions.map((d) =>
        d.id === event.tool_id ? updated : d,
      );
      return { ...withTurn(nextTurn), decisions };
    }

    case "run_end":
      return {
        ...withTurn({
          ...turn,
          streaming: false,
          text: event.result.message || turn.text,
        }),
        currentTurnId: null,
      };

    case "error":
      return {
        ...withTurn({ ...turn, streaming: false, error: event.message }),
        currentTurnId: null,
      };

    default:
      return state;
  }
}

function randomId(): string {
  return Math.random().toString(36).slice(2, 10);
}
