"""Serve subcommand: bridge a local agent to the Hexgate control plane.

Connects to ``ws://{API_URL}/v1/serve`` and authenticates via the
``bearer.<envelope>`` WebSocket subprotocol — the server derives the
project from the bearer token (Phase 6, token-implicit project). The
``hexgate.v1`` marker subprotocol is offered alongside and must come
back echoed on the accepted handshake; a missing echo means the
platform is older than Phase 6 and we error out fast.

Receives chat messages sent by dashboard Playground tabs, runs the
agent via the same ``stream_agent`` engine the terminal chat uses,
and ships every normalized ``StreamEvent`` back over the socket.

Handles reconnection with exponential backoff so a backend bounce
doesn't permanently break the connection.

When a payload includes ``user_attenuation`` metadata (the Playground's
"Act as alice" affordance), the turn is wrapped in an ``async with
User(...)`` scope. The runtime then lazily attenuates the agent's
bound HexgateClient token inside ``stream_agent`` — same code path a
production dev's backend uses when serving a real user.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote
from uuid import uuid4

from pydantic import ValidationError
from rich.console import Console
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from hexgate.agents.factory import stream_agent
from hexgate.bootstrap import bootstrap
from hexgate.cli._common import (
    AgentRuntime,
    build_approval_handler,
    build_runtime_from_local_agent,
    load_spec,
)
from hexgate.cli.state import ChatState
from hexgate.cloud.client import HexgateConfig, HexgateError
from hexgate.runtime import User
from hexgate.security.decision import Decision

logger = logging.getLogger(__name__)

# Default TTL for a single approval request. Long enough for a human to
# read + click, short enough that the LLM turn's own budget isn't fully
# consumed on the wait. Configurable per instance if the deployment
# needs different pacing.
APPROVAL_TTL_SECONDS = 300

RECONNECT_BASE = 1.0
RECONNECT_CAP = 15.0
PING_INTERVAL = 20.0
# Marker subprotocol the platform echoes back on a successful bearer
# handshake (matches ``_WS_PROTOCOL_MARKER`` in platform/api/main.py).
WS_PROTOCOL_MARKER = "hexgate.v1"


class RelayApprovalHandler:
    """``approval_handler`` that routes NEEDS_APPROVAL over the serve WS.

    When the enforcer flags a tool call as ``approval_required``, this
    handler emits an ``approval.request`` frame on the currently-bound
    serve WebSocket and awaits a matching ``approval.reply``. The
    playground dashboard renders the request inline and sends the
    reply through the same relay.

    Fail-closed by design:
      * ``__call__`` returns ``False`` if the socket isn't bound (no
        connected playground → treat as denied rather than hanging the
        agent turn forever).
      * ``__call__`` returns ``False`` on TTL timeout — the LLM sees
        the tool as denied and can recover next turn.
      * ``unbind_socket`` resolves every in-flight request with
        ``allowed=False`` on WS disconnect so pending coroutines don't
        leak past the connection they belonged to.

    Concurrent parallel tool calls (LangGraph's ToolNode fires them via
    ``asyncio.gather``) are supported: each gets its own decision_id and
    its own ``asyncio.Event``. WS sends are serialized under a lock
    because the ``websockets`` library does NOT serialize concurrent
    ``send()`` calls on one socket — interleaved frames would be a
    silent bug otherwise.
    """

    def __init__(self, ttl_seconds: float = APPROVAL_TTL_SECONDS) -> None:
        self._pending: dict[str, tuple[asyncio.Event, dict[str, Any]]] = {}
        self._ws: Any = None
        self._send_lock: asyncio.Lock | None = None
        self._ttl = ttl_seconds

    def bind_socket(self, ws: Any, send_lock: asyncio.Lock) -> None:
        """Called by ``_serve_loop`` on each new WS connect.

        Takes the per-connection send lock so approval-request sends
        serialize with every OTHER send on the same socket (chat
        stream, reset ack, error echo). One lock across all sends is
        the only way to keep frames from interleaving — websockets
        does not serialize concurrent send() calls itself.
        """
        self._ws = ws
        self._send_lock = send_lock

    def unbind_socket(self) -> None:
        """Called on WS disconnect. Fail-closes every in-flight approval
        so awaiting handlers unblock immediately (as deny) rather than
        outliving the connection."""
        for evt, box in list(self._pending.values()):
            box["allowed"] = False
            evt.set()
        self._pending.clear()
        self._ws = None
        self._send_lock = None

    async def __call__(self, decision: Decision) -> bool:
        ws = self._ws
        send_lock = self._send_lock
        if ws is None or send_lock is None:
            logger.warning(
                "approval requested but no playground is connected — denying "
                "tool_name=%s",
                decision.tool_name,
            )
            return False

        decision_id = f"appr_{uuid4().hex}"
        evt: asyncio.Event = asyncio.Event()
        # ``box`` carries the outcome across the coroutine boundary so a
        # resolve() firing at any point overrides the default (False).
        box: dict[str, bool] = {"allowed": False}
        self._pending[decision_id] = (evt, box)

        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=self._ttl)
        ).isoformat()
        # Use ``type`` on both directions of the approval protocol —
        # matches every other control frame (hello, reset, session_reset).
        payload = {
            "type": "approval.request",
            "decision_id": decision_id,
            "tool_name": decision.tool_name,
            "arguments": decision.arguments or {},
            "reason": decision.reason,
            "agent_name": decision.agent_name,
            "role": decision.role,
            "expires_at": expires_at,
        }
        try:
            # Narrow except around SEND only — a send failure denies
            # (fail-closed). Once send succeeds and we're purely awaiting
            # the Event, an exception here (Timeout is caught below; the
            # only other path is cancellation) should NOT clobber a
            # resolve() that already set allowed=True.
            try:
                async with send_lock:
                    await ws.send(json.dumps(payload))
            except Exception:
                logger.exception(
                    "approval request %s failed to send — denying", decision_id
                )
                return False

            try:
                await asyncio.wait_for(evt.wait(), timeout=self._ttl)
            except asyncio.TimeoutError:
                # Fail-closed on TTL. `box["allowed"]` stays False.
                logger.info(
                    "approval request %s timed out after %ss — denying",
                    decision_id,
                    self._ttl,
                )
        finally:
            self._pending.pop(decision_id, None)
        return box["allowed"]

    def resolve(self, decision_id: str, allowed: bool) -> None:
        """Called by ``_handle_message`` on ``approval.reply``.

        Unknown ``decision_id`` (already timed out, spurious reply,
        stale from a previous connection) is a no-op — we don't crash
        the serve loop over untrusted payload keys.

        Atomically pops the entry from ``_pending`` before mutating
        ``box``: without this, an ``unbind_socket`` firing between
        ``box["allowed"] = True`` and the parked ``__call__``
        coroutine waking up would find the still-registered entry and
        flip ``allowed`` back to False — silently denying a call the
        user just approved. Popping first means unbind can't see it.
        The parked ``__call__`` sees ``box["allowed"] == True`` and
        returns approve; its own ``finally`` ``pop(..., None)`` no-ops
        because we already removed the entry.
        """
        entry = self._pending.pop(decision_id, None)
        if entry is None:
            logger.debug(
                "ignoring approval.reply for unknown decision_id=%r", decision_id
            )
            return
        evt, box = entry
        # ``allowed`` is validated as a strict bool by the caller
        # (``_handle_message``) before it lands here — non-bool values
        # already fail-closed at that layer.
        box["allowed"] = allowed
        evt.set()


@dataclass
class ServeContext:
    """Runtime context required to service remote chat messages."""

    runtime: AgentRuntime
    state: ChatState
    # Bearer token used to build the WS subprotocol on each (re)connect.
    # Carried on the context so reconnect loops don't need to rebuild
    # the HexgateConfig on every retry.
    api_key: str
    # The handler wired into enforce_policy(). ``RelayApprovalHandler``
    # instances need bind/unbind + reply routing; other handler shapes
    # (auto-approve/deny bool, callable) are simply passed through to
    # the enforcer without any WS involvement.
    approval_handler: Any = None
    # Per-connection send lock. Every ``ws.send`` on this connection —
    # chat stream deltas, reset ack, error echo, approval.request —
    # must acquire it. Now that ``_serve_loop`` dispatches each inbound
    # frame as its own asyncio task, two of those sends can fire
    # concurrently, and the ``websockets`` library does NOT serialize
    # concurrent ``send()`` calls; interleaved frames would corrupt the
    # protocol on the peer side. Set at connect time by ``_serve_loop``;
    # ``None`` outside an active connection.
    send_lock: asyncio.Lock | None = None
    # Per-connection chat lock. Serializes the chat branch of
    # ``_handle_message`` so two concurrent "chat" frames don't both
    # call ``ChatState.start_turn`` (which unconditionally overwrites
    # ``self.current_run``) and produce interleaved state mutation.
    # Approval replies and reset frames still run concurrently with
    # streaming — only chat-vs-chat is serialized. Set at connect time
    # by ``_serve_loop``; ``None`` outside an active connection.
    chat_lock: asyncio.Lock | None = None


async def _safe_send(context: "ServeContext", ws: Any, message: str) -> None:
    """Send ``message`` on ``ws`` under the connection's send lock.

    Every non-approval WS send on the serve path routes through here so
    concurrent frames don't interleave. The approval-request path
    inside :class:`RelayApprovalHandler.__call__` acquires the same
    lock (given to it via ``bind_socket``) — one lock across all send
    sites is the invariant.
    """
    lock = context.send_lock
    if lock is None:
        # Not inside an active connection scope — should only happen in
        # tests that bypass ``_serve_loop``. Fall through to a raw send
        # so the test isn't forced to invent a lock.
        await ws.send(message)
        return
    async with lock:
        await ws.send(message)


def _user_from_payload(attenuation: Any) -> User | None:
    """Build a :class:`User` from a chat payload's ``user_attenuation`` dict.

    Returns ``None`` (and logs a warning) when the payload is missing or
    malformed — the turn proceeds without an active User scope and the
    agent runs as if no attenuation was requested.
    """
    if not isinstance(attenuation, dict) or not attenuation.get("user"):
        return None
    try:
        return User(
            user_id=str(attenuation["user"]),
            role=attenuation.get("role"),
            session_id=attenuation.get("session_id"),
            ttl_seconds=attenuation.get("ttl_seconds"),
        )
    except (TypeError, ValueError, ValidationError) as exc:
        logger.warning("serve: invalid user_attenuation %r: %s", attenuation, exc)
        return None


@asynccontextmanager
async def _maybe_user_scope(user: User | None):
    """No-op async context manager when ``user`` is ``None``."""
    if user is None:
        yield
    else:
        async with user:
            yield


async def _run_chat_turn(
    context: ServeContext, ws: Any, text: str, payload: dict
) -> None:
    """Run one chat turn end-to-end: start_turn → stream → apply + send.

    Extracted so the chat branch of ``_handle_message`` can wrap it
    under ``context.chat_lock`` without a giant indented block. Every
    outbound event goes through ``_safe_send`` so a mid-turn approval
    request from the enforcer serializes cleanly with these stream
    deltas rather than interleaving on the wire.
    """
    # Policy refresh is handled inside stream_agent now (Phase 8a) —
    # the attached PolicySource sends If-None-Match and reuses the
    # cached bundle on 304. No need for serve to rebuild the runtime.
    context.state.start_turn(text)
    user = _user_from_payload(payload.get("user_attenuation"))
    async with _maybe_user_scope(user):
        async for event in stream_agent(
            context.runtime.agent,
            context.runtime.handler,
            context.state.build_input(),
        ):
            context.state.apply_event(event)
            await _safe_send(context, ws, event.model_dump_json())


async def _handle_message(
    context: ServeContext,
    ws,
    payload: dict,
) -> None:
    """Dispatch a single inbound message from the chat peer."""
    kind = payload.get("type")

    if kind == "chat":
        text = str(payload.get("message", "")).strip()
        if not text:
            return
        # Serialize chat turns so two "chat" frames arriving back-to-back
        # can't both call start_turn() concurrently — start_turn()
        # unconditionally overwrites ``current_run``, which would leak
        # the first turn's remaining events into the second turn's
        # state. Approval replies still race with the streaming chat
        # (different branch), so the deadlock fix isn't undone.
        chat_lock = context.chat_lock
        if chat_lock is None:
            # No lock provided (test bypass of _serve_loop) — fall
            # through unserialized; the test is responsible for not
            # firing overlapping chats.
            await _run_chat_turn(context, ws, text, payload)
            return
        async with chat_lock:
            await _run_chat_turn(context, ws, text, payload)
        return

    if kind == "reset":
        context.state.clear()
        await _safe_send(context, ws, json.dumps({"type": "session_reset"}))
        return

    if kind == "approval.reply":
        # Playground answered a NEEDS_APPROVAL prompt. Route to the
        # relay handler by decision_id. Non-relay handlers (auto-
        # approve/deny bool, custom callable) can't consume the reply
        # — log at warning so an operator debugging "why isn't my
        # approval landing" sees the trail.
        if not isinstance(context.approval_handler, RelayApprovalHandler):
            logger.warning(
                "serve: ignoring approval.reply — active handler is %r, not "
                "a RelayApprovalHandler; playground approvals only work when "
                "--approval-mode=ask (the default).",
                type(context.approval_handler).__name__,
            )
            return
        decision_id = payload.get("decision_id")
        if not isinstance(decision_id, str):
            logger.warning("serve: approval.reply missing string decision_id")
            return
        allowed = payload.get("allowed")
        # STRICT bool check — never truthy-coerce. `bool("false")` is
        # True in Python, so a client sending allowed="false" would
        # otherwise approve the tool call. Fail-closed contract.
        if allowed is not True and allowed is not False:
            logger.warning(
                "serve: approval.reply for %s has non-bool allowed=%r — "
                "denying to preserve fail-closed",
                decision_id,
                allowed,
            )
            allowed = False
        context.approval_handler.resolve(decision_id, allowed)
        return

    logger.warning("serve: ignoring unknown message type %r", kind)


async def _serve_loop(context: ServeContext, url: str, console: Console) -> None:
    """Receive loop for a single WebSocket session.

    Auth is via the ``bearer.<envelope>`` subprotocol — the server reads
    the token there, resolves the project, and rejects the handshake
    with close code 4401 on any failure. The ``hexgate.v1`` marker comes
    back echoed; an absent echo means we're talking to a pre-Phase-6
    platform and we bail out clean rather than running with no auth.

    The envelope is percent-encoded before being placed in the
    subprotocol value — the biscuit's base64 payload ends with ``=``
    padding, but WS subprotocols inherit the RFC 7230 token grammar
    which doesn't allow ``=``. The server unquotes it back on the
    other side; the grammar does allow ``%`` so percent-encoding
    survives the handshake intact.
    """
    bearer_value = quote(context.api_key, safe="")
    subprotocols = [f"bearer.{bearer_value}", WS_PROTOCOL_MARKER]
    # Track dispatched handler tasks so we can cancel them cleanly on
    # disconnect (and so pending approvals fail-close via unbind, not by
    # sitting on TTL). Each inbound frame gets its own task — otherwise
    # a chat frame that triggers an approval prompt would block the
    # very same coroutine that must read the matching approval.reply
    # frame off the socket → hard deadlock, every approval TTL-denies.
    dispatched: set[asyncio.Task[None]] = set()
    # Per-connection locks live for the duration of THIS `async with
    # connect(...)` block. Recreated on every reconnect so a torn-down
    # connection can't share a lock with the next one — clean lifecycle.
    context.send_lock = asyncio.Lock()
    context.chat_lock = asyncio.Lock()
    async with connect(
        url, ping_interval=PING_INTERVAL, subprotocols=subprotocols
    ) as ws:
        if ws.subprotocol != WS_PROTOCOL_MARKER:
            raise HexgateError(
                f"platform did not negotiate the {WS_PROTOCOL_MARKER} "
                "subprotocol — deployment may be running an older API. "
                "Update the platform or pin to a matching hexgate CLI."
            )
        try:
            # Bind AFTER handshake succeeded but INSIDE the try, so the
            # finally always unbinds — a hello-send failure that bypasses
            # this block leaves the handler unbound (its default state).
            if isinstance(context.approval_handler, RelayApprovalHandler):
                context.approval_handler.bind_socket(ws, context.send_lock)
            console.print(f"[green]connected[/] — relaying through {url}")
            await _safe_send(
                context,
                ws,
                json.dumps({"type": "hello", "agent": context.runtime.agent_name}),
            )
            async for message in ws:
                try:
                    payload = json.loads(message)
                except json.JSONDecodeError:
                    logger.warning("serve: ignoring non-JSON frame")
                    continue
                # Dispatch on a background task so the read loop can
                # immediately pick up the next frame — critical for
                # approval.reply arriving mid-chat.
                task = asyncio.create_task(_dispatch_message(context, ws, payload))
                dispatched.add(task)
                task.add_done_callback(dispatched.discard)
        except ConnectionClosed:
            console.print("[yellow]disconnected[/]")
        finally:
            # Fail-close every in-flight approval FIRST — this lets any
            # coroutine parked on an approval Event unblock as denied so
            # the tool call returns to its caller, which then lets the
            # dispatched task complete naturally. If we cancelled the
            # tasks first, the enforcer's downstream cleanup would run
            # under CancelledError and could leak subtasks.
            if isinstance(context.approval_handler, RelayApprovalHandler):
                context.approval_handler.unbind_socket()
            # Give the freshly-denied tool calls a moment to finish
            # cleanly, then cancel anything still running.
            if dispatched:
                _, pending = await asyncio.wait(dispatched, timeout=1.0)
                for task in pending:
                    task.cancel()
                # Reap the cancellations so we don't leak "Task was
                # destroyed but it is pending!" warnings on shutdown.
                await asyncio.gather(*pending, return_exceptions=True)
            # Drop the per-connection locks so a next-reconnect call to
            # bind_socket doesn't inherit a stale lock a canceled task
            # might still be holding.
            context.send_lock = None
            context.chat_lock = None


async def _dispatch_message(context: ServeContext, ws: Any, payload: dict) -> None:
    """Handle one inbound frame, catching + reporting errors as tool events.

    Extracted from ``_serve_loop`` so each frame runs in its own task,
    which keeps the read loop free to pick up the next frame while a
    long-running chat call is still streaming. Errors that escape
    ``_handle_message`` are logged and echoed back to the peer as an
    ``error`` event so the dashboard sees the failure inline.
    """
    try:
        await _handle_message(context, ws, payload)
    except Exception as exc:  # noqa: BLE001
        logger.exception("serve: error handling %r", payload.get("type"))
        try:
            await _safe_send(
                context,
                ws,
                json.dumps(
                    {
                        "event_type": "error",
                        "message": str(exc),
                        "run_id": "serve",
                        "root_run_id": "serve",
                        "sequence": 0,
                    }
                ),
            )
        except Exception:  # noqa: BLE001
            # Socket already gone — nothing to report to.
            pass


async def run_serve(
    runtime: AgentRuntime,
    approval_handler: Any = None,
) -> None:
    """Top-level serve loop with reconnect + graceful shutdown.

    Policy hot-reload is handled by the agent's attached :class:`~hexgate.
    security.source.PolicySource`: ``stream_agent`` calls
    ``agent.refresh_policy()`` at the start of every turn, the source
    sends ``If-None-Match`` to the platform, and a ``304`` short-circuits
    to the cached bundle. No bespoke runtime rebuild needed here.

    ``approval_handler`` is the SAME object the runtime was built with;
    passed separately so ``_serve_loop`` can bind/unbind it on the WS
    connect/disconnect boundary when it's a :class:`RelayApprovalHandler`.
    Non-relay handlers (auto-approve/deny bool, custom callables) are
    unused here — they take effect inside the enforcer directly.
    """
    console = Console()
    config = HexgateConfig.from_env()
    base = config.base_url.rstrip("/")
    if base.startswith("https://"):
        ws_base = "wss://" + base.removeprefix("https://")
    elif base.startswith("http://"):
        ws_base = "ws://" + base.removeprefix("http://")
    else:
        ws_base = f"ws://{base}"
    # No ``project_id`` in the URL — the bearer subprotocol carries it.
    url = f"{ws_base}/v1/serve"

    context = ServeContext(
        runtime=runtime,
        state=ChatState(),
        api_key=config.api_key,
        approval_handler=approval_handler,
    )
    backoff = RECONNECT_BASE

    # ``project_id`` is best-effort display now (Phase 6); show a
    # placeholder when the envelope didn't carry it. The token itself
    # is the source of truth and the server logs the resolved project
    # on its side.
    project_display = config.project_id or "<from token>"
    console.print(
        f"[bold]hexgate-serve[/] agent=[cyan]{runtime.agent_name}[/] "
        f"project=[cyan]{project_display}[/]"
    )
    # Flag the default-flip loudly for existing operators. Before this
    # release, `hexgate serve` coerced `ask` → `auto-approve` because
    # there was no way to prompt during a relay session. Now `ask`
    # (still the default) uses RelayApprovalHandler — approval_required
    # tool calls that fire while no playground is connected DENY. This
    # is the correct security default but a behavior change; scripts
    # that relied on the old silent auto-approve must opt in explicitly.
    if isinstance(approval_handler, RelayApprovalHandler):
        console.print(
            "[yellow]approval:[/] approval_required tool calls will prompt the "
            "connected playground; without a connected playground they DENY. "
            "Use [cyan]--approval-mode auto-approve[/] for headless / CI runs "
            "if that's what you want."
        )
    console.print("[dim]Ctrl+C to stop[/]")

    while True:
        try:
            await _serve_loop(context, url, console)
            backoff = RECONNECT_BASE
        except (ConnectionClosed, OSError) as exc:
            console.print(
                f"[yellow]connection lost[/] ({exc}); retrying in {backoff:.1f}s"
            )
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, RECONNECT_CAP)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]unexpected error:[/] {exc}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, RECONNECT_CAP)


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the `serve` subcommand on the top-level hexgate CLI."""
    parser = subparsers.add_parser(
        "serve",
        help="Relay a local agent to the Hexgate dashboard over WebSocket.",
        description=(
            "Serve a local agent to the Hexgate dashboard Playground over "
            "WebSocket. Takes a module:attr spec — the same form as "
            "`hexgate register --agent ...` — and brings the agent up "
            "end-to-end: auto-registers the manifest (idempotent), fetches "
            "the cloud's policy, applies enforcement, then opens the relay. "
            "Policy edits in the dashboard take effect at the next turn."
        ),
    )
    parser.add_argument(
        "agent_spec",
        help=(
            "Agent to serve as module:attr — e.g. "
            "examples.customer_bot:agent. Same spec form as "
            "`hexgate register --agent ...`."
        ),
    )
    parser.add_argument(
        "--description",
        default=None,
        help="Optional description for the registered manifest.",
    )
    parser.add_argument(
        "--approval-mode",
        choices=("ask", "auto-approve", "auto-deny"),
        default="ask",
        help=(
            "How approval-required tool calls are handled. ``ask`` (default) "
            "routes the request to the connected playground for a human to "
            "decide; ``auto-approve`` / ``auto-deny`` skip the round-trip "
            "and apply the outcome directly (script / CI mode)."
        ),
    )
    parser.add_argument(
        "--no-auto-register",
        action="store_true",
        help=(
            "Skip the auto-register POST at startup. Errors if the agent "
            "isn't already on the platform. Useful for CI / deliberate "
            "deployments where registration is a separate step."
        ),
    )
    parser.set_defaults(func=main)


def main(args: argparse.Namespace) -> int:
    """Entrypoint for the `hexgate serve` subcommand.

    The uvicorn-style flow: load the agent object from a module:attr
    spec, derive a manifest from it (no flags needed — the object
    carries name, tools, model, and system_prompt), auto-register
    on the platform, fetch the operator's policy, and relay.
    """
    console = Console()
    settings = bootstrap()

    agent_obj = load_spec(args.agent_spec)

    # Default (``ask``) routes approvals to the connected playground
    # via the WS relay. Script/CI callers can still opt into
    # ``auto-approve`` / ``auto-deny`` to skip the round-trip. The
    # RelayApprovalHandler needs the socket bound at runtime — that
    # happens in _serve_loop.
    if args.approval_mode in ("auto-approve", "auto-deny"):
        approval_handler = build_approval_handler(console, args.approval_mode)
    else:
        approval_handler = RelayApprovalHandler()

    try:
        runtime = build_runtime_from_local_agent(
            settings,
            agent_obj=agent_obj,
            description=args.description,
            approval_handler=approval_handler,
            auto_register=not args.no_auto_register,
            console=console,
        )
    except HexgateError as exc:
        # Token + handshake + registration errors all bubble through
        # HexgateError; surface the message and exit cleanly.
        console.print(f"[red]✗[/] {exc}")
        return 1

    asyncio.run(run_serve(runtime, approval_handler=approval_handler))
    return 0
