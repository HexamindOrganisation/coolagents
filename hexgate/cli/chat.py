"""Inline terminal chat subcommand: `hexgate chat`."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections import deque
from pathlib import Path

from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from hexgate.agents.factory import stream_agent
from hexgate.agents.loader import list_available_agents, resolve_agent_source
from hexgate.bootstrap import bootstrap
from hexgate.cli._common import (
    AgentRuntime,
    add_shared_agent_flags,
    build_approval_handler,
    build_runtime,
    load_agent_script,
)
from hexgate.cli.state import ChatState, LiveRunState, ToolActivity
from hexgate.security.decision import Decision, DecisionOutcome
from hexgate.streaming import ToolCallState
from hexgate.tools.decorators import format_tool_call_label
from hexgate.tracing.langfuse_core import maybe_get_trace_url

MAX_LIVE_RESPONSE_LINES = 12
MAX_LIVE_RESPONSE_CHARS = 2_400
DOG_LOGO = "\n".join(
    [
        " / \\__",
        "(    @\\___",
        " /         O",
        "/   (_____/",
        "/_____/   U",
    ]
)


def _tool_prefix(tool: ToolActivity) -> RenderableType:
    """Return a compact renderable prefix for a tool activity."""
    if tool.status == ToolCallState.STARTED:
        return Text("◉", style="bold cyan")
    if tool.status == ToolCallState.FAILED:
        return Text("◉", style="bold red")
    return Text("◉", style="bold green")


def _tool_summary(runtime: AgentRuntime, tool: ToolActivity) -> str:
    """Return a short one-line summary for a tool activity."""
    tool_object = runtime.tools_by_name.get(tool.tool_name)
    if tool_object is not None:
        return format_tool_call_label(tool_object, tool.arguments)
    return tool.tool_name


def _tail_text(
    text: str,
    *,
    max_lines: int = MAX_LIVE_RESPONSE_LINES,
    max_chars: int = MAX_LIVE_RESPONSE_CHARS,
) -> tuple[str, bool]:
    """Return the tail of a long text block for live terminal rendering."""
    truncated = False
    if len(text) > max_chars:
        text = text[-max_chars:]
        truncated = True

    lines = text.splitlines()
    if len(lines) > max_lines:
        text = "\n".join(lines[-max_lines:])
        truncated = True

    return text.lstrip("\n"), truncated


def _render_current_run(
    runtime: AgentRuntime,
    current_run: LiveRunState,
    trace_url: str | None = None,
    *,
    live: bool = False,
) -> list[RenderableType]:
    """Render the active assistant turn inline in the transcript."""
    renderables: list[RenderableType] = []

    for index, tool in enumerate(current_run.tools):
        renderables.append(
            Text.assemble(
                _tool_prefix(tool), " ", (_tool_summary(runtime, tool), "white")
            )
        )
        if tool.summary and tool.status == ToolCallState.FAILED:
            renderables.append(Text(f"  {tool.summary}", style="dim red"))
        if index < len(current_run.tools) - 1:
            renderables.append(Text("│", style="dim white"))

    if current_run.reasoning_text.strip():
        renderables.append(
            Text(f"  {current_run.reasoning_text.rstrip()}", style="dim white")
        )

    if current_run.response_text.strip():
        if live:
            tailed_text, truncated = _tail_text(current_run.response_text.rstrip())
            if truncated:
                renderables.append(Text("...", style="dim white", justify="center"))
            renderables.append(Text(tailed_text, style="white"))
        else:
            renderables.append(Markdown(current_run.response_text.rstrip()))
    elif current_run.is_streaming:
        renderables.append(Spinner("dots", text=" thinking...", style="white"))

    if current_run.error:
        renderables.append(Text(f"  Error: {current_run.error}", style="bold red"))

    if trace_url and not current_run.is_streaming:
        renderables.append(Text(f"  Trace: {trace_url}", style="cyan"))

    return renderables


def _render_live_turn(
    runtime: AgentRuntime,
    current_run: LiveRunState,
    trace_url: str | None = None,
) -> RenderableType:
    """Render only the currently active assistant turn."""
    return Group(*_render_current_run(runtime, current_run, trace_url, live=True))


def _print_completed_turn(
    console: Console,
    runtime: AgentRuntime,
    current_run: LiveRunState,
    trace_url: str | None = None,
) -> None:
    """Print one completed assistant turn as stable terminal output."""
    console.print(
        Group(*_render_current_run(runtime, current_run, trace_url, live=False))
    )
    console.print()


def _render_decision_panel(decision: Decision) -> Panel | None:
    """Render one ``Decision`` as a rich Panel — or ``None`` for ALLOW.

    Allows are muted by design: a chatty REPL with a panel per tool call
    is noise. The whole point of the decision feed is "what got blocked
    and why," surfaced right where the dev is iterating. A ``--show-allow``
    flag can land later if anyone asks.
    """
    if decision.outcome is DecisionOutcome.ALLOW:
        return None

    is_deny = decision.outcome is DecisionOutcome.DENY
    border_style = "red" if is_deny else "yellow"
    title_glyph = "⛔" if is_deny else "⏸"
    title = f"{title_glyph} {decision.outcome.value} · {decision.tool_name}"

    lines: list[RenderableType] = []
    if decision.reason:
        lines.append(Text(decision.reason, style="white"))
    if decision.error_type:
        lines.append(Text(f"error_type: {decision.error_type}", style="dim"))
    if decision.user_roles:
        lines.append(Text(f"roles: {', '.join(decision.user_roles)}", style="dim"))
    if decision.deciding_role is not None:
        lines.append(Text(f"granted by: {decision.deciding_role}", style="dim"))
    if decision.violations:
        lines.append(Text("violations:", style="dim"))
        for v in decision.violations:
            lines.append(Text(f"  • {v}", style="dim red" if is_deny else "dim yellow"))
    if decision.hint is not None:
        # JSON over Python repr so {"glob": "/x/**"} reads as JSON, not
        # {'glob': '/x/**'} — matches the wire format the platform stores.
        # default=str defends against non-JSON-serializable values the
        # engine might pass through (rare, but cheap insurance).
        lines.append(
            Text(f"hint: {json.dumps(decision.hint, default=str)}", style="dim")
        )

    return Panel(
        Group(*lines) if lines else Text("(no detail)", style="dim"),
        title=title,
        title_align="left",
        border_style=border_style,
        padding=(0, 1),
    )


def _drain_decisions(console: Console, pending: deque[Decision]) -> None:
    """Print panels for any decisions captured during the just-finished
    turn, then clear the deque. Called between turns so the panels
    appear after the agent's response but before the next prompt — the
    same surface the user just looked at."""
    while pending:
        decision = pending.popleft()
        panel = _render_decision_panel(decision)
        if panel is not None:
            console.print(panel)


def _default_agent_name(base_dir: Path) -> str:
    """Return the default agent id for the current project context."""
    available = list_available_agents(base_dir)
    if "example_agent" in available:
        return "example_agent"
    if not available:
        raise RuntimeError(
            "No agents found. Add an agent directory (with agent.yaml) to the "
            "project, register one in code, or pass --use / --agent explicitly."
        )
    return available[0]


def _render_welcome(runtime: AgentRuntime) -> RenderableType:
    """Render a compact startup card for the terminal chat."""
    logo = Text(DOG_LOGO, style="bold bright_yellow", justify="center")
    info = Group(
        Text("hexgate", style="bold white"),
        Text("a calm little terminal swarm", style="dim"),
        Text(""),
        Text(f"agent  {runtime.agent_name} ({runtime.agent_source})", style="white"),
        Text(f"model  {runtime.model}", style="white"),
        Text(""),
        Text("/clear  reset chat", style="dim"),
        Text("/exit   leave chat", style="dim"),
    )
    return Panel(
        Columns([logo, info], expand=True, equal=False),
        title="[bold bright_yellow]Welcome Back[/]",
        border_style="bright_yellow",
        padding=(1, 2),
    )


async def _chat_loop(
    console: Console,
    runtime: AgentRuntime,
    pending_decisions: deque[Decision] | None = None,
) -> None:
    """Run the interactive terminal chat loop.

    ``pending_decisions`` is the deque the injected ``decision_observer``
    appends to as the enforcer makes calls during a turn. The loop
    drains it between turns and renders deny / needs_approval panels.
    Default ``None`` keeps the loop usable from tests that don't care."""
    state = ChatState()

    console.print(_render_welcome(runtime))
    console.print("[dim]Ask a question. Use /clear to reset or /exit to quit.[/]")
    console.print()

    while True:
        user_text = console.input("[bold cyan]> [/]").strip()

        if not user_text:
            continue
        if user_text in {"/exit", "/quit"}:
            break
        if user_text == "/clear":
            state.clear()
            console.clear()
            console.print(_render_welcome(runtime))
            console.print(
                "[dim]Ask a question. Use /clear to reset or /exit to quit.[/]"
            )
            console.print()
            continue

        state.start_turn(user_text)
        current_run = state.current_run
        if current_run is None:
            continue

        with Live(
            _render_live_turn(runtime, current_run),
            console=console,
            refresh_per_second=20,
            transient=True,
        ) as live:
            async for event in stream_agent(
                runtime.agent, runtime.handler, state.build_input()
            ):
                state.apply_event(event)
                if state.current_run is not None:
                    current_run = state.current_run
                    live.update(_render_live_turn(runtime, current_run))

            trace_url = maybe_get_trace_url(runtime.handler)
            current_run = state.current_run or current_run

        _print_completed_turn(console, runtime, current_run, trace_url)

        if pending_decisions is not None:
            _drain_decisions(console, pending_decisions)

        console.print()


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the `chat` subcommand on the top-level hexgate CLI."""
    parser = subparsers.add_parser(
        "chat",
        help="Run the interactive terminal chat against a local or builtin agent.",
        description="Run the hexgate inline chat CLI.",
    )
    add_shared_agent_flags(parser)
    parser.add_argument(
        "--list-agents",
        action="store_true",
        help="List available local and builtin agents, then exit.",
    )
    parser.set_defaults(func=main)


def main(args: argparse.Namespace) -> int:
    """Entrypoint for the `hexgate chat` subcommand."""
    console = Console()
    # Terminal chat is a "no platform required" loop: pass local_only=True
    # so bootstrap sets HEXGATE_LOCAL_MODE before any adapter wrapper can
    # spin up an audit sender against a key that's lingering in .env.
    settings = bootstrap(local_only=True)
    base_dir = Path.cwd()

    if args.use:
        load_agent_script(args.use)

    if args.list_agents:
        for agent_name in list_available_agents(base_dir):
            source = resolve_agent_source(agent_name, base_dir)
            console.print(f"{agent_name} [{source}]")
        return 0

    agent_name = args.agent or _default_agent_name(base_dir)

    # Decision feed: the observer appends to a bounded deque the chat
    # loop drains between turns. Sync callback, no threading concerns
    # (PolicyEnforcer.decide runs in the same event loop the chat loop
    # awaits stream_agent on). maxlen=64 caps memory if an LLM goes
    # wild calling tools and we somehow miss draining between turns.
    pending_decisions: deque[Decision] = deque(maxlen=64)

    # Terminal chat deliberately ignores HEXGATE_API_KEY: there's no playground to
    # feed and policy enforcement still works via the agent's own YAML or
    # registered factory. The serve subcommand keeps the cloud path.
    runtime = build_runtime(
        settings,
        agent_name=agent_name,
        base_dir=base_dir,
        model=args.model,
        local_only=True,
        approval_handler=build_approval_handler(console, args.approval_mode),
        decision_observer=pending_decisions.append,
    )
    asyncio.run(_chat_loop(console, runtime, pending_decisions))
    return 0
