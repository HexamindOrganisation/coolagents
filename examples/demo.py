"""Small CLI demo for the hexgate runtime."""

from __future__ import annotations

import asyncio
from pathlib import Path

from hexgate.agents.factory import stream_agent
from hexgate.agents.loader import list_available_agents, load_agent
from hexgate.bootstrap import bootstrap
from hexgate.streaming import BlockDeltaEvent, EventType, ToolEndEvent, ToolStartEvent
from hexgate.tracing.langfuse import maybe_get_trace_url


def _render_event(event: object) -> str | None:
    """Render a normalized stream event for the CLI."""
    if isinstance(event, BlockDeltaEvent):
        return event.text
    if isinstance(event, ToolStartEvent):
        return f"\n[tool:start] {event.tool_name}\n"
    if isinstance(event, ToolEndEvent):
        return f"[tool:end] {event.tool_name}\n"
    if getattr(event, "event_type", None) == EventType.RUN_END:
        return "\n"
    return None


def _default_demo_agent(base_dir: Path) -> str:
    """Return the default demo agent for the current project context."""
    available = list_available_agents(base_dir)
    if "example_agent" in available:
        return "example_agent"
    if not available:
        raise RuntimeError("No local or registered agents available for the demo.")
    return available[0]


async def main() -> None:
    """Run the demo agent and print normalized stream events."""
    settings = bootstrap()
    base_dir = Path.cwd()
    agent_name = _default_demo_agent(base_dir)
    agent, handler = load_agent(
        agent_name,
        base_dir=base_dir,
        model=settings.model,
        session_id="demo-session",
        tags=["hexgate", settings.search_engine, settings.model],
    )

    query = "Search for the latest major AI breakthroughs this month and summarize the top 5 with sources."
    print(f"Agent: {agent_name}")
    print(f"Query: {query}\n")

    async for event in stream_agent(agent, handler, query):
        rendered = _render_event(event)
        if rendered:
            print(rendered, end="", flush=True)

    trace_url = maybe_get_trace_url(handler)
    if trace_url:
        print(f"\nLangfuse trace: {trace_url}")


if __name__ == "__main__":
    asyncio.run(main())
