"""Tool guards: functions that run before and after a tool call.

Author a guard with ``@before_tool`` / ``@after_tool``; it observes a call,
rewrites its args (before only), or halts. Register guards as one flat
``guards=[...]`` list on the agent. See ``tool-guards-explained.md`` for the
intuition, ``docs/adr/R-GUARD-001..003`` for the decisions, and the later phases
(result rewrite, egress, official plugins) in ``ROADMAP.md``.
"""

from __future__ import annotations

from hexgate.guards.runner import run_guarded_async, run_guarded_sync
from hexgate.guards.types import (
    Halt,
    GuardEvent,
    GuardObserver,
    Modification,
    Proceed,
    ToolCall,
    ToolOutcome,
    after_tool,
    before_tool,
    build_pipeline,
)

__all__ = [
    "Halt",
    "GuardEvent",
    "GuardObserver",
    "Modification",
    "Proceed",
    "ToolCall",
    "ToolOutcome",
    "after_tool",
    "before_tool",
    "build_pipeline",
    "run_guarded_async",
    "run_guarded_sync",
]
