"""Pre/post tool-call hooks.

A pluggable pipeline that runs alongside ``PolicyEnforcer.decide``: an
ordered list of hooks before a tool call (which may observe, rewrite args,
or halt) and after it (observe or halt in v1). See ``tool-hooks-design.md``
for the design and the later phases (result rewrite, egress, official
plugins).
"""

from __future__ import annotations

from hexgate.hooks.runner import run_guarded_async, run_guarded_sync
from hexgate.hooks.types import (
    Halt,
    Hook,
    HookEvent,
    HookObserver,
    Modification,
    PostHook,
    PreHook,
    Proceed,
    ToolCall,
    ToolOutcome,
    ToolPipeline,
    observe,
)

__all__ = [
    "Halt",
    "Hook",
    "HookEvent",
    "HookObserver",
    "Modification",
    "PostHook",
    "PreHook",
    "Proceed",
    "ToolCall",
    "ToolOutcome",
    "ToolPipeline",
    "observe",
    "run_guarded_async",
    "run_guarded_sync",
]
