"""OpenAI Agents adapter: resolve the platform policy and return a clone
of the agent whose tools are policy-gated. HexgateContext-agnostic at wrap time —
role resolution happens inside the enforcer via the :class:`HexgateContext`
contextvar.

Policy is resolved from the platform (register-on-404); the lifecycle —
binding cache + per-run refresh — lives in the runner, since the OpenAI
``Runner`` receives the agent per call.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import TYPE_CHECKING

from agents import Agent

from hexgate.adapters.openai.tools import wrap_tools
from hexgate.approvals import ApprovalHandler
from hexgate.hooks.types import build_pipeline
from hexgate.security.enforcer import PolicyEnforcer

if TYPE_CHECKING:
    from hexgate.hooks.types import Hook, HookObserver


def wrap_openai_agent(
    agent: Agent,
    *,
    enforcer: PolicyEnforcer,
    approval_handler: ApprovalHandler | None = None,
    hooks: Sequence[Hook] | None = None,
    hook_observer: HookObserver | None = None,
) -> Agent:
    """Return a clone of ``agent`` whose tools are gated by ``enforcer``.

    Mechanics only — resolution/refresh live with the caller. Caller
    must open a :class:`HexgateContext` scope around the run. ``approval_handler``
    (async ``fn(decision) -> bool`` or ``bool`` shorthand) fires when a
    tool call carries a ``NEEDS_APPROVAL`` outcome; a truthy return runs
    the tool, falsy surfaces the ``[approval_required]`` marker. ``hooks`` is the
    flat ``@before_tool`` / ``@after_tool`` guard list run around each tool call
    (the same argument the other adapters take); ``hook_observer`` receives the
    provenance ``HookEvent``s.
    """
    pipeline = build_pipeline(hooks, observer=hook_observer)
    guarded_tools = wrap_tools(
        agent.tools, enforcer, approval_handler=approval_handler, pipeline=pipeline
    )
    return dataclasses.replace(agent, tools=guarded_tools)
